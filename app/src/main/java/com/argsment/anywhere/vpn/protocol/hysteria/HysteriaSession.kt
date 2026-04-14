package com.argsment.anywhere.vpn.protocol.hysteria

import com.argsment.anywhere.vpn.quic.QuicConnection
import com.argsment.anywhere.vpn.quic.QuicTuning
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap

private val logger = AnywhereLogger("Hysteria-Session")

/** Errors raised by the Hysteria protocol layer. */
sealed class HysteriaError(message: String) : IOException(message) {
    object NotReady : HysteriaError("Hysteria session not ready")
    class ConnectionFailed(m: String) : HysteriaError("Hysteria connection failed: $m")
    class AuthRejected(val statusCode: Int) : HysteriaError("Hysteria auth rejected (status $statusCode)")
    class TunnelFailed(message: String) : HysteriaError("Hysteria tunnel failed: $message")
    object StreamClosed : HysteriaError("Hysteria stream closed")
    object UdpNotSupported : HysteriaError("Hysteria server does not support UDP")
}

/**
 * One Hysteria v2 session over a single QUIC connection. Direct port of iOS
 * `HysteriaSession.swift`, adapted to the Android `QuicConnection` API.
 *
 * Brings the connection through QUIC handshake → HTTP/3 SETTINGS → POST /auth
 * → 233 response, then routes server-initiated TCP streams to per-flow
 * [HysteriaConnection]s and DATAGRAM frames to [HysteriaUdpConnection]s.
 *
 * Brutal congestion control runs natively via the JNI-exposed
 * `ngtcp2_android_install_brutal` plugin. The initial rate reflects the
 * client's configured upload cap; [applyBrutalBandwidth] refines it
 * post-auth with `min(server_rx, client_tx)`.
 */
class HysteriaSession(private val configuration: HysteriaConfiguration) {

    enum class State { IDLE, CONNECTING, AUTHENTICATING, READY, CLOSED }

    private val quic = QuicConnection(
        host = configuration.proxyHost,
        port = configuration.proxyPort,
        serverName = configuration.effectiveSni,
        alpn = listOf("h3"),
        datagramsEnabled = true,
        // Seed Brutal with the client's own upload cap. Gets refined to
        // `min(server_rx, client_tx)` in `applyBrutalBandwidth` once the
        // auth response lands. The hysteria preset also clamps stream/
        // connection windows to 8 MB / 20 MB with `max == initial` so the
        // ngtcp2 receive-window auto-tuner doesn't grow past Brutal's
        // fixed-rate sender. Mirrors `QUICTuning.hysteria(uploadMbps:)`.
        tuning = QuicTuning.hysteria(uploadMbps = configuration.uploadMbps)
    )

    /** Coordinates state transitions. */
    private val mutex = Mutex()

    @Volatile private var state: State = State.IDLE

    private var authStreamId: Long = -1L
    private val authBuffer = ByteArrayOutputStream()
    @Volatile private var authHeadersReceived = false

    private val readyDeferreds = ArrayList<CompletableDeferred<Unit>>()

    /** Pool eviction / close hook. Set by [HysteriaSessionPool]. */
    var onClose: (() -> Unit)? = null

    /** Post-auth TCP streams keyed by QUIC stream id. */
    private val tcpStreams = ConcurrentHashMap<Long, HysteriaConnection>()

    /** Active UDP sessions keyed by Hysteria session id. */
    private val udpSessions = ConcurrentHashMap<Int, HysteriaUdpConnection>()
    private var nextUdpSessionId: Int = 1

    @Volatile var udpSupported: Boolean = false
        private set

    /** Server-advertised RX budget in bytes/sec. 0 = unlimited. */
    @Volatile var serverRxBytesPerSec: Long = 0
        private set

    /** Pool-visible state. */
    @Volatile var poolIsClosed: Boolean = false
        private set
    private val poolCounters = Object()
    private var poolTcpCount = 0
    private var poolUdpCount = 0

    val hasActiveConnections: Boolean
        get() = synchronized(poolCounters) { poolTcpCount > 0 || poolUdpCount > 0 }

    /** Background scope used to invoke completion callbacks asynchronously. */
    private val callbackScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // -- Lifecycle --

    /** Brings the session to [State.READY]; suspends until ready or fails. */
    suspend fun ensureReady() {
        val deferred: CompletableDeferred<Unit>
        mutex.withLock {
            when (state) {
                State.READY -> return
                State.CLOSED -> throw HysteriaError.ConnectionFailed("Session closed")
                State.CONNECTING, State.AUTHENTICATING -> {
                    deferred = CompletableDeferred()
                    readyDeferreds.add(deferred)
                }
                State.IDLE -> {
                    state = State.CONNECTING
                    deferred = CompletableDeferred()
                    readyDeferreds.add(deferred)
                    callbackScope.launch { startConnection() }
                }
            }
        }
        deferred.await()
    }

    private suspend fun startConnection() {
        quic.streamDataHandler = { sid, data, fin ->
            // Copy because the buffer is reused on the QUIC reader thread.
            val copy = data.copyOf()
            callbackScope.launch { handleStreamData(sid, copy, fin) }
        }
        quic.datagramHandler = { data ->
            val copy = data.copyOf()
            callbackScope.launch { handleDatagram(copy) }
        }
        quic.connectionClosedHandler = { err -> failSession(err) }

        try {
            quic.connect()
        } catch (e: Throwable) {
            failSession(e)
            return
        }

        openHttp3Control()
        sendAuthRequest()
        mutex.withLock { if (state == State.CONNECTING) state = State.AUTHENTICATING }
    }

    private fun openHttp3Control() {
        // RFC 9114 §6.2: clients must open a control uni stream with a SETTINGS
        // frame even if no further frames follow.
        quic.openUniStream()?.let { sid ->
            val payload = ByteArrayOutputStream()
            payload.write(0x00) // stream type = control
            payload.write(clientSettingsFrame())
            quic.writeStream(sid, payload.toByteArray(), fin = false)
        }
        // QPACK encoder (0x02) / decoder (0x03) uni streams (dynamic table = 0).
        quic.openUniStream()?.let { sid -> quic.writeStream(sid, byteArrayOf(0x02), fin = false) }
        quic.openUniStream()?.let { sid -> quic.writeStream(sid, byteArrayOf(0x03), fin = false) }
    }

    private fun clientSettingsFrame(): ByteArray {
        // SETTINGS frame: type=0x04, payload = pairs of varint(id, value).
        // id=0x01 QPACK_MAX_TABLE_CAPACITY = 0; id=0x07 QPACK_BLOCKED_STREAMS = 0.
        val payload = byteArrayOf(0x01, 0x00, 0x07, 0x00)
        return byteArrayOf(0x04, payload.size.toByte()) + payload
    }

    private fun sendAuthRequest() {
        val sid = quic.openBidiStream()
        if (sid == null) {
            failSession(HysteriaError.ConnectionFailed("Failed to open auth stream"))
            return
        }
        authStreamId = sid

        val extraHeaders = listOf(
            HysteriaHttp3Codec.Header("hysteria-auth", configuration.password),
            HysteriaHttp3Codec.Header("hysteria-cc-rx", configuration.clientRxBytesPerSec.toString()),
            HysteriaHttp3Codec.Header("hysteria-padding", HysteriaProtocol.randomPaddingString()),
            HysteriaHttp3Codec.Header("content-length", "0"),
        )
        val frame = HysteriaHttp3Codec.encodeAuthRequestFrame(
            authority = "hysteria",
            path = "/auth",
            extraHeaders = extraHeaders
        )
        quic.writeStream(sid, frame, fin = false)
    }

    // -- Stream dispatch --

    private fun handleStreamData(sid: Long, data: ByteArray, fin: Boolean) {
        if (sid == authStreamId) {
            handleAuthStreamData(data, fin)
            return
        }
        tcpStreams[sid]?.let {
            it.handleStreamData(data, fin)
            return
        }
        // Server-initiated unidirectional streams (low 2 bits == 0x03). Drain
        // their flow-control offset so the connection doesn't stall — Hysteria
        // v2 doesn't use them after auth.
        if ((sid and 0x03L) == 0x03L && data.isNotEmpty()) {
            quic.extendStreamOffset(sid, data.size)
        }
    }

    private fun handleAuthStreamData(data: ByteArray, fin: Boolean) {
        authBuffer.write(data)
        quic.extendStreamOffset(authStreamId, data.size)
        if (authHeadersReceived) return

        val buf = authBuffer.toByteArray()
        // Parse leading HTTP/3 HEADERS frame: varint(type=0x01) | varint(len) | block
        val (frameType, typeLen) = decodeQuicVarInt(buf, 0) ?: return
        val (payloadLen, lenBytes) = decodeQuicVarInt(buf, typeLen) ?: return
        val headerLen = typeLen + lenBytes
        val total = headerLen + payloadLen.toInt()
        if (buf.size < total) return

        // Consume the frame.
        authBuffer.reset()
        if (buf.size > total) {
            authBuffer.write(buf, total, buf.size - total)
        }

        if (frameType != 0x01L) {
            failSession(HysteriaError.ConnectionFailed("Auth response wasn't HEADERS"))
            return
        }
        val headers = HysteriaHttp3Codec.decodeHeaderBlock(buf, headerLen, total)
            ?: run {
                failSession(HysteriaError.ConnectionFailed("Malformed auth QPACK block"))
                return
            }

        authHeadersReceived = true

        val statusStr = headers.firstOrNull { it.name == ":status" }?.value
        val code = statusStr?.toIntOrNull()
        if (code == null) {
            failSession(HysteriaError.ConnectionFailed("Missing :status on auth response"))
            return
        }
        if (code != HysteriaProtocol.AUTH_SUCCESS_STATUS) {
            failSession(HysteriaError.AuthRejected(code))
            return
        }

        udpSupported = headers.firstOrNull { it.name == "hysteria-udp" }
            ?.value?.lowercase() == "true"
        val ccRxValue = headers.firstOrNull { it.name == "hysteria-cc-rx" }?.value ?: ""
        // Server may respond with "auto" → treat as 0 ("unlimited").
        serverRxBytesPerSec = ccRxValue.toLongOrNull() ?: 0L

        // Brutal tx rate = min(server_rx, client_max_tx); 0 = no server cap.
        val clientTxBps = configuration.uploadBytesPerSec
        val effectiveTxBps = if (serverRxBytesPerSec == 0L) clientTxBps
                             else minOf(serverRxBytesPerSec, clientTxBps)
        applyBrutalBandwidth(effectiveTxBps)

        // Tear down the auth stream.
        quic.shutdownStream(authStreamId, HysteriaProtocol.CLOSE_ERR_CODE_OK)

        callbackScope.launch {
            val toResolve: List<CompletableDeferred<Unit>>
            mutex.withLock {
                state = State.READY
                toResolve = readyDeferreds.toList()
                readyDeferreds.clear()
            }
            for (d in toResolve) d.complete(Unit)
        }
    }

    /**
     * Updates the Brutal target send rate on the QUIC connection. The
     * rate was seeded at construction with `configuration.uploadBytesPerSec`;
     * this call refines it using `min(server_rx, client_tx)` derived
     * from the auth response's `hysteria-cc-rx` header.
     */
    private fun applyBrutalBandwidth(txBytesPerSec: Long) {
        logger.debug("[Hysteria] Brutal CC tx target=${txBytesPerSec} B/s")
        quic.setBrutalBandwidth(txBytesPerSec)
    }

    // -- Datagram dispatch --

    private fun handleDatagram(data: ByteArray) {
        val msg = HysteriaProtocol.decodeUdpMessage(data) ?: return
        udpSessions[msg.sessionId]?.handleIncomingDatagram(msg)
    }

    // -- TCP stream API (called by HysteriaConnection) --

    fun openTcpStream(conn: HysteriaConnection): Long {
        if (state != State.READY) throw HysteriaError.NotReady
        val sid = quic.openBidiStream() ?: throw HysteriaError.ConnectionFailed("Failed to open TCP stream")
        tcpStreams[sid] = conn
        synchronized(poolCounters) { poolTcpCount += 1 }
        return sid
    }

    fun writeStream(sid: Long, data: ByteArray) {
        quic.writeStream(sid, data, fin = false)
    }

    fun extendStreamOffset(sid: Long, count: Int) = quic.extendStreamOffset(sid, count)

    fun shutdownStream(sid: Long, appErrorCode: Long = HysteriaProtocol.CLOSE_ERR_CODE_OK) {
        quic.shutdownStream(sid, appErrorCode)
    }

    fun releaseTcpStream(sid: Long) {
        if (tcpStreams.remove(sid) != null) {
            synchronized(poolCounters) { poolTcpCount = maxOf(0, poolTcpCount - 1) }
        }
    }

    // -- UDP session API --

    /** Registers a new UDP session. Returns null when the server didn't
     *  advertise UDP support. */
    fun registerUdpSession(conn: HysteriaUdpConnection): Int? {
        if (state != State.READY || !udpSupported) return null
        val sid = nextUdpSessionId
        nextUdpSessionId = if (nextUdpSessionId == Int.MAX_VALUE) 1 else nextUdpSessionId + 1
        udpSessions[sid] = conn
        synchronized(poolCounters) { poolUdpCount += 1 }
        return sid
    }

    fun releaseUdpSession(sessionId: Int) {
        if (udpSessions.remove(sessionId) != null) {
            synchronized(poolCounters) { poolUdpCount = maxOf(0, poolUdpCount - 1) }
        }
    }

    fun writeDatagrams(datagrams: List<ByteArray>) {
        for (d in datagrams) quic.writeDatagram(d)
    }

    val maxDatagramPayloadSize: Int get() = quic.maxDatagramPayloadSize

    // -- Close / fail --

    fun close() {
        callbackScope.launch { failSession(HysteriaError.StreamClosed) }
    }

    private fun failSession(error: Throwable) {
        callbackScope.launch {
            mutex.withLock {
                if (state == State.CLOSED) return@launch
                state = State.CLOSED
                poolIsClosed = true
            }

            val toResolve = readyDeferreds.toList()
            readyDeferreds.clear()
            for (d in toResolve) d.completeExceptionally(error)

            val tcp = tcpStreams.values.toList()
            tcpStreams.clear()
            for (c in tcp) c.handleSessionError(error)

            val udp = udpSessions.values.toList()
            udpSessions.clear()
            for (c in udp) c.handleSessionError(error)

            quic.close()
            onClose?.invoke()
        }
    }

    // -- Helpers --

    private fun decodeQuicVarInt(data: ByteArray, offset: Int): Pair<Long, Int>? {
        if (offset >= data.size) return null
        val first = data[offset].toInt() and 0xFF
        val prefix = first ushr 6
        val len = 1 shl prefix
        if (offset + len > data.size) return null
        var v = (first and 0x3F).toLong()
        for (i in 1 until len) v = (v shl 8) or (data[offset + i].toLong() and 0xFF)
        return v to len
    }
}
