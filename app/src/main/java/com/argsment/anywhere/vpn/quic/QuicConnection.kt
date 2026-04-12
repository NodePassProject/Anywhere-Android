package com.argsment.anywhere.vpn.quic

import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private val logger = AnywhereLogger("QUIC")

/** Sealed error hierarchy — mirrors Swift `QUICConnection.QUICError`. */
sealed class QuicError(message: String) : IOException(message) {
    class ConnectionFailed(m: String) : QuicError("QUIC: $m")
    class HandshakeFailed(m: String) : QuicError("QUIC TLS: $m")
    class StreamError(m: String) : QuicError("QUIC stream: $m")
    class Timeout : QuicError("QUIC timeout")
    class Closed : QuicError("QUIC closed")
}

/**
 * A single QUIC connection, anchored on a UDP [DatagramSocket]. All ngtcp2
 * state lives on the C side (see `quic_jni_bridge.c`); this class owns the
 * UDP socket, the read/write coroutines, the retransmit timer, and the
 * Kotlin-side TLS handler.
 *
 * Mirrors the iOS `QUICConnection` — single-threaded event loop (here: a
 * dedicated coroutine dispatcher), packet I/O via a [DatagramSocket], and
 * one-shot retransmit timer keyed to `ngtcp2_conn_get_expiry`.
 */
class QuicConnection(
    private val host: String,
    private val port: Int,
    serverName: String? = null,
    private val alpn: List<String> = listOf("h3"),
    private val datagramsEnabled: Boolean = false
) {
    private val sni: String = serverName ?: host

    enum class State { IDLE, CONNECTING, HANDSHAKING, CONNECTED, CLOSING, CLOSED }

    @Volatile var state: State = State.IDLE
        private set

    /** Opaque native handle for AndroidQuicConn. */
    private var handle: Long = 0

    private var socket: DatagramSocket? = null
    private var hostAddr: InetAddress? = null

    /** Dedicated single-thread dispatcher so all ngtcp2 calls are serialized. */
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "quic-$host:$port").apply { isDaemon = true }
    }
    private val dispatcher: CoroutineDispatcher =
        executor.asCoroutineDispatcher()
    private val scope = CoroutineScope(dispatcher)

    /** Per-packet TLS handshaker. Exposes keys via install* callbacks. */
    private val tls = QuicTlsHandler(sni, alpn, onHandshakeKeys = ::installHandshakeKeys,
                                     onApplicationKeys = ::installApplicationKeys,
                                     onCipherSuite = { suite ->
                                         if (handle != 0L) QuicBridge.nativeSetTlsCipherSuite(handle, suite)
                                     })

    private var connectDeferred: CompletableDeferred<Unit>? = null
    private var readerJob: Job? = null
    private var timerJob: Job? = null

    /** Callbacks to the application (HTTP/3 layer). */
    var streamDataHandler: ((Long, ByteArray, Boolean) -> Unit)? = null
    var datagramHandler: ((ByteArray) -> Unit)? = null
    var connectionClosedHandler: ((Throwable) -> Unit)? = null

    private val callbacks = object : QuicBridge.NativeCallbacks {
        override fun buildClientHello(transportParams: ByteArray): ByteArray? {
            return try { tls.buildClientHello(transportParams) }
            catch (e: Throwable) { logger.error("buildClientHello failed: $e"); null }
        }

        override fun processCryptoData(level: Int, data: ByteArray): Int {
            return try {
                tls.processCryptoData(handle, level, data)
            } catch (e: Throwable) {
                logger.error("processCryptoData failed: $e")
                -1
            }
        }

        override fun onStreamData(streamId: Long, data: ByteArray, fin: Boolean) {
            streamDataHandler?.invoke(streamId, data, fin)
        }

        override fun onAckedStreamData(streamId: Long, offset: Long, dataLen: Long) {
            // No-op: ngtcp2 tracks retransmission state internally.
        }

        override fun onStreamClose(streamId: Long, appErrorCode: Long) {
            // No-op: HTTP/3 layer tracks stream state via FIN.
        }

        override fun onRecvDatagram(data: ByteArray) {
            datagramHandler?.invoke(data)
        }

        override fun onHandshakeCompleted() {
            state = State.CONNECTED
            connectDeferred?.complete(Unit)
            connectDeferred = null
        }

        override fun sendUdpPacket(packet: ByteArray) {
            val s = socket ?: return
            val addr = hostAddr ?: return
            try {
                s.send(DatagramPacket(packet, packet.size, addr, port))
            } catch (e: Exception) {
                logger.error("UDP send failed: ${e.message}")
            }
        }
    }

    suspend fun connect() {
        if (state != State.IDLE) throw QuicError.ConnectionFailed("Invalid state")
        state = State.CONNECTING

        val addr = resolveHost(host) ?: throw QuicError.ConnectionFailed("DNS failed: $host")
        hostAddr = addr
        val ipv6 = addr.address.size == 16

        val sock = DatagramSocket()
        sock.connect(InetSocketAddress(addr, port))
        sock.soTimeout = 100 // short timeout so the reader loop can check state
        socket = sock

        handle = QuicBridge.nativeCreate(callbacks, host, port, ipv6,
                                          addr.address, datagramsEnabled)
        if (handle == 0L) {
            state = State.CLOSED
            sock.close()
            throw QuicError.ConnectionFailed("ngtcp2_conn_client_new failed")
        }

        state = State.HANDSHAKING
        connectDeferred = CompletableDeferred()

        startReader()
        flushOutgoing(streamId = -1, data = null, fin = false)
        rescheduleTimer()

        try {
            connectDeferred!!.await()
        } catch (e: Throwable) {
            close(e)
            throw e
        }
    }

    private fun startReader() {
        readerJob = scope.launch {
            val buf = ByteArray(2048)
            val pkt = DatagramPacket(buf, buf.size)
            val s = socket ?: return@launch
            while (isActive && state != State.CLOSED) {
                try {
                    s.receive(pkt)
                } catch (_: java.net.SocketTimeoutException) {
                    continue
                } catch (e: Exception) {
                    if (state != State.CLOSED) logger.error("UDP recv: ${e.message}")
                    break
                }
                val data = buf.copyOfRange(0, pkt.length)
                val rv = QuicBridge.nativeReadPacket(handle, data)
                if (rv != 0) {
                    val err = when (rv) {
                        NGTCP2_ERR_DRAINING, NGTCP2_ERR_CLOSING -> QuicError.Closed()
                        NGTCP2_ERR_CALLBACK_FAILURE, NGTCP2_ERR_CRYPTO -> QuicError.HandshakeFailed("ngtcp2 $rv")
                        else -> null
                    }
                    if (err != null) {
                        connectDeferred?.completeExceptionally(err)
                        connectDeferred = null
                        close(err)
                        return@launch
                    }
                }
                flushOutgoing(streamId = -1, data = null, fin = false)
            }
        }
    }

    /** Serializes all writes through the single-thread executor. */
    fun writeStream(streamId: Long, data: ByteArray, fin: Boolean) {
        scope.launch {
            if (state != State.CONNECTED && state != State.HANDSHAKING) return@launch
            flushOutgoing(streamId, data, fin)
        }
    }

    fun openBidiStream(): Long? {
        if (state != State.CONNECTED) return null
        val sid = QuicBridge.nativeOpenBidiStream(handle)
        return if (sid < 0) null else sid
    }

    fun openUniStream(): Long? {
        if (state != State.CONNECTED) return null
        val sid = QuicBridge.nativeOpenUniStream(handle)
        return if (sid < 0) null else sid
    }

    fun extendStreamOffset(streamId: Long, count: Int) {
        if (count <= 0) return
        scope.launch {
            if (handle != 0L) QuicBridge.nativeExtendStreamOffset(handle, streamId, count.toLong())
        }
    }

    fun shutdownStream(streamId: Long, appErrorCode: Long = 0x0100L) {
        scope.launch {
            if (handle != 0L) {
                QuicBridge.nativeShutdownStream(handle, streamId, appErrorCode)
                flushOutgoing(streamId = -1, data = null, fin = false)
            }
        }
    }

    fun writeDatagram(data: ByteArray): Int {
        if (state != State.CONNECTED) return -1
        return QuicBridge.nativeWriteDatagram(handle, data)
    }

    val maxDatagramPayloadSize: Int
        get() = if (handle == 0L) 0 else QuicBridge.nativeMaxDatagramPayload(handle).toInt()

    private fun flushOutgoing(streamId: Long, data: ByteArray?, fin: Boolean) {
        if (handle == 0L) return
        QuicBridge.nativeWriteLoop(handle, streamId, data, fin)
        rescheduleTimer()
    }

    private fun rescheduleTimer() {
        val expiry = QuicBridge.nativeGetExpiry(handle)
        if (expiry < 0) { timerJob?.cancel(); timerJob = null; return }
        val nowNs = System.nanoTime()
        val delayNs = (expiry - nowNs).coerceAtLeast(0)
        timerJob?.cancel()
        timerJob = scope.launch {
            delay(delayNs / 1_000_000L + 1)
            if (!isActive || state == State.CLOSED) return@launch
            val rv = QuicBridge.nativeHandleExpiry(handle)
            if (rv != 0) {
                val err = QuicError.ConnectionFailed("expiry error: $rv")
                connectDeferred?.completeExceptionally(err)
                connectDeferred = null
                close(err)
                return@launch
            }
            flushOutgoing(streamId = -1, data = null, fin = false)
        }
    }

    fun close(error: Throwable? = null) {
        if (state == State.CLOSED) return
        scope.launch { closeInternal(error) }
    }

    private fun closeInternal(error: Throwable?) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        timerJob?.cancel(); timerJob = null
        readerJob?.cancel(); readerJob = null
        socket?.close(); socket = null
        if (handle != 0L) {
            QuicBridge.nativeDestroy(handle)
            handle = 0L
        }
        val e = error ?: QuicError.Closed()
        connectionClosedHandler?.invoke(e)
        connectionClosedHandler = null
        executor.shutdown()
    }

    /** Callback from QuicTlsHandler to install derived handshake keys. */
    private fun installHandshakeKeys(rxSecret: ByteArray, txSecret: ByteArray): Int {
        return if (handle == 0L) -1
        else QuicBridge.nativeInstallHandshakeKeys(handle, rxSecret, txSecret)
    }

    /** Callback from QuicTlsHandler to install derived application keys. */
    private fun installApplicationKeys(rxSecret: ByteArray, txSecret: ByteArray): Int {
        return if (handle == 0L) -1
        else QuicBridge.nativeInstallApplicationKeys(handle, rxSecret, txSecret)
    }

    private fun resolveHost(name: String): InetAddress? {
        return runCatching {
            val addrs = InetAddress.getAllByName(name)
            // Prefer IPv4 first (matches iOS behavior for QUIC).
            addrs.firstOrNull { it is java.net.Inet4Address } ?: addrs.firstOrNull()
        }.getOrNull()
    }

    companion object {
        // ngtcp2 error codes we need to distinguish in Kotlin.
        const val NGTCP2_ERR_DRAINING = -231
        const val NGTCP2_ERR_CLOSING = -230
        const val NGTCP2_ERR_CALLBACK_FAILURE = -228
        const val NGTCP2_ERR_CRYPTO = -226
    }
}
