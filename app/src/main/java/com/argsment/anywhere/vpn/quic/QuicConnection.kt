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
    private val datagramsEnabled: Boolean = false,
    /**
     * Per-protocol tuning knobs. Defaults to [QuicTuning.naive] which
     * matches Chromium's QUIC client (CUBIC + 64 MB / 128 MB windows).
     * Pass [QuicTuning.hysteria] for Hysteria v2 sessions — that preset
     * selects [QuicTuning.CongestionControl.Brutal] which causes
     * [connect] to overlay the Brutal callbacks on top of ngtcp2's
     * CUBIC state once the connection exists.
     *
     * Mirrors `QUICTuning` on iOS (`Shared/QUIC/QUICTuning.swift`).
     */
    private val tuning: QuicTuning = QuicTuning.naive
) {
    private val sni: String = serverName ?: host

    enum class State { IDLE, CONNECTING, HANDSHAKING, CONNECTED, CLOSING, CLOSED }

    @Volatile var state: State = State.IDLE
        private set

    /** Opaque native handle for AndroidQuicConn. */
    private var handle: Long = 0

    private var socket: DatagramSocket? = null
    private var hostAddr: InetAddress? = null

    /** Dedicated single-thread dispatcher for coroutines that mutate
     *  Kotlin-side state (timer scheduling, write coalescing, etc.). */
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "quic-$host:$port").apply { isDaemon = true }
    }
    private val dispatcher: CoroutineDispatcher =
        executor.asCoroutineDispatcher()
    private val scope = CoroutineScope(dispatcher)

    /**
     * ngtcp2 is not thread-safe, so every `ngtcp2_conn_*` call must be
     * serialized. We use a plain lock rather than dispatching to the
     * `executor`: the reader coroutine runs on `executor` and parks on a
     * blocking `DatagramSocket.receive` syscall with no coroutine
     * suspension points, so an `executor.submit { … }.get()` from another
     * thread would queue behind the reader and never run. With a lock the
     * reader holds it only during `nativeReadPacket` + the trailing
     * `flushOutgoing`, releasing it between iterations so external callers
     * (e.g. `HysteriaSession.openHttp3Control()` from `Dispatchers.IO`) can
     * acquire it between packets. iOS's serial GCD queue already yields
     * around `NWConnection.receive` callbacks; on Android the equivalent
     * is this lock.
     */
    private val ngtcp2Lock = Any()

    private fun <T> runOnQuicThread(block: () -> T): T? = try {
        synchronized(ngtcp2Lock) { block() }
    } catch (_: Throwable) { null }

    /** Per-packet TLS handshaker. Exposes keys via install* callbacks. */
    private val tls = QuicTlsHandler(sni, alpn, onHandshakeKeys = ::installHandshakeKeys,
                                     onApplicationKeys = ::installApplicationKeys,
                                     onCipherSuite = { suite ->
                                         if (handle != 0L) QuicBridge.nativeSetTlsCipherSuite(handle, suite)
                                     })

    private var connectDeferred: CompletableDeferred<Unit>? = null
    private var readerJob: Job? = null
    private var timerJob: Job? = null

    /**
     * Hysteria Brutal CC handle. Non-null when [tuning]'s congestion
     * controller is [QuicTuning.CongestionControl.Brutal] and the native
     * install succeeded. Its lifetime matches the ngtcp2 connection;
     * `nativeDestroy` tears down the registry entry before freeing
     * `conn->cc`.
     */
    private var brutalCC: BrutalCongestionControl? = null

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
        // Match iOS RawUDPSocket (4 MB) so a paced QUIC sender doesn't get
        // stalled by the kernel's default ~200 KB datagram buffer when the
        // path is briefly under-served. iOS does this in QUICConnection.swift
        // setupUDP() via SO_SNDBUF/SO_RCVBUF setsockopt — Java exposes the
        // same knobs on DatagramSocket.
        try { sock.sendBufferSize = 4 * 1024 * 1024 } catch (_: Throwable) {}
        try { sock.receiveBufferSize = 4 * 1024 * 1024 } catch (_: Throwable) {}
        sock.connect(InetSocketAddress(addr, port))
        sock.soTimeout = 100 // short timeout so the reader loop can check state
        socket = sock

        val tuningParams = longArrayOf(
            tuning.ngtcp2CcAlgo.toLong(),
            tuning.maxStreamWindow,
            tuning.maxWindow,
            tuning.initialMaxData,
            tuning.initialMaxStreamDataBidiLocal,
            tuning.initialMaxStreamDataBidiRemote,
            tuning.initialMaxStreamDataUni,
            tuning.initialMaxStreamsBidi,
            tuning.initialMaxStreamsUni,
            tuning.maxIdleTimeoutNs,
            tuning.handshakeTimeoutNs,
            if (tuning.disableActiveMigration) 1L else 0L,
            // Emit a PING every 15 s of inactivity so a silently-broken UDP
            // path (carrier NAT rebind, server-side idle sweep) surfaces as a
            // loss / idle-close within one retransmission cycle. Mirrors
            // QUICConnection.swift:830 and naiveproxy's
            // `set_keep_alive_ping_timeout(kPingTimeoutSecs)`.
            15L * 1_000_000_000L
        )

        handle = QuicBridge.nativeCreate(callbacks, host, port, ipv6,
                                          addr.address, datagramsEnabled,
                                          tuningParams)
        if (handle == 0L) {
            state = State.CLOSED
            sock.close()
            throw QuicError.ConnectionFailed("ngtcp2_conn_client_new failed")
        }

        // Install Brutal CC on top of CUBIC before any packets have been
        // read/sent, so no stale CUBIC decisions leak through. Mirrors
        // QUICConnection.swift:839.
        (tuning.cc as? QuicTuning.CongestionControl.Brutal)?.let { brutal ->
            val cc = BrutalCongestionControl(handle)
            cc.install(brutal.initialBps)
            brutalCC = cc
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
        // The reader parks in `DatagramSocket.receive` — a blocking syscall
        // with no coroutine suspension points. If we let this coroutine run
        // on the QUIC executor (a single-thread dispatcher), the reader
        // would monopolize the only thread and every other `scope.launch`
        // (writes, timer, shutdown, close) would starve. ngtcp2 itself is
        // serialized by `ngtcp2Lock`, so we only need the executor for
        // ordering Kotlin-side coroutines, not for the read loop. Run it
        // on `Dispatchers.IO` instead, where blocking I/O belongs.
        readerJob = scope.launch(kotlinx.coroutines.Dispatchers.IO) {
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
                val rv = synchronized(ngtcp2Lock) {
                    if (handle == 0L) 0 else QuicBridge.nativeReadPacket(handle, data)
                }
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

    fun openBidiStream(): Long? = runOnQuicThread {
        if (state != State.CONNECTED || handle == 0L) null
        else QuicBridge.nativeOpenBidiStream(handle).takeIf { it >= 0 }
    }

    fun openUniStream(): Long? = runOnQuicThread {
        if (state != State.CONNECTED || handle == 0L) null
        else QuicBridge.nativeOpenUniStream(handle).takeIf { it >= 0 }
    }

    fun extendStreamOffset(streamId: Long, count: Int) {
        if (count <= 0) return
        scope.launch {
            synchronized(ngtcp2Lock) {
                if (handle != 0L) QuicBridge.nativeExtendStreamOffset(handle, streamId, count.toLong())
            }
        }
    }

    fun shutdownStream(streamId: Long, appErrorCode: Long = 0x0100L) {
        scope.launch {
            val needsFlush = synchronized(ngtcp2Lock) {
                if (handle == 0L) false
                else {
                    QuicBridge.nativeShutdownStream(handle, streamId, appErrorCode)
                    true
                }
            }
            if (needsFlush) flushOutgoing(streamId = -1, data = null, fin = false)
        }
    }

    fun writeDatagram(data: ByteArray): Int = runOnQuicThread {
        if (state != State.CONNECTED || handle == 0L) -1
        else QuicBridge.nativeWriteDatagram(handle, data)
    } ?: -1

    /**
     * Updates the Hysteria Brutal target send rate (bytes/sec). No-op
     * if this connection wasn't constructed with a Brutal-flavoured
     * [QuicTuning]. Safe to call from any thread. Mirrors
     * `QUICConnection.setBrutalBandwidth` on iOS.
     */
    fun setBrutalBandwidth(bytesPerSec: Long) {
        scope.launch {
            brutalCC?.setTargetBandwidth(bytesPerSec)
        }
    }

    val maxDatagramPayloadSize: Int
        get() = runOnQuicThread {
            if (handle == 0L) 0 else QuicBridge.nativeMaxDatagramPayload(handle).toInt()
        } ?: 0

    private fun flushOutgoing(streamId: Long, data: ByteArray?, fin: Boolean) {
        synchronized(ngtcp2Lock) {
            if (handle == 0L) return
            QuicBridge.nativeWriteLoop(handle, streamId, data, fin)
            rescheduleTimer()
        }
    }

    /** Caller must hold [ngtcp2Lock]. */
    private fun rescheduleTimer() {
        if (handle == 0L) { timerJob?.cancel(); timerJob = null; return }
        val expiry = QuicBridge.nativeGetExpiry(handle)
        if (expiry < 0) { timerJob?.cancel(); timerJob = null; return }
        val nowNs = System.nanoTime()
        val delayNs = (expiry - nowNs).coerceAtLeast(0)
        timerJob?.cancel()
        timerJob = scope.launch {
            delay(delayNs / 1_000_000L + 1)
            if (!isActive || state == State.CLOSED) return@launch
            val rv = synchronized(ngtcp2Lock) {
                if (handle == 0L) 0 else QuicBridge.nativeHandleExpiry(handle)
            }
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
        synchronized(ngtcp2Lock) {
            if (handle != 0L) {
                // `nativeDestroy` removes the Brutal registry entry before
                // freeing `conn->cc`, so no explicit tear-down here.
                QuicBridge.nativeDestroy(handle)
                handle = 0L
            }
        }
        brutalCC = null
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
