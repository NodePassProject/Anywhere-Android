package com.argsment.anywhere.vpn.util

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.SocketProtector
import com.argsment.anywhere.vpn.protocol.Transport
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.CancelledKeyException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

private val logger = AnywhereLogger("NioSocket")

sealed class NioSocketError(message: String) : IOException(message) {
    class ResolutionFailed(msg: String) : NioSocketError("DNS resolution failed: $msg")
    class SocketCreationFailed(msg: String) : NioSocketError("Socket creation failed: $msg")
    class ConnectionFailed(msg: String) : NioSocketError("Connection failed: $msg")
    class NotConnected : NioSocketError("Not connected")
    class SendFailed(msg: String) : NioSocketError("Send failed: $msg")
    class ReceiveFailed(msg: String) : NioSocketError("Receive failed: $msg")
}

/**
 * Non-blocking TCP socket using a shared selector thread for all socket I/O.
 *
 * A single shared selector thread services every instance — per-socket
 * threads would cause GC pressure and native OOM under many connections.
 *
 * CRITICAL: [SocketProtector.protect] must be called before connect to
 * prevent a VPN routing loop.
 */
class NioSocket : Transport {

    enum class State {
        SETUP, READY, FAILED, CANCELLED
    }

    @Volatile
    var state: State = State.SETUP
        private set

    private var channel: SocketChannel? = null
    @Volatile
    private var selectionKey: SelectionKey? = null
    @Volatile
    private var running = false

    // AtomicReference for thread-safe claim between selector and timeout.
    private val connectCont = AtomicReference<Continuation<Unit>?>(null)
    private var connectTimeout: ScheduledFuture<*>? = null

    /**
     * Optional bytes to send the instant the handshake completes, piggybacked
     * on the ACK. Only read on the selector thread in [onConnectable].
     */
    @Volatile
    private var pendingInitialData: ByteArray? = null

    // Only accessed from caller coroutine.
    private var fastPathBuffer: ByteBuffer? = null

    private val pendingReceive = AtomicReference<Continuation<ByteArray?>?>(null)
    private val pendingSends = ConcurrentLinkedQueue<PendingSend>()

    private class PendingSend(
        val data: ByteArray,
        var offset: Int = 0,
        val continuation: Continuation<Unit>?
    )

    companion object {
        private const val CONNECT_TIMEOUT_MS = 16_000L

        private val sharedSelector: Selector = Selector.open()
        private val pendingOps = ConcurrentLinkedQueue<() -> Unit>()

        private val timeoutScheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "NioSocket-timeout").apply { isDaemon = true }
        }

        /**
         * Runs continuation resumes off the selector thread.
         *
         * The selector is shared across every NioSocket in the process. If a
         * selector callback resumed a continuation whose dispatcher ran work
         * inline (e.g. Unconfined), the selector would end up executing
         * TLS/Reality/VLESS handshake code before returning to `select()`,
         * stalling I/O for every other socket. Dispatching resumes here keeps
         * the selector hot for event dispatch only.
         */
        private val resumeExecutor = Executors.newCachedThreadPool { r ->
            Thread(r, "NioSocket-resume").apply { isDaemon = true }
        }

        /** Only accessed from selectorThread. */
        private val selectorReadBuffer = ByteBuffer.allocate(131072)

        private const val MAX_PENDING_SEND_BYTES = 4_194_304

        private val selectorThread = Thread({
            while (true) {
                try {
                    sharedSelector.select()

                    while (true) {
                        val op = pendingOps.poll() ?: break
                        try { op() } catch (e: Exception) {
                            logger.debug("Pending op error: ${e.message}")
                        }
                    }

                    val iter = sharedSelector.selectedKeys().iterator()
                    while (iter.hasNext()) {
                        val key = iter.next()
                        iter.remove()
                        if (!key.isValid) continue

                        val socket = key.attachment() as? NioSocket ?: continue
                        try {
                            if (key.isConnectable) socket.onConnectable(key)
                            if (key.isValid && key.isReadable) socket.onReadable(key)
                            if (key.isValid && key.isWritable) socket.onWritable(key)
                        } catch (_: CancelledKeyException) {
                        } catch (e: Exception) {
                            logger.debug("Key handler error: ${e.message}")
                        }
                    }
                } catch (e: Exception) {
                    logger.debug("Selector loop error: ${e.message}")
                }
            }
        }, "NioSocket-selector").apply { isDaemon = true }

        init { selectorThread.start() }

        private fun runOnSelector(op: () -> Unit) {
            pendingOps.add(op)
            sharedSelector.wakeup()
        }
    }

    /**
     * Connects to a remote host.
     *
     * @param initialData Optional bytes to send as the first payload on the
     *   new socket. They are queued on the selector thread the instant
     *   [finishConnect] returns true, so the first `write(2)` piggybacks on
     *   the ACK of the TCP handshake (no extra coroutine yield between
     *   connect completion and the first send).
     */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null) {
        val bare = if (host.startsWith("[") && host.endsWith("]")) {
            host.substring(1, host.length - 1)
        } else {
            host
        }

        val ipStrings = DnsCache.resolveAll(bare)
        if (ipStrings.isEmpty()) {
            state = State.FAILED
            throw NioSocketError.ResolutionFailed("No addresses returned for $bare")
        }

        val addresses = ipStrings.mapNotNull { ip ->
            try { InetAddress.getByName(ip) } catch (_: Exception) { null }
        }
        if (addresses.isEmpty()) {
            state = State.FAILED
            throw NioSocketError.ResolutionFailed("No usable addresses for $bare")
        }

        // Prefer IPv4 to avoid long timeouts when IPv6 is unreachable; IPv6
        // addresses are tried only after all IPv4 addresses fail.
        val sorted = addresses.sortedBy { if (it is Inet4Address) 0 else 1 }

        var lastError: Exception? = null
        for (addr in sorted) {
            try {
                connectToAddress(InetSocketAddress(addr, port), initialData)
                return
            } catch (e: Exception) {
                lastError = e
            }
        }

        state = State.FAILED
        throw NioSocketError.ConnectionFailed(lastError?.message ?: "All addresses failed")
    }

    private suspend fun connectToAddress(
        address: InetSocketAddress,
        initialData: ByteArray? = null
    ) {
        val ch = SocketChannel.open()
        ch.configureBlocking(false)
        ch.setOption(StandardSocketOptions.TCP_NODELAY, true)
        ch.setOption(StandardSocketOptions.SO_KEEPALIVE, true)
        // Tighten kernel keep-alive defaults so a half-open peer (Wi-Fi drop,
        // NAT rebind, server crash) is detected within ~60 s instead of the
        // kernel default of ~2 h.
        applyTcpKeepAliveTuning(ch)

        // Protect socket from VPN routing loop BEFORE connect.
        if (!SocketProtector.protect(ch.socket())) {
            ch.close()
            throw NioSocketError.ConnectionFailed("Failed to protect socket")
        }

        // Stash initialData before connect starts so that onConnectable can
        // queue it the instant finishConnect() returns true. The kernel will
        // piggyback the first write on the ACK of the handshake, avoiding a
        // separate segment for the ClientHello.
        if (initialData != null && initialData.isNotEmpty()) {
            pendingInitialData = initialData
        }

        try {
            ch.connect(address)
        } catch (e: Exception) {
            pendingInitialData = null
            ch.close()
            throw NioSocketError.ConnectionFailed(e.message ?: "Connect initiation failed")
        }

        // suspendCancellableCoroutine lets coroutine cancellation interrupt
        // the wait without an external forceCancel().
        suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
            connectCont.set(cont)
            cont.invokeOnCancellation {
                // Atomic claim so onConnectable/timeout won't double-resume.
                if (connectCont.compareAndSet(cont, null)) {
                    connectTimeout?.cancel(false)
                    connectTimeout = null
                    runCatching { ch.close() }
                }
            }

            connectTimeout = timeoutScheduler.schedule({
                runOnSelector {
                    val cc = connectCont.getAndSet(null) ?: return@runOnSelector
                    connectTimeout = null
                    runCatching { ch.close() }
                    resumeSafe(cc) { it.resumeWithException(
                        NioSocketError.ConnectionFailed("Connection timed out")
                    ) }
                }
            }, CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)

            runOnSelector {
                try {
                    ch.register(sharedSelector, SelectionKey.OP_CONNECT, this)
                } catch (e: Exception) {
                    val cc = connectCont.getAndSet(null) ?: return@runOnSelector
                    connectTimeout?.cancel(false)
                    connectTimeout = null
                    runCatching { ch.close() }
                    resumeSafe(cc) { it.resumeWithException(
                        NioSocketError.ConnectionFailed(e.message ?: "Registration failed")
                    ) }
                }
            }
        }
    }

    /** Selector thread. */
    private fun onConnectable(key: SelectionKey) {
        val ch = key.channel() as SocketChannel
        try {
            if (ch.finishConnect()) {
                val cc = connectCont.getAndSet(null) ?: return
                connectTimeout?.cancel(false)
                connectTimeout = null

                channel = ch
                selectionKey = key
                state = State.READY
                running = true

                // Queue initialData so the first segment carrying the
                // handshake ACK also carries the payload. Writing here on
                // the selector thread, before the caller resumes, ensures
                // the kernel piggybacks the data onto the ACK.
                val initial = pendingInitialData
                pendingInitialData = null
                var needWriteInterest = false
                if (initial != null) {
                    try {
                        val buffer = ByteBuffer.wrap(initial)
                        ch.write(buffer)
                        if (buffer.hasRemaining()) {
                            // Partial write: enqueue remainder for OP_WRITE.
                            // Fire-and-forget — no continuation.
                            val offset = buffer.position()
                            pendingSends.add(PendingSend(initial, offset, null))
                            needWriteInterest = true
                        }
                    } catch (e: IOException) {
                        // First write after a successful TCP handshake failed.
                        // The socket is unusable, so fail the connect rather
                        // than hand the caller a doomed connection.
                        state = State.FAILED
                        running = false
                        channel = null
                        selectionKey = null
                        runCatching { ch.close() }
                        key.cancel()
                        resumeSafe(cc) { it.resumeWithException(
                            NioSocketError.ConnectionFailed(
                                "Initial payload send failed: ${e.message ?: "write failed"}"
                            )
                        ) }
                        return
                    }
                }

                // No read interest initially — receive() adds OP_READ when
                // needed. Prevents a busy-loop when the channel is readable
                // but nobody has called receive() yet.
                key.interestOps(if (needWriteInterest) SelectionKey.OP_WRITE else 0)

                resumeSafe(cc) { it.resume(Unit) }
            }
        } catch (e: IOException) {
            val cc = connectCont.getAndSet(null) ?: return
            connectTimeout?.cancel(false)
            connectTimeout = null
            pendingInitialData = null
            runCatching { ch.close() }
            key.cancel()
            resumeSafe(cc) { it.resumeWithException(
                NioSocketError.ConnectionFailed(e.message ?: "Connect failed")
            ) }
        }
    }

    /**
     * Receives up to 64KB. Returns null on EOF.
     */
    override suspend fun receive(): ByteArray? {
        val ch = channel ?: throw NioSocketError.NotConnected()
        if (!ch.isOpen) throw NioSocketError.NotConnected()

        // Reuse buffer to avoid per-call 64KB allocation.
        val buffer = (fastPathBuffer ?: ByteBuffer.allocate(65536).also { fastPathBuffer = it }).also { it.clear() }
        try {
            val n = ch.read(buffer)
            when {
                n > 0 -> {
                    buffer.flip()
                    val data = ByteArray(n)
                    buffer.get(data)
                    return data
                }
                n < 0 -> return null
            }
        } catch (e: IOException) {
            throw NioSocketError.ReceiveFailed(e.message ?: "Read failed")
        }

        // suspendCancellableCoroutine lets coroutine cancellation interrupt
        // the wait immediately rather than hanging until forceCancel().
        return suspendCancellableCoroutine { cont ->
            pendingReceive.set(cont)
            cont.invokeOnCancellation {
                pendingReceive.compareAndSet(cont, null)
            }
            runOnSelector {
                val key = selectionKey
                if (key != null && key.isValid) {
                    try {
                        key.interestOps(key.interestOps() or SelectionKey.OP_READ)
                    } catch (_: CancelledKeyException) {}
                }
            }
        }
    }

    /** Selector thread. */
    private fun onReadable(key: SelectionKey) {
        val cont = pendingReceive.getAndSet(null)
        if (cont == null) {
            // No one waiting — remove OP_READ to prevent busy-loop.
            if (key.isValid) {
                try {
                    key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv())
                } catch (_: CancelledKeyException) {}
            }
            return
        }

        val ch = key.channel() as SocketChannel
        val buffer = selectorReadBuffer
        buffer.clear()
        try {
            val n = ch.read(buffer)
            when {
                n > 0 -> {
                    buffer.flip()
                    val data = ByteArray(n)
                    buffer.get(data)
                    if (key.isValid) {
                        try {
                            key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv())
                        } catch (_: CancelledKeyException) {}
                    }
                    resumeSafe(cont) { it.resume(data) }
                }
                n == 0 -> {
                    pendingReceive.set(cont)
                }
                else -> {
                    resumeSafe(cont) { it.resume(null) }
                }
            }
        } catch (e: IOException) {
            resumeSafe(cont) { it.resumeWithException(NioSocketError.ReceiveFailed(e.message ?: "Read failed")) }
        }
    }

    /**
     * Dispatches the resume onto [resumeExecutor] so the caller's next block
     * never runs inline on the selector thread — without the hop, a resumed
     * coroutine whose dispatcher runs work inline would execute handshake
     * code (TLS, Reality, VLESS) on the selector and stall every other
     * NioSocket in the process.
     *
     * Also swallows the IllegalStateException that a concurrently-cancelled
     * suspendCancellableCoroutine throws on resume.
     */
    private inline fun <T> resumeSafe(cont: Continuation<T>, crossinline block: (Continuation<T>) -> Unit) {
        resumeExecutor.execute {
            try {
                block(cont)
            } catch (_: IllegalStateException) {
            }
        }
    }

    override suspend fun send(data: ByteArray) {
        val ch = channel ?: throw NioSocketError.NotConnected()
        if (!ch.isOpen) throw NioSocketError.NotConnected()
        if (queuedSendBytes() + data.size > MAX_PENDING_SEND_BYTES) {
            throw NioSocketError.SendFailed("Send queue full")
        }

        // Only attempt immediate write if no pending sends are queued. A
        // previous partial write leaves its remainder in pendingSends;
        // writing directly here would interleave data on the wire and
        // corrupt the stream.
        if (pendingSends.isEmpty()) {
            val buffer = ByteBuffer.wrap(data)
            try {
                val written = ch.write(buffer)
                if (written >= data.size) return
            } catch (e: IOException) {
                throw NioSocketError.SendFailed(e.message ?: "Write failed")
            }

            val offset = buffer.position()
            suspendCoroutine { cont: Continuation<Unit> ->
                pendingSends.add(PendingSend(data, offset, cont))
                runOnSelector {
                    val key = selectionKey
                    if (key != null && key.isValid) {
                        try {
                            key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
                        } catch (_: CancelledKeyException) {}
                    }
                }
            }
        } else {
            suspendCoroutine { cont: Continuation<Unit> ->
                pendingSends.add(PendingSend(data, 0, cont))
                runOnSelector {
                    val key = selectionKey
                    if (key != null && key.isValid) {
                        try {
                            key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
                        } catch (_: CancelledKeyException) {}
                    }
                }
            }
        }
    }

    override fun sendAsync(data: ByteArray) {
        val ch = channel ?: return
        if (!ch.isOpen) return
        if (queuedSendBytes() + data.size > MAX_PENDING_SEND_BYTES) {
            logger.debug("Send queue full, dropping ${data.size} bytes")
            return
        }

        pendingSends.add(PendingSend(data, 0, null))
        runOnSelector {
            val key = selectionKey
            if (key != null && key.isValid) {
                try {
                    key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
                } catch (_: CancelledKeyException) {}
            }
        }
    }

    /** Selector thread. */
    private fun onWritable(key: SelectionKey) {
        val ch = key.channel() as SocketChannel

        while (true) {
            val send = pendingSends.peek() ?: break

            val remaining = send.data.size - send.offset
            val buffer = ByteBuffer.wrap(send.data, send.offset, remaining)

            try {
                val written = ch.write(buffer)
                if (written > 0) {
                    send.offset += written
                    if (send.offset >= send.data.size) {
                        pendingSends.poll()
                        send.continuation?.let { cont ->
                            resumeSafe(cont) { it.resume(Unit) }
                        }
                    }
                } else {
                    break
                }
            } catch (e: IOException) {
                val err = NioSocketError.SendFailed(e.message ?: "Write failed")
                pendingSends.poll()
                send.continuation?.let { cont ->
                    resumeSafe(cont) { it.resumeWithException(err) }
                }
                while (true) {
                    val s = pendingSends.poll() ?: break
                    s.continuation?.let { cont ->
                        resumeSafe(cont) { it.resumeWithException(err) }
                    }
                }
                break
            }
        }

        if (pendingSends.isEmpty() && key.isValid) {
            try {
                key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
            } catch (_: CancelledKeyException) {}
        }
    }

    override fun forceCancel() {
        running = false
        state = State.CANCELLED

        connectCont.getAndSet(null)?.let { cont ->
            resumeSafe(cont) { it.resumeWithException(NioSocketError.NotConnected()) }
        }
        connectTimeout?.cancel(false)
        connectTimeout = null

        pendingReceive.getAndSet(null)?.let { cont ->
            resumeSafe(cont) { it.resume(null) }
        }

        while (true) {
            val send = pendingSends.poll() ?: break
            send.continuation?.let { cont ->
                resumeSafe(cont) { it.resumeWithException(NioSocketError.NotConnected()) }
            }
        }

        try { channel?.close() } catch (_: Exception) {}
        channel = null
        selectionKey = null
        fastPathBuffer = null
    }

    private fun queuedSendBytes(): Int {
        var total = 0
        for (send in pendingSends) {
            total += send.data.size - send.offset
        }
        return total
    }

    /**
     * Tunes keep-alive (idle = 30 s, probe interval = 10 s, max probes = 3 →
     * ~60 s to surface a dead peer).
     *
     * `SocketChannel` exposes only `SO_KEEPALIVE` through
     * [StandardSocketOptions]; the per-knob TCP options live on the
     * underlying file descriptor and have to be poked via reflection on
     * `FileDescriptor` + `Os.setsockoptInt`. Wrapped in best-effort
     * try/catch — if the platform's libcore signature drifts, fall back to
     * the kernel default rather than failing the connect.
     */
    private fun applyTcpKeepAliveTuning(ch: SocketChannel) {
        try {
            val fd = ch.socket().getFileDescriptorField()
                ?: return
            val osClass = Class.forName("android.system.Os")
            val osConstantsClass = Class.forName("android.system.OsConstants")

            fun constant(name: String): Int =
                osConstantsClass.getField(name).getInt(null)

            val ipprotoTcp = constant("IPPROTO_TCP")
            val keepIdle = runCatching { constant("TCP_KEEPIDLE") }.getOrNull()
            val keepIntvl = runCatching { constant("TCP_KEEPINTVL") }.getOrNull()
            val keepCnt = runCatching { constant("TCP_KEEPCNT") }.getOrNull()

            val setIntMethod = osClass.getMethod(
                "setsockoptInt",
                java.io.FileDescriptor::class.java,
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType
            )
            keepIdle?.let { setIntMethod.invoke(null, fd, ipprotoTcp, it, 30) }
            keepIntvl?.let { setIntMethod.invoke(null, fd, ipprotoTcp, it, 10) }
            keepCnt?.let { setIntMethod.invoke(null, fd, ipprotoTcp, it, 3) }
        } catch (_: Throwable) {
            // Older / restricted Android builds may not expose the underlying
            // setsockopt or the FD field. Default keep-alive is still on via
            // SO_KEEPALIVE.
        }
    }
}

/**
 * Reads the private `FileDescriptor` field that `java.net.Socket` carries
 * for its underlying kernel fd. Returns null when the field isn't exposed
 * — the caller treats that as "skip optional tuning."
 */
private fun java.net.Socket.getFileDescriptorField(): java.io.FileDescriptor? {
    return try {
        val implField = java.net.Socket::class.java.getDeclaredField("impl")
        implField.isAccessible = true
        val impl = implField.get(this) ?: return null
        val fdField = generateSequence<Class<*>>(impl.javaClass) { it.superclass }
            .firstNotNullOfOrNull { cls ->
                runCatching { cls.getDeclaredField("fd") }.getOrNull()
            } ?: return null
        fdField.isAccessible = true
        fdField.get(impl) as? java.io.FileDescriptor
    } catch (_: Throwable) {
        null
    }
}
