package com.argsment.anywhere.vpn

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.direct.DirectTcpRelay
import com.argsment.anywhere.vpn.protocol.vless.VlessClient
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Represents a single TCP connection through the VPN.
 *
 * Bridges between the lwIP PCB (protocol control block) on the local side
 * and either a VLESS proxy connection or a direct TCP relay on the remote side.
 *
 * All lwIP calls must happen on the lwIP executor thread.
 * Protocol connect/send/receive use coroutines dispatched on the lwIP executor.
 */
class LwipTcpConnection(
    val connId: Long,
    val pcb: Long,
    val dstHost: String,
    val dstPort: Int,
    val configuration: ProxyConfiguration,
    forceBypass: Boolean,
    private val lwipExecutor: ScheduledExecutorService
) {
    // Coroutine scope for protocol operations, dispatched on the lwIP executor
    private val scopeJob = SupervisorJob()
    private val scope = CoroutineScope(lwipExecutor.asCoroutineDispatcher() + scopeJob)

    // Connection paths (mutually exclusive)
    private var vlessConnection: VlessConnection? = null
    private var directRelay: DirectTcpRelay? = null

    private var vlessConnecting = false
    private var directConnecting = false

    // Upload coalescing: accumulates multiple TCP segments into a single batch
    // before sending to the proxy protocol, reducing per-segment encryption overhead.
    private var coalesceBuffer: ByteArrayOutputStream? = null
    private var coalesceScheduled = false
    private var coalesceFlushInFlight = false

    private val bypass: Boolean = forceBypass ||
        (LwipStack.instance?.shouldBypass(dstHost) == true)
    private var pendingData = ByteArrayOutputStream()
    var closed = false
        private set

    // -- Backpressure State --

    /** Data that couldn't fit in lwIP's TCP send buffer. */
    private var overflowBuffer = ByteArrayOutputStream()

    /** Whether the receive loop is paused due to a full lwIP send buffer. */
    private var receivePaused = false

    // -- Activity Timeout (matches Xray-core policy defaults) --

    private var activityTimer: ActivityTimer? = null
    private var handshakeTimer: ScheduledFuture<*>? = null
    private var uplinkDone = false
    private var downlinkDone = false

    init {
        // Start handshake timeout (60s)
        handshakeTimer = lwipExecutor.schedule({
            if (!closed && (vlessConnecting || directConnecting)) {
                logger.error("[TCP] Handshake timeout for $dstHost:$dstPort")
                abort()
            }
        }, HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)

        if (bypass) {
            connectDirect()
        } else {
            connectProxy()
        }
    }

    // -- lwIP Callbacks (called on lwIP thread) --

    /** Handles data received from the local app via lwIP. */
    fun handleReceivedData(data: ByteArray) {
        if (closed) return
        activityTimer?.update()

        // Buffer data while outbound connection is being established
        if (vlessConnecting || directConnecting) {
            pendingData.write(data)
            return
        }

        if (directRelay != null || vlessConnection != null) {
            // Coalesce segments: accumulate data and schedule a batched send
            // to reduce per-segment encryption overhead.
            // When flush is in-flight or buffer would exceed max, send directly per-segment.
            if (coalesceFlushInFlight ||
                (coalesceBuffer != null && coalesceBuffer!!.size() + data.size > MAX_COALESCE_SIZE)) {
                sendSegmentDirect(data)
            } else {
                if (coalesceBuffer == null) coalesceBuffer = ByteArrayOutputStream()
                coalesceBuffer!!.write(data)

                if (!coalesceScheduled) {
                    coalesceScheduled = true
                    lwipExecutor.execute { flushCoalesceBuffer() }
                }
            }
        } else {
            pendingData.write(data)
            if (bypass) connectDirect() else connectProxy()
        }
    }

    /**
     * Called when the local app acknowledges receipt of data sent via lwIP.
     * Drains the overflow buffer into the now-available send buffer space.
     */
    fun handleSent(len: Int) {
        if (closed) return
        drainOverflowBuffer()
    }

    /** Called when the local app closes its write side (TCP FIN from app). */
    fun handleRemoteClose() {
        if (closed) return
        uplinkDone = true
        if (downlinkDone) {
            close()
        } else {
            activityTimer?.setTimeout(DOWNLINK_ONLY_TIMEOUT_MS)
        }
    }

    /** Called when lwIP reports an error (PCB is already freed). */
    fun handleError(err: Int) {
        if (closed) return
        closed = true
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    // -- Direct Connection (bypass) --

    private fun connectDirect() {
        if (directConnecting || directRelay != null || closed) return
        directConnecting = true

        val initialData = if (pendingData.size() > 0) pendingData.toByteArray() else null
        if (initialData != null) pendingData.reset()

        val relay = DirectTcpRelay()
        directRelay = relay

        scope.launch {
            try {
                relay.connect(dstHost, dstPort)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    directConnecting = false
                    if (!closed) {
                        logger.error("[TCP] connect failed: $dstHost:$dstPort: ${e.message}")
                        abort()
                    }
                }
                return@launch
            }

            lwipExecutor.execute {
                directConnecting = false
                if (closed) return@execute

                handshakeTimer?.cancel(false)
                handshakeTimer = null
                activityTimer = ActivityTimer(lwipExecutor, CONNECTION_IDLE_TIMEOUT_MS) {
                    if (!closed) close()
                }

                // Flush initial data
                if (initialData != null) {
                    val dataLen = initialData.size.coerceAtMost(65535)
                    scope.launch {
                        try {
                            relay.send(initialData)
                            lwipExecutor.execute {
                                if (!closed) NativeBridge.nativeTcpRecved(pcb, dataLen)
                            }
                        } catch (_: CancellationException) {
                        } catch (e: Exception) {
                            if (!closed) logger.debug("[TCP] Direct initial send error for $dstHost: ${e.message}")
                            lwipExecutor.execute { abort() }
                        }
                    }
                }

                // Flush data that arrived during connect
                if (pendingData.size() > 0) {
                    val dataToSend = pendingData.toByteArray()
                    val dataLen = dataToSend.size.coerceAtMost(65535)
                    pendingData.reset()
                    scope.launch {
                        try {
                            relay.send(dataToSend)
                            lwipExecutor.execute {
                                if (!closed) NativeBridge.nativeTcpRecved(pcb, dataLen)
                            }
                        } catch (_: CancellationException) {
                        } catch (e: Exception) {
                            if (!closed) logger.debug("[TCP] Direct pending send error for $dstHost: ${e.message}")
                            lwipExecutor.execute { abort() }
                        }
                    }
                }

                requestNextReceive()
            }
        }
    }

    // -- Protocol Connection --

    /**
     * Connects to the proxy using the appropriate protocol (VLESS, Shadowsocks, NaiveProxy).
     * Uses [ProxyClientFactory] for protocol selection.
     */
    private fun connectProxy() {
        if (vlessConnecting || vlessConnection != null || closed) return
        vlessConnecting = true

        val initialData = if (pendingData.size() > 0) pendingData.toByteArray() else null
        if (initialData != null) pendingData.reset()

        // If config has a chain, build chained connections first
        val chain = configuration.chain
        if (!chain.isNullOrEmpty()) {
            connectChain(chain, initialData)
            return
        }

        scope.launch {
            try {
                val connection = ProxyClientFactory.connect(
                    configuration, dstHost, dstPort, initialData
                )
                onProxyConnected(connection)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        logger.error("[TCP] connect failed: $dstHost:$dstPort: ${e.message}")
                        abort()
                    }
                }
            }
        }
    }

    /**
     * Handles post-connection setup common to all protocol paths.
     * Sets up activity timer, flushes pending data, and starts the receive loop.
     */
    private fun onProxyConnected(connection: VlessConnection) {
        lwipExecutor.execute {
            vlessConnecting = false
            if (closed) {
                connection.cancel()
                return@execute
            }

            vlessConnection = connection
            handshakeTimer?.cancel(false)
            handshakeTimer = null
            activityTimer = ActivityTimer(lwipExecutor, CONNECTION_IDLE_TIMEOUT_MS) {
                if (!closed) close()
            }

            // Flush data that arrived during connect
            if (pendingData.size() > 0) {
                val dataToSend = pendingData.toByteArray()
                val dataLen = dataToSend.size.coerceAtMost(65535)
                pendingData.reset()
                scope.launch {
                    try {
                        connection.send(dataToSend)
                        lwipExecutor.execute {
                            if (!closed) NativeBridge.nativeTcpRecved(pcb, dataLen)
                        }
                    } catch (_: CancellationException) {
                    } catch (e: Exception) {
                        if (!closed) logger.debug("[TCP] pending send error for $dstHost: ${e.message}")
                        lwipExecutor.execute { abort() }
                    }
                }
            }

            requestNextReceive()
        }
    }

    // -- Chain Connection --

    /**
     * Builds a chain of proxy connections: entry → intermediate → ... → exit → target.
     *
     * Each intermediate hop creates a VLESS tunnel to the next proxy's server.
     * The final hop uses [ProxyClientFactory] for protocol selection, allowing
     * the exit proxy to use any supported protocol (VLESS, Shadowsocks, NaiveProxy).
     */
    private fun connectChain(
        chain: List<ProxyConfiguration>,
        initialData: ByteArray?
    ) {
        scope.launch {
            try {
                var previousConnection: VlessConnection? = null

                for (i in chain.indices) {
                    val hopConfig = chain[i]
                    val nextConfig = if (i + 1 < chain.size) chain[i + 1] else configuration
                    val conn = ProxyClientFactory.connect(
                        hopConfig,
                        nextConfig.serverAddress,
                        nextConfig.serverPort.toInt(),
                        tunnel = previousConnection
                    )
                    previousConnection = conn
                }

                // Final hop: use factory for protocol selection, tunneled through the chain
                val connection = ProxyClientFactory.connect(
                    configuration, dstHost, dstPort, initialData, tunnel = previousConnection
                )
                onProxyConnected(connection)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        logger.error("[TCP] connect failed: $dstHost:$dstPort: ${e.message}")
                        abort()
                    }
                }
            }
        }
    }

    // -- Upload Coalescing --

    /**
     * Sends a single segment directly (bypassing coalesce buffer).
     * Used when the coalesce buffer flush is in-flight or would exceed the size cap.
     */
    private fun sendSegmentDirect(data: ByteArray) {
        val dataLen = data.size.coerceAtMost(65535)
        val relay = directRelay
        val connection = vlessConnection

        scope.launch {
            try {
                if (relay != null) {
                    relay.send(data)
                } else {
                    connection?.send(data) ?: return@launch
                }
                lwipExecutor.execute {
                    if (!closed) NativeBridge.nativeTcpRecved(pcb, dataLen)
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                if (!closed) logger.debug("[TCP] segment send error for $dstHost:$dstPort: ${e.message}")
                lwipExecutor.execute { abort() }
            }
        }
    }

    /**
     * Flushes the coalesce buffer, sending all accumulated segments as a single batch.
     * Called on the lwIP executor thread after the current processing cycle completes.
     */
    private fun flushCoalesceBuffer() {
        val buf = coalesceBuffer
        coalesceBuffer = null
        coalesceScheduled = false

        if (closed || buf == null || buf.size() == 0) return

        val relay = directRelay
        val connection = vlessConnection
        if (relay == null && connection == null) return

        val dataToSend = buf.toByteArray()
        coalesceFlushInFlight = true
        scope.launch {
            try {
                if (relay != null) {
                    relay.send(dataToSend)
                } else {
                    connection!!.send(dataToSend)
                }
                lwipExecutor.execute {
                    coalesceFlushInFlight = false
                    if (!closed) {
                        // Acknowledge all coalesced bytes to advance the TCP receive window
                        var remaining = dataToSend.size
                        while (remaining > 0) {
                            val ack = remaining.coerceAtMost(65535)
                            NativeBridge.nativeTcpRecved(pcb, ack)
                            remaining -= ack
                        }
                    }
                }
            } catch (_: CancellationException) {
                lwipExecutor.execute { coalesceFlushInFlight = false }
            } catch (e: Exception) {
                if (!closed) logger.debug("[TCP] send error for $dstHost:$dstPort: ${e.message}")
                lwipExecutor.execute {
                    coalesceFlushInFlight = false
                    abort()
                }
            }
        }
    }

    // -- Data Writing to lwIP (downlink: remote → local app) --

    /**
     * Feeds as many bytes as possible from [data] (starting at [dataOffset]) into
     * lwIP's TCP send buffer. Returns bytes written, or -1 on fatal (non-transient)
     * tcp_write error. ERR_MEM is treated as transient (breaks out of the loop).
     *
     * When [retryOnEmpty] is true, calls tcp_output once to flush if the send
     * buffer is initially full, then retries — used by the initial write path.
     */
    private fun feedLwip(data: ByteArray, dataOffset: Int, count: Int, retryOnEmpty: Boolean = false): Int {
        var offset = 0
        while (offset < count) {
            var sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
            if (sndbuf <= 0) {
                if (retryOnEmpty) {
                    NativeBridge.nativeTcpOutput(pcb)
                    sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
                }
                if (sndbuf <= 0) break
            }
            val chunkSize = minOf(sndbuf, count - offset, MAX_LWIP_WRITE_SIZE)
            val err = NativeBridge.nativeTcpWrite(pcb, data, dataOffset + offset, chunkSize)
            if (err != 0) {
                if (err == -1) break  // ERR_MEM: transient — remaining data goes to overflow
                return -1             // fatal error
            }
            offset += chunkSize
        }
        return offset
    }

    /**
     * Writes data from the remote side to the lwIP TCP send buffer.
     * Called from the receive loop when data arrives from VLESS/direct.
     *
     * If overflow buffer already has data, appends to preserve ordering.
     * ERR_MEM from tcp_write is treated as transient (data goes to overflow),
     * matching iOS behavior which avoids unnecessary RSTs under heavy load.
     */
    fun writeToLwip(data: ByteArray) {
        if (closed) return

        // If overflow already queued, append to preserve ordering (matching iOS).
        if (overflowBuffer.size() > 0) {
            overflowBuffer.write(data)
            drainOverflowBuffer()
            if (closed) return
            if (overflowBuffer.size() < MAX_OVERFLOW_BUFFER_SIZE) {
                requestNextReceive()
            } else {
                receivePaused = true
            }
            return
        }

        val written = feedLwip(data, 0, data.size, retryOnEmpty = true)
        if (written == -1) {
            logger.error("[TCP] Write failed: $dstHost:$dstPort")
            abort()
            return
        }
        if (written < data.size) {
            overflowBuffer.write(data, written, data.size - written)
        }

        if (closed) return
        NativeBridge.nativeTcpOutput(pcb)

        // Backpressure gate: if overflow has accumulated beyond the soft limit,
        // pause receives so the remote side stops sending.
        if (overflowBuffer.size() < MAX_OVERFLOW_BUFFER_SIZE) {
            requestNextReceive()
        } else {
            receivePaused = true
        }
    }

    /** Drains the overflow buffer into lwIP's TCP send buffer. */
    private fun drainOverflowBuffer() {
        if (closed || overflowBuffer.size() == 0) return

        val data = overflowBuffer.backingArray()
        val dataSize = overflowBuffer.size()
        val written = feedLwip(data, 0, dataSize)
        if (written == -1) {
            logger.error("[TCP] Write failed: $dstHost:$dstPort")
            abort()
            return
        }

        if (closed) return

        if (written > 0) {
            if (written >= dataSize) {
                overflowBuffer.reset()
            } else {
                overflowBuffer.consume(written)
            }
            NativeBridge.nativeTcpOutput(pcb)
        } else if (overflowBuffer.size() > 0) {
            // Nothing drained (ERR_MEM with empty send buffer) — no handleSent will
            // fire for this connection, so schedule a delayed retry (matching iOS).
            lwipExecutor.schedule({ drainOverflowBuffer() }, DRAIN_RETRY_DELAY_MS, TimeUnit.MILLISECONDS)
            return
        }

        if (receivePaused && overflowBuffer.size() < MAX_OVERFLOW_BUFFER_SIZE) {
            receivePaused = false
            requestNextReceive()
        }
    }

    /** Requests the next chunk of data from the protocol connection. */
    private fun requestNextReceive() {
        if (closed || receivePaused) return

        if (directRelay != null) {
            val relay = directRelay!!
            scope.launch {
                try {
                    val data = relay.receive()
                    lwipExecutor.execute {
                        if (closed) return@execute
                        if (data == null || data.isEmpty()) {
                            // EOF
                            downlinkDone = true
                            if (uplinkDone) {
                                close()
                            } else {
                                activityTimer?.setTimeout(UPLINK_ONLY_TIMEOUT_MS)
                            }
                        } else {
                            activityTimer?.update()
                            writeToLwip(data)
                        }
                    }
                } catch (_: CancellationException) {
                    // Scope cancelled during teardown — silently ignore
                } catch (e: Exception) {
                    if (!closed) logger.debug("[TCP] Direct recv error: $dstHost:$dstPort: ${e.message}")
                    lwipExecutor.execute { abort() }
                }
            }
            return
        }

        val connection = vlessConnection ?: return
        scope.launch {
            try {
                val data = connection.receive()
                lwipExecutor.execute {
                    if (closed) return@execute
                    if (data == null || data.isEmpty()) {
                        // EOF
                        downlinkDone = true
                        if (uplinkDone) {
                            close()
                        } else {
                            activityTimer?.setTimeout(UPLINK_ONLY_TIMEOUT_MS)
                        }
                    } else {
                        activityTimer?.update()
                        writeToLwip(data)
                    }
                }
            } catch (_: CancellationException) {
                // Scope cancelled during teardown — silently ignore
            } catch (e: Exception) {
                if (!closed) logger.debug("[TCP] VLESS recv error: $dstHost:$dstPort: ${e.message}")
                lwipExecutor.execute { abort() }
            }
        }
    }

    // -- Close / Abort --

    /** Best-effort flush of overflow data into lwIP send buffer before close. */
    private fun flushOverflowToLwip() {
        if (overflowBuffer.size() == 0) return
        val written = feedLwip(overflowBuffer.backingArray(), 0, overflowBuffer.size())
        if (written > 0) {
            NativeBridge.nativeTcpOutput(pcb)
        }
    }

    fun close() {
        if (closed) return
        closed = true
        flushOverflowToLwip()
        NativeBridge.nativeTcpClose(pcb)
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    fun abort() {
        if (closed) return
        closed = true
        NativeBridge.nativeTcpAbort(pcb)
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    private fun releaseProtocol() {
        // Cancel all in-flight coroutines first to prevent them from using freed resources
        scopeJob.cancel()

        handshakeTimer?.cancel(false)
        handshakeTimer = null
        activityTimer?.cancel()
        activityTimer = null
        val relay = directRelay
        val connection = vlessConnection
        directRelay = null
        vlessConnection = null
        vlessConnecting = false
        directConnecting = false
        pendingData.reset()
        overflowBuffer.reset()
        coalesceBuffer = null
        coalesceScheduled = false
        receivePaused = false
        relay?.cancel()
        connection?.cancel()
    }

    companion object {
        private val logger = AnywhereLogger("LWIP-TCP")
        private const val CONNECTION_IDLE_TIMEOUT_MS = 300_000L  // 300s (Xray-core connIdle)
        private const val DOWNLINK_ONLY_TIMEOUT_MS = 1_000L      // 1s (Xray-core downlinkOnly)
        private const val UPLINK_ONLY_TIMEOUT_MS = 1_000L        // 1s (Xray-core uplinkOnly)
        private const val HANDSHAKE_TIMEOUT_MS = 60_000L         // 60s (Xray-core Timeout.Handshake)
        private const val MAX_OVERFLOW_BUFFER_SIZE = 2 * 1024 * 1024  // 2 MB (soft limit, increased from iOS's 512 KB)
        private const val MAX_LWIP_WRITE_SIZE = 16 * 1024        // 16 KB per tcp_write (matching iOS, limits pbuf/segment pressure)
        private const val MAX_COALESCE_SIZE = 65535              // UInt16 max (matching iOS, protocol framing limit)
        private const val DRAIN_RETRY_DELAY_MS = 100L            // 100ms drain retry (matching iOS)
    }
}

/** Simple ByteArrayOutputStream replacement for buffer management. */
private class ByteArrayOutputStream {
    private var buf = ByteArray(256)
    private var count = 0
    companion object {
        private const val SHRINK_THRESHOLD = 8192
    }

    fun write(data: ByteArray) {
        write(data, 0, data.size)
    }

    fun write(data: ByteArray, off: Int, len: Int) {
        ensureCapacity(count + len)
        System.arraycopy(data, off, buf, count, len)
        count += len
    }

    fun toByteArray(): ByteArray = buf.copyOf(count)

    /** Direct access to backing array (valid up to [size] bytes). Avoids copy. */
    fun backingArray(): ByteArray = buf

    fun size(): Int = count

    fun reset() {
        count = 0
        // Shrink backing array if it grew well beyond the initial size,
        // preventing long-lived connections from retaining peak memory.
        if (buf.size > SHRINK_THRESHOLD) {
            buf = ByteArray(256)
        }
    }

    /** Removes the first [n] bytes, shifting remaining data to the front. */
    fun consume(n: Int) {
        if (n >= count) {
            count = 0
        } else {
            System.arraycopy(buf, n, buf, 0, count - n)
            count -= n
        }
    }

    private fun ensureCapacity(minCapacity: Int) {
        if (minCapacity > buf.size) {
            val newSize = maxOf(buf.size * 2, minCapacity)
            buf = buf.copyOf(newSize)
        }
    }
}
