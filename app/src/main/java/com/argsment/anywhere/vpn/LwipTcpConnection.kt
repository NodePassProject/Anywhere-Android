package com.argsment.anywhere.vpn

import android.util.Log
import com.argsment.anywhere.data.model.VlessConfiguration
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
    val configuration: VlessConfiguration,
    forceBypass: Boolean,
    private val lwipExecutor: ScheduledExecutorService
) {
    // Coroutine scope for protocol operations, dispatched on the lwIP executor
    private val scopeJob = SupervisorJob()
    private val scope = CoroutineScope(lwipExecutor.asCoroutineDispatcher() + scopeJob)

    // Connection paths (mutually exclusive)
    private var vlessClient: VlessClient? = null
    private var vlessConnection: VlessConnection? = null
    private var directRelay: DirectTcpRelay? = null

    private var vlessConnecting = false
    private var directConnecting = false
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
                Log.e(TAG, "[TCP] Handshake timeout for $dstHost:$dstPort")
                abort()
            }
        }, HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)

        if (bypass) {
            connectDirect()
        } else {
            connectVless()
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

        if (directRelay != null) {
            val relay = directRelay!!
            val dataLen = data.size.coerceAtMost(65535)
            scope.launch {
                try {
                    relay.send(data)
                    lwipExecutor.execute {
                        if (!closed) NativeBridge.nativeTcpRecved(pcb, dataLen)
                    }
                } catch (_: CancellationException) {
                    // Scope cancelled during teardown — silently ignore
                } catch (e: Exception) {
                    if (!closed) Log.e(TAG, "[TCP] Direct send error for $dstHost:$dstPort: ${e.message}")
                    lwipExecutor.execute { abort() }
                }
            }
        } else if (vlessConnection != null) {
            val connection = vlessConnection!!
            val dataLen = data.size.coerceAtMost(65535)
            scope.launch {
                try {
                    connection.send(data)
                    lwipExecutor.execute {
                        if (!closed) NativeBridge.nativeTcpRecved(pcb, dataLen)
                    }
                } catch (_: CancellationException) {
                    // Scope cancelled during teardown — silently ignore
                } catch (e: Exception) {
                    if (!closed) Log.e(TAG, "[TCP] VLESS send error for $dstHost:$dstPort: ${e.message}")
                    lwipExecutor.execute { abort() }
                }
            }
        } else {
            pendingData.write(data)
            if (bypass) connectDirect() else connectVless()
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
                        Log.e(TAG, "[TCP] Direct connect failed: $dstHost:$dstPort: ${e.message}")
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
                            if (!closed) Log.e(TAG, "[TCP] Direct initial send error for $dstHost: ${e.message}")
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
                            if (!closed) Log.e(TAG, "[TCP] Direct pending send error for $dstHost: ${e.message}")
                            lwipExecutor.execute { abort() }
                        }
                    }
                }

                requestNextReceive()
            }
        }
    }

    // -- VLESS Connection --

    private fun connectVless() {
        if (vlessConnecting || vlessConnection != null || closed) return
        vlessConnecting = true

        val initialData = if (pendingData.size() > 0) pendingData.toByteArray() else null
        if (initialData != null) pendingData.reset()

        val client = VlessClient(configuration)
        vlessClient = client

        scope.launch {
            val connection: VlessConnection
            try {
                connection = client.connect(dstHost, dstPort, initialData)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        Log.e(TAG, "[TCP] connect failed: $dstHost:$dstPort: ${e.message}")
                        abort()
                    }
                }
                return@launch
            }

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
                            if (!closed) Log.e(TAG, "[TCP] VLESS pending send error for $dstHost: ${e.message}")
                            lwipExecutor.execute { abort() }
                        }
                    }
                }

                requestNextReceive()
            }
        }
    }

    // -- Data Writing to lwIP (downlink: remote → local app) --

    /**
     * Writes data from the remote side to the lwIP TCP send buffer.
     * Called from the receive loop when data arrives from VLESS/direct.
     */
    fun writeToLwip(data: ByteArray) {
        if (closed) return

        var offset = 0
        while (offset < data.size) {
            var sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
            if (sndbuf <= 0) {
                NativeBridge.nativeTcpOutput(pcb)
                sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
                if (sndbuf <= 0) {
                    val remaining = data.size - offset
                    if (overflowBuffer.size() + remaining > MAX_OVERFLOW_BUFFER_SIZE) {
                        Log.e(TAG, "[TCP] Overflow buffer limit exceeded for $dstHost:$dstPort")
                        abort()
                        return
                    }
                    overflowBuffer.write(data, offset, remaining)
                    offset = data.size
                    break
                }
            }
            val chunkSize = minOf(sndbuf, data.size - offset, 65535)
            val err = NativeBridge.nativeTcpWrite(pcb, data, offset, chunkSize)
            if (err != 0) {
                Log.e(TAG, "[TCP] tcp_write error: $err for $dstHost:$dstPort")
                abort()
                return
            }
            offset += chunkSize
        }

        if (closed) return
        NativeBridge.nativeTcpOutput(pcb)

        if (overflowBuffer.size() == 0) {
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
        var offset = 0
        while (offset < dataSize) {
            val sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
            if (sndbuf <= 0) break
            val chunkSize = minOf(sndbuf, dataSize - offset, 65535)
            val err = NativeBridge.nativeTcpWrite(pcb, data, offset, chunkSize)
            if (err != 0) {
                Log.e(TAG, "[TCP] tcp_write error: $err for $dstHost:$dstPort")
                abort()
                return
            }
            offset += chunkSize
        }

        if (closed) return

        if (offset > 0) {
            if (offset >= dataSize) {
                overflowBuffer.reset()
            } else {
                overflowBuffer.consume(offset)
            }
            NativeBridge.nativeTcpOutput(pcb)
        }

        if (overflowBuffer.size() == 0 && receivePaused) {
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
                    if (!closed) Log.e(TAG, "[TCP] Direct recv error: $dstHost:$dstPort: ${e.message}")
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
                if (!closed) Log.e(TAG, "[TCP] VLESS recv error: $dstHost:$dstPort: ${e.message}")
                lwipExecutor.execute { abort() }
            }
        }
    }

    // -- Close / Abort --

    /** Best-effort flush of overflow data into lwIP send buffer before close. */
    private fun flushOverflowToLwip() {
        if (overflowBuffer.size() == 0) return
        val data = overflowBuffer.backingArray()
        val dataSize = overflowBuffer.size()
        var offset = 0
        while (offset < dataSize) {
            val sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
            if (sndbuf <= 0) break
            val chunkSize = minOf(sndbuf, dataSize - offset, 65535)
            val err = NativeBridge.nativeTcpWrite(pcb, data, offset, chunkSize)
            if (err != 0) break
            offset += chunkSize
        }
        if (offset > 0) {
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
        val client = vlessClient
        directRelay = null
        vlessConnection = null
        vlessClient = null
        vlessConnecting = false
        directConnecting = false
        pendingData.reset()
        overflowBuffer.reset()
        receivePaused = false
        relay?.cancel()
        connection?.cancel()
        client?.cancel()
    }

    companion object {
        private const val TAG = "LWIP-TCP"
        private const val CONNECTION_IDLE_TIMEOUT_MS = 300_000L  // 300s (Xray-core connIdle)
        private const val DOWNLINK_ONLY_TIMEOUT_MS = 1_000L      // 1s (Xray-core downlinkOnly)
        private const val UPLINK_ONLY_TIMEOUT_MS = 1_000L        // 1s (Xray-core uplinkOnly)
        private const val HANDSHAKE_TIMEOUT_MS = 60_000L         // 60s (Xray-core Timeout.Handshake)
        private const val MAX_OVERFLOW_BUFFER_SIZE = 512 * 1024  // 512 KB
    }
}

/** Simple ByteArrayOutputStream replacement for buffer management. */
private class ByteArrayOutputStream {
    private var buf = ByteArray(256)
    private var count = 0

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
