package com.argsment.anywhere.vpn

import android.util.Log
import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.direct.DirectUdpRelay
import com.argsment.anywhere.vpn.protocol.mux.MuxNetwork
import com.argsment.anywhere.vpn.protocol.mux.MuxSession
import com.argsment.anywhere.vpn.protocol.mux.Xudp
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksClient
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksUdpRelay
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.util.concurrent.ScheduledExecutorService

/**
 * Represents a single UDP "flow" (identified by 5-tuple).
 * Routes UDP datagrams through either a VLESS proxy, mux session, or direct relay.
 *
 * All methods must be called on the lwIP executor thread.
 */
class LwipUdpFlow(
    val flowKey: String,
    val srcHost: String,
    val srcPort: Int,
    val dstHost: String,
    val dstPort: Int,
    val srcIpBytes: ByteArray,   // original source (becomes dst in response)
    val dstIpBytes: ByteArray,   // original destination (becomes src in response)
    val isIpv6: Boolean,
    val configuration: ProxyConfiguration,
    private val forceBypass: Boolean,
    private val lwipExecutor: ScheduledExecutorService
) {
    // Coroutine scope for protocol operations, dispatched on the lwIP executor
    private val scopeJob = SupervisorJob()
    private val scope = CoroutineScope(lwipExecutor.asCoroutineDispatcher() + scopeJob)

    var lastActivity: Double = System.nanoTime() / 1_000_000_000.0
        private set

    // Direct bypass path
    private var directRelay: DirectUdpRelay? = null

    // Non-mux path
    private var vlessConnection: VlessConnection? = null

    // Mux path
    private var muxSession: MuxSession? = null

    // Shadowsocks UDP relay
    private var ssUdpRelay: ShadowsocksUdpRelay? = null

    private var vlessConnecting = false
    private var pendingData = mutableListOf<ByteArray>()  // always raw payloads
    private var pendingBufferSize = 0
    var closed = false
        private set

    // -- Data Handling (called on lwIP thread) --

    fun handleReceivedData(data: ByteArray, payloadLength: Int) {
        if (closed) return
        lastActivity = System.nanoTime() / 1_000_000_000.0

        val payload = if (payloadLength < data.size) data.copyOf(payloadLength) else data

        // Buffer data while the outbound connection is being established
        if (vlessConnecting) {
            bufferPayload(payload)
            return
        }

        // Direct bypass path
        if (directRelay != null) {
            directRelay!!.send(payload)
            return
        }

        // Mux path: send raw payload (mux framing handled by MuxSession).
        // Use sendAsync to check closed synchronously on the lwipExecutor.
        if (muxSession != null) {
            muxSession!!.sendAsync(payload)
            return
        }

        // Shadowsocks UDP relay: raw payload, per-packet encryption handled by relay
        if (ssUdpRelay != null) {
            ssUdpRelay!!.send(payload)
            return
        }

        // Non-mux path: send length-framed payload through VLESS connection
        if (vlessConnection != null) {
            sendUdpThroughVless(payload)
            return
        }

        // No connection yet — buffer and start connecting
        bufferPayload(payload)
        connectVless()
    }

    private fun bufferPayload(payload: ByteArray) {
        // Drop datagram if buffer limit would be exceeded (DiscardOverflow)
        if (pendingBufferSize + payload.size > MAX_UDP_BUFFER_SIZE) return
        pendingData.add(payload)
        pendingBufferSize += payload.size
    }

    private fun sendUdpThroughVless(payload: ByteArray) {
        val connection = vlessConnection ?: return
        // Frame with 2-byte big-endian length prefix via JNI
        val framed = NativeBridge.nativeFrameUdpPayload(payload)
        scope.launch {
            try {
                connection.sendRaw(framed)
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                if (!closed) Log.e(TAG, "[UDP] VLESS send error for $flowKey: ${e.message}")
            }
        }
    }

    // -- Connection Setup --

    private fun connectVless() {
        if (vlessConnecting || vlessConnection != null || muxSession != null || directRelay != null || ssUdpRelay != null || closed) return

        if (forceBypass || LwipStack.instance?.shouldBypass(dstHost) == true) {
            connectDirectUdp()
            return
        }

        // Route Shadowsocks to its own UDP relay, even with a chain (matching iOS).
        // SS per-packet AEAD is designed for UDP datagrams, not TCP streams,
        // and the SS protocol has no UDP command byte for TCP tunneling.
        if (configuration.outboundProtocol == OutboundProtocol.SHADOWSOCKS) {
            connectShadowsocksUdp()
            return
        }

        val chain = configuration.chain
        if (!chain.isNullOrEmpty()) {
            connectUdpChain(chain)
            return
        }

        // Vision flow silently drops UDP/443 (QUIC) — matching VlessClient.connectWithCommand()
        val flow = configuration.flow
        val isVision = flow == "xtls-rprx-vision" || flow == "xtls-rprx-vision-udp443"
        val allowUdp443 = flow == "xtls-rprx-vision-udp443"
        if (dstPort == 443 && isVision && !allowUdp443) {
            closed = true
            LwipStack.instance?.udpFlows?.remove(flowKey)
            return
        }

        vlessConnecting = true

        // Check if we should use mux (only for default configuration)
        val stack = LwipStack.instance
        val isDefaultConfig = stack?.configuration?.id == configuration.id
        if (isDefaultConfig && stack?.muxManager != null) {
            val muxManager = stack.muxManager!!
            // Cone NAT: GlobalID = blake3_keyed(BaseKey, "udp:srcHost:srcPort")[0:8]
            // Uses keyed BLAKE3 with per-process BaseKey and 8-byte output,
            // matching Xray-core xudp.go and iOS XUDP.swift.
            val globalId = if (configuration.xudpEnabled) {
                Xudp.generateGlobalID("udp:$srcHost:$srcPort")
            } else null

            scope.launch {
                try {
                    val session = muxManager.dispatch(
                        network = MuxNetwork.UDP,
                        host = dstHost,
                        port = dstPort,
                        globalID = globalId
                    )

                    lwipExecutor.execute {
                        vlessConnecting = false
                        if (closed) {
                            session.close()
                            return@execute
                        }

                        // Guard against session being closed by closeAll() during dispatch
                        // (matching iOS post-dispatch session.closed check)
                        if (session.closed) {
                            releaseProtocol()
                            LwipStack.instance?.udpFlows?.remove(flowKey)
                            return@execute
                        }

                        muxSession = session

                        // Set up receive handler
                        session.dataHandler = { data ->
                            handleRemoteData(data)
                        }
                        session.closeHandler = {
                            lwipExecutor.execute {
                                close()
                                LwipStack.instance?.udpFlows?.remove(flowKey)
                            }
                        }

                        // Send buffered raw payloads synchronously on the lwipExecutor.
                        // Using sendAsync avoids the race where closeAll() could run
                        // between coroutine scheduling and execution.
                        val buffered = pendingData.toList()
                        pendingData.clear()
                        pendingBufferSize = 0
                        for (payload in buffered) {
                            session.sendAsync(payload)
                        }
                    }
                } catch (_: CancellationException) {
                } catch (e: Exception) {
                    lwipExecutor.execute {
                        vlessConnecting = false
                        if (closed) return@execute
                        Log.e(TAG, "[UDP] Mux dispatch failed: $flowKey: ${e.message}")
                        releaseProtocol()
                        LwipStack.instance?.udpFlows?.remove(flowKey)
                    }
                }
            }
        } else {
            connectVlessNonMux()
        }
    }

    private fun connectUdpChain(chain: List<ProxyConfiguration>) {
        if (closed) return
        vlessConnecting = true

        scope.launch {
            try {
                var previousConnection: VlessConnection? = null

                for (i in chain.indices) {
                    val hopConfig = chain[i]
                    val nextConfig = if (i + 1 < chain.size) chain[i + 1] else configuration
                    previousConnection = ProxyClientFactory.connect(
                        hopConfig,
                        nextConfig.serverAddress,
                        nextConfig.serverPort.toInt(),
                        tunnel = previousConnection
                    )
                }

                val connection = ProxyClientFactory.connectUDP(
                    configuration,
                    dstHost,
                    dstPort,
                    tunnel = previousConnection
                )

                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) {
                        connection.cancel()
                        return@execute
                    }

                    vlessConnection = connection

                    if (pendingData.isNotEmpty()) {
                        // Batch all pending payloads into a single sendRaw call (matching iOS)
                        var totalSize = 0
                        for (payload in pendingData) totalSize += 2 + payload.size
                        val batched = ByteArray(totalSize)
                        var offset = 0
                        for (payload in pendingData) {
                            batched[offset++] = (payload.size shr 8).toByte()
                            batched[offset++] = (payload.size and 0xFF).toByte()
                            System.arraycopy(payload, 0, batched, offset, payload.size)
                            offset += payload.size
                        }
                        pendingData.clear()
                        pendingBufferSize = 0

                        scope.launch {
                            try {
                                connection.sendRaw(batched)
                            } catch (_: CancellationException) {
                            } catch (e: Exception) {
                                if (!closed) Log.e(TAG, "[UDP] Chained initial send error for $flowKey: ${e.message}")
                            }
                        }
                    }

                    startVlessReceiving(connection)
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) return@execute
                    Log.e(TAG, "[UDP] Chain connect failed: $flowKey: ${e.message}")
                    releaseProtocol()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun connectVlessNonMux() {
        if (closed) return
        vlessConnecting = true

        scope.launch {
            try {
                val connection = ProxyClientFactory.connectUDP(configuration, dstHost, dstPort)

                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) {
                        connection.cancel()
                        return@execute
                    }

                    vlessConnection = connection

                    // Send buffered raw payloads batched into a single sendRaw (matching iOS)
                    if (pendingData.isNotEmpty()) {
                        var totalSize = 0
                        for (payload in pendingData) totalSize += 2 + payload.size
                        val batched = ByteArray(totalSize)
                        var offset = 0
                        for (payload in pendingData) {
                            batched[offset++] = (payload.size shr 8).toByte()
                            batched[offset++] = (payload.size and 0xFF).toByte()
                            System.arraycopy(payload, 0, batched, offset, payload.size)
                            offset += payload.size
                        }
                        pendingData.clear()
                        pendingBufferSize = 0

                        scope.launch {
                            try {
                                connection.sendRaw(batched)
                            } catch (_: CancellationException) {
                            } catch (e: Exception) {
                                if (!closed) Log.e(TAG, "[UDP] VLESS initial send error for $flowKey: ${e.message}")
                            }
                        }
                    }

                    // Start receiving VLESS responses
                    startVlessReceiving(connection)
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) return@execute
                    Log.e(TAG, "[UDP] connect failed: $flowKey: ${e.message}")
                    releaseProtocol()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun connectShadowsocksUdp() {
        if (closed) return
        vlessConnecting = true

        val ssClient = ShadowsocksClient(configuration)
        val relay = ssClient.createUdpRelay(dstHost, dstPort)
        ssUdpRelay = relay

        scope.launch {
            try {
                relay.connect(configuration.serverAddress, configuration.serverPort.toInt())

                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) {
                        relay.cancel()
                        return@execute
                    }

                    // Send buffered payloads
                    for (payload in pendingData) {
                        relay.send(payload)
                    }
                    pendingData.clear()
                    pendingBufferSize = 0

                    // Start receiving responses
                    scope.launch {
                        while (!closed) {
                            val data = relay.receive() ?: break
                            handleRemoteData(data)
                        }
                    }
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) return@execute
                    Log.e(TAG, "[UDP] SS connect failed: $flowKey: ${e.message}")
                    close()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun connectDirectUdp() {
        if (directRelay != null || closed) return
        vlessConnecting = true  // reuse flag to prevent re-entry

        val relay = DirectUdpRelay()
        directRelay = relay

        scope.launch {
            try {
                relay.connect(dstHost, dstPort)

                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) return@execute

                    // Send buffered payloads
                    for (payload in pendingData) {
                        relay.send(payload)
                    }
                    pendingData.clear()
                    pendingBufferSize = 0

                    // Start receiving responses
                    relay.startReceiving { data ->
                        handleRemoteData(data)
                    }
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (closed) return@execute
                    Log.e(TAG, "[UDP] Direct connect failed: $flowKey: ${e.message}")
                    close()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun startVlessReceiving(connection: VlessConnection) {
        scope.launch {
            connection.startReceiving(
                handler = { data ->
                    handleRemoteData(data)
                },
                errorHandler = { error ->
                    if (error != null) {
                        Log.e(TAG, "[UDP] VLESS recv error: $flowKey: ${error.message}")
                    }
                    lwipExecutor.execute {
                        close()
                        LwipStack.instance?.udpFlows?.remove(flowKey)
                    }
                }
            )
        }
    }

    /**
     * Handles data received from the remote side (VLESS/mux/direct).
     * Sends it back through lwIP with swapped src/dst addresses.
     */
    fun handleRemoteData(data: ByteArray) {
        lwipExecutor.execute {
            if (closed) return@execute
            lastActivity = System.nanoTime() / 1_000_000_000.0

            // Send UDP response via lwIP (swap src/dst for response)
            NativeBridge.nativeUdpSendto(
                dstIpBytes, dstPort,     // response source = original destination
                srcIpBytes, srcPort,     // response destination = original source
                isIpv6,
                data, data.size
            )
        }
    }

    // -- Close --

    fun close() {
        if (closed) return
        closed = true
        releaseProtocol()
    }

    private fun releaseProtocol() {
        scopeJob.cancel()

        val relay = directRelay
        val connection = vlessConnection
        val session = muxSession
        val ssRelay = ssUdpRelay
        directRelay = null
        vlessConnection = null
        muxSession = null
        ssUdpRelay = null
        vlessConnecting = false
        pendingData.clear()
        pendingBufferSize = 0
        relay?.cancel()
        connection?.cancel()
        session?.close()
        ssRelay?.cancel()
    }

    companion object {
        private const val TAG = "LWIP-UDP"
        /** Maximum buffer for queued datagrams (matches Xray-core DiscardOverflow 16KB). */
        private const val MAX_UDP_BUFFER_SIZE = 16 * 1024  // 16 KB
    }
}
