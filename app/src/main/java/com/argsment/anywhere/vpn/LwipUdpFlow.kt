package com.argsment.anywhere.vpn

import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.DnsCache
import com.argsment.anywhere.vpn.util.TransportErrorLogger
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.direct.DirectUdpRelay
import com.argsment.anywhere.vpn.protocol.mux.MuxNetwork
import com.argsment.anywhere.vpn.protocol.mux.MuxSession
import com.argsment.anywhere.vpn.protocol.mux.Xudp
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksUdpSession
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    private var proxyConnection: ProxyConnection? = null

    // Mux path
    private var muxSession: MuxSession? = null

    // Shadowsocks: shared session per ProxyConfiguration owned by LwipStack;
    // we hold an opaque token for our flow's responses.
    private var ssSession: ShadowsocksUdpSession? = null
    private var ssSessionToken: Long? = null

    private var proxyConnecting = false
    private var pendingData = mutableListOf<ByteArray>()  // always raw payloads
    private var pendingBufferSize = 0
    /**
     * One-shot gate so a runaway send path doesn't flood the log with
     * "pending buffer overflow" lines — one warning per flow is enough
     * for the user to see that datagrams are being dropped.
     */
    private var didWarnPendingOverflow = false
    var closed = false
        private set

    /**
     * Logs a transport failure with the right severity. If the lwIP stack
     * recently noted a tunnel-level interruption (network path drop,
     * sleep, memory pressure, …) we downgrade the message — those
     * failures are expected and don't indicate a server problem.
     */
    private fun logTransportFailure(
        operation: String,
        error: Throwable,
        defaultLevel: LwipStack.LogLevel
    ) {
        TransportErrorLogger.log(
            operation = operation,
            endpoint = flowKey,
            error = error,
            logger = logger,
            prefix = "[UDP]",
            defaultLevel = defaultLevel
        )
    }

    fun handleReceivedData(data: ByteArray, payloadLength: Int) {
        if (closed) return
        lastActivity = System.nanoTime() / 1_000_000_000.0

        val payload = if (payloadLength < data.size) data.copyOf(payloadLength) else data

        // Buffer data while the outbound connection is being established
        if (proxyConnecting) {
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

        // Shadowsocks UDP relay: raw payload, per-packet encryption handled by
        // the shared session (one socket / sessionID per ProxyConfiguration).
        val session = ssSession
        val token = ssSessionToken
        if (session != null && token != null) {
            session.send(token, dstHost, dstPort, payload)
            return
        }

        // Non-mux path: hand the raw payload to the proxy connection. Each
        // protocol's UDP connection applies its own per-packet wire framing
        // (VLESS adds the 2-byte length prefix via VlessUdpConnection, Trojan
        // emits its addr+length+CRLF header, SOCKS5 adds its UDP header, …).
        if (proxyConnection != null) {
            sendUdpThroughProxy(payload)
            return
        }

        // No connection yet — buffer and start connecting
        bufferPayload(payload)
        connectProxy()
    }

    private fun bufferPayload(payload: ByteArray) {
        // Drop datagram if buffer limit would be exceeded (DiscardOverflow).
        // Warn once per flow so users can tell they're losing packets, but
        // avoid flooding the log.
        if (pendingBufferSize + payload.size > TunnelConstants.udpMaxBufferSize) {
            if (!didWarnPendingOverflow) {
                didWarnPendingOverflow = true
                logger.warning(
                    "[UDP] Pending buffer overflow for $flowKey " +
                    "(${pendingBufferSize}+${payload.size} > ${TunnelConstants.udpMaxBufferSize}), dropping datagrams"
                )
            }
            return
        }
        pendingData.add(payload)
        pendingBufferSize += payload.size
    }

    private fun sendUdpThroughProxy(payload: ByteArray) {
        val connection = proxyConnection ?: return
        scope.launch {
            try {
                connection.send(payload)
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                if (!closed) logger.debug("[UDP] proxy send error for $flowKey: ${e.message}")
            }
        }
    }

    private fun connectProxy() {
        if (proxyConnecting || proxyConnection != null || muxSession != null || directRelay != null || ssSession != null || closed) return

        if (forceBypass || LwipStack.instance?.shouldBypass(dstHost) == true) {
            connectDirectUdp()
            return
        }

        // Route Shadowsocks to its own UDP relay, even with a chain.
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

        // Vision flow silently drops UDP/443.
        val flow = configuration.flow
        val isVision = flow == "xtls-rprx-vision" || flow == "xtls-rprx-vision-udp443"
        val allowUdp443 = flow == "xtls-rprx-vision-udp443"
        if (dstPort == 443 && isVision && !allowUdp443) {
            closed = true
            LwipStack.instance?.udpFlows?.remove(flowKey)
            return
        }

        proxyConnecting = true

        // Check if we should use mux (only for default VLESS configuration)
        val stack = LwipStack.instance
        val isDefaultConfig = stack?.configuration?.id == configuration.id
        if (isDefaultConfig &&
            configuration.outboundProtocol == OutboundProtocol.VLESS &&
            stack?.muxManager != null
        ) {
            val muxManager = stack.muxManager!!
            // Cone NAT: GlobalID = blake3_keyed(BaseKey, "udp:srcHost:srcPort")[0:8]
            // Uses keyed BLAKE3 with per-process BaseKey and 8-byte output.
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
                        proxyConnecting = false
                        if (closed) {
                            session.close()
                            return@execute
                        }

                        // Set up handlers BEFORE checking closed state to
                        // prevent a race where close fires between the
                        // check and handler registration, which would leak
                        // the flow.
                        session.dataHandler = { data ->
                            handleRemoteData(data)
                        }
                        session.closeHandler = {
                            lwipExecutor.execute {
                                close()
                                LwipStack.instance?.udpFlows?.remove(flowKey)
                            }
                        }

                        // Guard against race: closeAll() may have already
                        // closed the session (via receive-loop error) before
                        // this handler ran.
                        if (session.closed) {
                            releaseProtocol()
                            LwipStack.instance?.udpFlows?.remove(flowKey)
                            return@execute
                        }

                        muxSession = session

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
                        proxyConnecting = false
                        if (closed) return@execute
                        logTransportFailure("Mux dispatch", e, LwipStack.LogLevel.ERROR)
                        releaseProtocol()
                        LwipStack.instance?.udpFlows?.remove(flowKey)
                    }
                }
            }
        } else {
            connectProxyNonMux()
        }
    }

    private fun connectUdpChain(chain: List<ProxyConfiguration>) {
        if (closed) return
        proxyConnecting = true

        scope.launch {
            try {
                var previousConnection: ProxyConnection? = null

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
                    proxyConnecting = false
                    if (closed) {
                        connection.cancel()
                        return@execute
                    }

                    proxyConnection = connection

                    if (pendingData.isNotEmpty()) {
                        // Drain buffered payloads via per-packet `send` calls so
                        // each protocol's UDP connection applies its own wire framing.
                        val buffered = pendingData.toList()
                        pendingData.clear()
                        pendingBufferSize = 0

                        scope.launch {
                            for (payload in buffered) {
                                try {
                                    connection.send(payload)
                                } catch (_: CancellationException) {
                                    return@launch
                                } catch (e: Exception) {
                                    if (!closed) logger.debug("[UDP] Chained initial send error for $flowKey: ${e.message}")
                                }
                            }
                        }
                    }

                    startProxyReceiving(connection)
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                lwipExecutor.execute {
                    proxyConnecting = false
                    if (closed) return@execute
                    if (e !is ProxyError.Dropped) {
                        logTransportFailure("Connect", e, LwipStack.LogLevel.ERROR)
                    }
                    releaseProtocol()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun connectProxyNonMux() {
        if (closed) return
        proxyConnecting = true

        scope.launch {
            try {
                val connection = ProxyClientFactory.connectUDP(configuration, dstHost, dstPort)

                lwipExecutor.execute {
                    proxyConnecting = false
                    if (closed) {
                        connection.cancel()
                        return@execute
                    }

                    proxyConnection = connection

                    // Drain buffered payloads via per-packet `send` calls so each
                    // protocol's UDP connection applies its own wire framing. A bulk
                    // sendRaw with pre-inlined VLESS length prefixes would break
                    // Trojan, whose UDP framing is not length-prefixed.
                    if (pendingData.isNotEmpty()) {
                        val buffered = pendingData.toList()
                        pendingData.clear()
                        pendingBufferSize = 0

                        scope.launch {
                            for (payload in buffered) {
                                try {
                                    connection.send(payload)
                                } catch (_: CancellationException) {
                                    return@launch
                                } catch (e: Exception) {
                                    if (!closed) logger.debug("[UDP] initial send error for $flowKey: ${e.message}")
                                }
                            }
                        }
                    }

                    // Start receiving proxy responses
                    startProxyReceiving(connection)
                }
            } catch (_: CancellationException) {
            } catch (e: Exception) {
                lwipExecutor.execute {
                    proxyConnecting = false
                    if (closed) return@execute
                    if (e !is ProxyError.Dropped) {
                        logTransportFailure("Connect", e, LwipStack.LogLevel.ERROR)
                    }
                    releaseProtocol()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun connectShadowsocksUdp() {
        if (closed) return

        // The shared per-config session connects lazily on its first send;
        // there's no async TCP/TLS handshake to wait for, so flows bind
        // synchronously on the lwipExecutor and start sending immediately.
        val stack = LwipStack.instance
        if (stack == null) {
            close()
            return
        }
        val session = stack.shadowsocksUDPSession(configuration)
        if (session == null) {
            logTransportFailure(
                "SS UDP session",
                IllegalStateException("Shadowsocks credentials missing or malformed"),
                LwipStack.LogLevel.ERROR
            )
            close()
            stack.udpFlows.remove(flowKey)
            return
        }

        // Seed response-address hints with whatever's already in the DNS
        // cache. Fresh resolutions aren't forced here because the cache
        // lookup is synchronous and lwipExecutor is performance-critical;
        // the async prewarm below handles cache misses.
        val cachedHints = DnsCache.cachedIPs(dstHost) ?: emptyList()

        val token = session.register(
            dstHost = dstHost,
            dstPort = dstPort,
            responseHostHints = cachedHints,
            handler = { data -> handleRemoteData(data) },
            errorHandler = { error ->
                lwipExecutor.execute {
                    if (closed) return@execute
                    logTransportFailure("SS UDP session", error, LwipStack.LogLevel.WARNING)
                    close()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        )
        ssSession = session
        ssSessionToken = token

        // Drain anything buffered while we waited to bind a session.
        if (pendingData.isNotEmpty()) {
            val buffered = pendingData.toList()
            pendingData.clear()
            pendingBufferSize = 0
            for (payload in buffered) {
                session.send(token, dstHost, dstPort, payload)
            }
        }

        // If the destination is a domain that's not yet in the DNS cache,
        // kick off an async resolve so subsequent replies can route by
        // exact IP match instead of relying on the port-only fallback
        // (which misroutes when multiple flows share a destination port —
        // e.g. concurrent QUIC connections on 443). For IP literals
        // DnsCache short-circuits and addResponseHints becomes a no-op
        // (dstHost is already pinned).
        if (cachedHints.isEmpty() && !DnsCache.isIpAddress(dstHost)) {
            scope.launch {
                val ips = try {
                    withContext(Dispatchers.IO) { DnsCache.resolveAll(dstHost) }
                } catch (_: CancellationException) {
                    return@launch
                } catch (_: Exception) {
                    return@launch
                }
                if (ips.isEmpty()) return@launch
                // Resumed on lwipExecutor (scope dispatcher) after the IO hop.
                // Re-check our binding to the same session+token in case the
                // flow was torn down while we were resolving.
                if (closed) return@launch
                if (ssSession !== session || ssSessionToken != token) return@launch
                session.addResponseHints(token, ips)
            }
        }
    }

    private fun connectDirectUdp() {
        if (directRelay != null || closed) return
        proxyConnecting = true  // reuse flag to prevent re-entry

        val relay = DirectUdpRelay()
        directRelay = relay

        scope.launch {
            try {
                relay.connect(dstHost, dstPort)

                lwipExecutor.execute {
                    proxyConnecting = false
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
                    proxyConnecting = false
                    if (closed) return@execute
                    logTransportFailure("Connect", e, LwipStack.LogLevel.ERROR)
                    close()
                    LwipStack.instance?.udpFlows?.remove(flowKey)
                }
            }
        }
    }

    private fun startProxyReceiving(connection: ProxyConnection) {
        scope.launch {
            connection.startReceiving(
                handler = { data ->
                    handleRemoteData(data)
                },
                errorHandler = { error ->
                    if (error != null) {
                        logger.debug("[UDP] VLESS recv error: $flowKey: ${error.message}")
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

            NativeBridge.nativeUdpSendto(
                dstIpBytes, dstPort,     // response source = original destination
                srcIpBytes, srcPort,     // response destination = original source
                isIpv6,
                data, data.size
            )
        }
    }

    fun close() {
        if (closed) return
        closed = true
        releaseProtocol()
    }

    private fun releaseProtocol() {
        scopeJob.cancel()

        val relay = directRelay
        val connection = proxyConnection
        val session = muxSession
        val ssSess = ssSession
        val ssTok = ssSessionToken
        directRelay = null
        proxyConnection = null
        muxSession = null
        ssSession = null
        ssSessionToken = null
        proxyConnecting = false
        pendingData.clear()
        pendingBufferSize = 0
        didWarnPendingOverflow = false
        relay?.cancel()
        connection?.cancel()
        session?.close()
        // Unregister our flow from the shared SS UDP session — the session
        // itself is owned by LwipStack and stays alive for other flows.
        if (ssSess != null && ssTok != null) {
            ssSess.unregister(ssTok)
        }
    }

    companion object {
        private val logger = AnywhereLogger("LWIP-UDP")
    }
}
