package com.argsment.anywhere.vpn

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.TlsClientHelloSniffer
import com.argsment.anywhere.vpn.util.TransportErrorLogger
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.direct.DirectTcpRelay
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
    dstHost: String,
    val dstPort: Int,
    configuration: ProxyConfiguration,
    forceBypass: Boolean,
    sniffSNI: Boolean,
    private val lwipExecutor: ScheduledExecutorService
) {
    /**
     * Destination the proxy will be asked to connect to. Initialized from
     * the tcp_accept signal and may be replaced with the SNI hostname
     * once sniffing resolves.
     */
    var dstHost: String = dstHost
        private set

    /**
     * Routing configuration for this connection. Mutable because a
     * successful SNI sniff can re-match a domain rule that points to a
     * different proxy.
     */
    var configuration: ProxyConfiguration = configuration
        private set

    // Coroutine scope for protocol operations, dispatched on the lwIP executor
    private val scopeJob = SupervisorJob()
    private val scope = CoroutineScope(lwipExecutor.asCoroutineDispatcher() + scopeJob)

    // Connection paths (mutually exclusive)
    private var vlessConnection: ProxyConnection? = null
    private var directRelay: DirectTcpRelay? = null

    private var vlessConnecting = false
    private var directConnecting = false

    // Upload coalescing: accumulates multiple TCP segments into a single batch
    // before sending to the proxy protocol, reducing per-segment encryption overhead.
    private var coalesceBuffer: ByteArrayOutputStream? = null
    private var coalesceScheduled = false
    private var coalesceFlushInFlight = false

    /**
     * Whether the connection should bypass the configured proxy and connect
     * directly. May flip after SNI sniff resolves a routing rule.
     */
    private var bypass: Boolean = forceBypass ||
        (LwipStack.instance?.shouldBypass(dstHost) == true)

    private var pendingData = ByteArrayOutputStream()
    var closed = false
        private set

    // When present, the connection is in the "sniff" phase: inbound bytes
    // are buffered (in `pendingData`) and fed to the sniffer before the
    // proxy is dialed. The first terminal state (Found / NotTls /
    // Unavailable) commits the route and kicks off the proxy connect.
    // Cleared to null once the route is committed.
    private var sniffer: TlsClientHelloSniffer? =
        if (sniffSNI) TlsClientHelloSniffer() else null

    /**
     * Fires if the sniff phase doesn't resolve within [TunnelConstants.sniffDeadlineMs]
     * — commits the IP-based route so server-speaks-first protocols
     * (SSH, SMTP, FTP) don't stall waiting for a ClientHello.
     */
    private var sniffDeadline: ScheduledFuture<*>? = null

    /**
     * Downlink bytes received from the proxy that haven't been pushed into
     * lwIP's TCP send buffer yet. Holds ALL outstanding downlink bytes —
     * a concurrently prefetched receive appends here without racing the
     * ongoing drain.
     */
    private var pendingWrite = ByteArrayOutputStream()

    /**
     * True while a proxy receive is in flight. Guards against issuing a
     * parallel receive on top of an existing one.
     */
    private var receiveInFlight = false

    private var activityTimer: ActivityTimer? = null
    private var handshakeTimer: ScheduledFuture<*>? = null
    private var uplinkDone = false
    private var downlinkDone = false

    init {
        // Handshake timeout (60s) — covers both the SNI-sniff wait and the
        // proxy dial, so a stalled client can't hold a connection open
        // indefinitely before we ever call connect.
        handshakeTimer = lwipExecutor.schedule({
            if (!closed && isEstablishing) {
                val phase = if (sniffer != null) "TLS ClientHello sniff" else "proxy dial"
                logger.error("[TCP] Handshake timeout during $phase: $dstHost:$dstPort")
                abort()
            }
        }, TunnelConstants.handshakeTimeoutMs, TimeUnit.MILLISECONDS)

        // If we're sniffing, wait for the first ClientHello bytes in
        // handleReceivedData before choosing a route. Otherwise commit
        // immediately using the IP-derived configuration.
        if (sniffer == null) {
            beginConnecting()
        } else {
            // Safety net: non-TLS protocols where the server speaks first
            // (SSH, SMTP, FTP) never send client bytes of their own accord.
            // If we haven't decided by TunnelConstants.sniffDeadlineMs, commit the IP-
            // based route and proceed.
            sniffDeadline = lwipExecutor.schedule({
                if (!closed && sniffer != null) {
                    sniffer = null
                    beginConnecting()
                }
            }, TunnelConstants.sniffDeadlineMs, TimeUnit.MILLISECONDS)
        }
    }

    private val isEstablishing: Boolean
        get() = vlessConnecting || directConnecting || sniffer != null

    /** Cancels the sniff deadline timer. Called whenever the sniff phase
     *  resolves (successful SNI, fast reject, cap reached, close, abort). */
    private fun cancelSniffDeadline() {
        sniffDeadline?.cancel(false)
        sniffDeadline = null
    }

    /**
     * Appends to `pendingData` and enforces [TunnelConstants.tcpMaxPendingDataSize].
     * Aborts the connection if the cap would be exceeded and returns
     * `false` so callers can bail out early.
     */
    private fun appendPendingData(data: ByteArray): Boolean {
        if (pendingData.size() + data.size > TunnelConstants.tcpMaxPendingDataSize) {
            logger.warning(
                "[TCP] pendingData cap exceeded for $dstHost:$dstPort " +
                "(${pendingData.size()} + ${data.size} > ${TunnelConstants.tcpMaxPendingDataSize}), aborting"
            )
            abort()
            return false
        }
        pendingData.write(data)
        return true
    }

    /**
     * Kicks off the outbound connection using the currently committed
     * routing (configuration, bypass, dstHost). Idempotent — no-op once
     * the connect has started or completed.
     */
    private fun beginConnecting() {
        if (closed || vlessConnecting || directConnecting) return
        if (vlessConnection != null || directRelay != null) return
        if (bypass) connectDirect() else connectProxy()
    }

    /**
     * Re-evaluates routing using the hostname extracted from the TLS
     * ClientHello. Updates [dstHost], [configuration], and [bypass] in
     * place so the subsequent [beginConnecting] sees the SNI-based decision.
     *
     *   - Found a matching domain rule: apply it (may switch proxy, flip
     *     bypass, or reject the connection) and swap [dstHost] to the SNI
     *     so the new route resolves the name itself.
     *   - No rule matches: keep the IP-derived [dstHost] and
     *     configuration. Rewriting to the SNI hostname would force the
     *     outbound proxy to re-resolve via its own DNS, which can land on
     *     a different CDN IP than the one the caller already chose.
     */
    private fun applySNI(sni: String) {
        val stack = LwipStack.instance ?: return
        val action = stack.domainRouter.matchDomain(sni) ?: return

        // Rule matched: the sniffed hostname drives the new route, so
        // forward the proxy CONNECT to the name rather than the tentative
        // IP.
        dstHost = sni

        when (action) {
            RouteAction.Direct -> {
                bypass = true
            }
            RouteAction.Reject -> {
                logger.debug("[TCP] SNI rejected by routing rule: $sni ($dstHost:$dstPort)")
                rejectGracefully()
            }
            is RouteAction.Proxy -> {
                val resolved = stack.domainRouter.resolveConfiguration(action)
                if (resolved != null) {
                    // Preserve the ambient chain from the default
                    // configuration if the rule-targeted configuration
                    // didn't specify one.
                    val defaultChain = configuration.chain
                    configuration = if (!defaultChain.isNullOrEmpty() && resolved.chain == null) {
                        resolved.withChain(defaultChain)
                    } else {
                        resolved
                    }
                } else {
                    logger.warning("[TCP] SNI routing configuration not found for $sni")
                }
                bypass = stack.shouldBypass(sni)
            }
        }
    }

    /** Handles data received from the local app via lwIP. */
    fun handleReceivedData(data: ByteArray) {
        if (closed) return
        activityTimer?.update()

        // SNI sniff phase: buffer bytes and feed the sniffer before
        // dialing. Once a terminal state is reached we re-evaluate
        // routing (if SNI was found) and then kick off the proxy /
        // direct connect.
        val snifferRef = sniffer
        if (snifferRef != null) {
            val state = snifferRef.feed(data)
            if (!appendPendingData(data)) return
            when (state) {
                is TlsClientHelloSniffer.State.NeedMore -> return
                is TlsClientHelloSniffer.State.Found -> {
                    sniffer = null
                    cancelSniffDeadline()
                    applySNI(state.serverName)
                    if (closed) return  // rule may have rejected
                    beginConnecting()
                    return
                }
                is TlsClientHelloSniffer.State.NotTls,
                is TlsClientHelloSniffer.State.Unavailable -> {
                    sniffer = null
                    cancelSniffDeadline()
                    beginConnecting()
                    return
                }
            }
        }

        // Buffer data while outbound connection is being established
        if (vlessConnecting || directConnecting) {
            appendPendingData(data)
            return
        }

        if (directRelay != null || vlessConnection != null) {
            // Always coalesce — even while a flush is in-flight. This is a
            // buffered-pipe design where data accumulates during the
            // scMinPostsIntervalMs sleep and is sent as one large POST.
            //
            // Strict single-flight: every byte for this connection flows
            // through the same `flushCoalesceBuffer` coroutine chain. Concurrent
            // `connection.send()` calls would interleave inside protocols
            // whose framing can't tolerate it (Vision/HTTP-2/gRPC), so we
            // never spawn a parallel send. Mirrors iOS `UploadPipeline`'s
            // `sendInFlight` invariant in LWIPTCPConnection.swift:71-95.
            if (coalesceBuffer == null) coalesceBuffer = ByteArrayOutputStream()
            coalesceBuffer!!.write(data)

            // Schedule flush only when no send is in-flight (data accumulated
            // during an in-flight send will be flushed when it completes).
            if (!coalesceFlushInFlight && !coalesceScheduled) {
                coalesceScheduled = true
                lwipExecutor.execute { flushCoalesceBuffer() }
            }
        } else {
            if (!appendPendingData(data)) return
            beginConnecting()
        }
    }

    /**
     * Called when the local app acknowledges receipt of data sent via lwIP.
     * Drains the overflow buffer into the now-available send buffer space.
     */
    fun handleSent(len: Int) {
        if (closed) return
        drainPendingWrite()
    }

    /** Called when the local app closes its write side (TCP FIN from app). */
    fun handleRemoteClose() {
        if (closed) return

        // Client FIN'd before we finished sniffing. If we never received
        // any bytes, there's nothing to forward — drop the connection.
        // Otherwise commit the tentative IP-based route and forward what
        // we have.
        if (sniffer != null) {
            sniffer = null
            cancelSniffDeadline()
            if (pendingData.size() == 0) {
                close()
                return
            }
            beginConnecting()
        }

        uplinkDone = true
        if (downlinkDone) {
            close()
        } else {
            activityTimer?.setTimeout(TunnelConstants.downlinkOnlyTimeoutMs)
        }
    }

    /**
     * Surfaces why lwIP tore this connection down. Without this log the
     * connection simply vanishes from the user's perspective — no send /
     * receive error fires because the PCB has already been freed by the
     * time tcp_err runs.
     */
    fun handleError(err: Int) {
        val reason = TransportErrorLogger.describeLwIPError(err)
        when {
            err == -15 ->  // ERR_CLSD — orderly close, not a failure
                logger.debug("[TCP] lwIP closed connection: $endpointDescription: $reason")
            err == -14 ->  // ERR_RST — always local-app-initiated in TUN mode
                logger.debug("[TCP] lwIP peer reset: $endpointDescription: $reason")
            err == -13 && LwipStack.instance?.isTearingDown == true ->
                // ERR_ABRT during a deliberate stack teardown
                // (shutdown/restart/wake). Outside teardown, ERR_ABRT
                // indicates lwIP's own pressure aborts (tcp_kill_prio /
                // tcp_kill_timewait) — those stay at warning below.
                logger.debug("[TCP] lwIP aborted connection (tunnel teardown): $endpointDescription: $reason")
            else ->
                logger.warning("[TCP] lwIP aborted connection: $endpointDescription: $reason")
        }
        if (closed) return
        closed = true
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    private val endpointDescription: String
        get() = "$dstHost:$dstPort"

    private fun logTransportFailure(
        operation: String,
        error: Throwable,
        defaultLevel: LwipStack.LogLevel = LwipStack.LogLevel.ERROR
    ) {
        TransportErrorLogger.log(
            operation = operation,
            endpoint = endpointDescription,
            error = error,
            logger = logger,
            prefix = "[TCP]",
            defaultLevel = defaultLevel
        )
    }

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
                        logTransportFailure("Connect", e)
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
                activityTimer = ActivityTimer(lwipExecutor, TunnelConstants.connectionIdleTimeoutMs) {
                    if (!closed) close()
                }

                // Drain initialData + any pendingData that arrived during connect.
                // Send sequentially in one coroutine so byte order is preserved
                // (mirrors iOS UploadPipeline's strict single-flight semantics).
                val followup = if (pendingData.size() > 0) {
                    val data = pendingData.toByteArray()
                    pendingData.reset()
                    data
                } else null

                if (initialData != null || followup != null) {
                    scope.launch {
                        try {
                            if (initialData != null) relay.send(initialData)
                            if (followup != null) relay.send(followup)
                            val totalAck = (initialData?.size ?: 0) + (followup?.size ?: 0)
                            lwipExecutor.execute {
                                if (closed) return@execute
                                ackBytesToLwip(totalAck)
                            }
                        } catch (_: CancellationException) {
                        } catch (e: Exception) {
                            if (!closed) logTransportFailure("Send", e, LwipStack.LogLevel.WARNING)
                            lwipExecutor.execute { abort() }
                        }
                    }
                }

                tryArmReceive()
            }
        }
    }

    /**
     * Acknowledges [bytes] to lwIP in 65535-byte chunks (UInt16 cap), then
     * forces an immediate window-update output flush. Mirrors iOS
     * `acknowledgeReceivedBytes` (LWIPTCPConnection.swift:332-342).
     */
    private fun ackBytesToLwip(bytes: Int) {
        if (bytes <= 0) return
        var remaining = bytes
        while (remaining > 0) {
            val chunk = remaining.coerceAtMost(65535)
            NativeBridge.nativeTcpRecved(pcb, chunk)
            remaining -= chunk
        }
        NativeBridge.nativeTcpOutput(pcb)
        LwipStack.instance?.flushOutputInline()
    }

    /**
     * Connects to the proxy using the appropriate protocol (VLESS, Shadowsocks, NaiveProxy).
     * Uses [ProxyClientFactory] for protocol selection.
     */
    private fun connectProxy() {
        if (vlessConnecting || vlessConnection != null || closed) return
        vlessConnecting = true

        // Only protocols that embed the first bytes inside their handshake
        // (VLESS + transports) consume `pendingData` here. For everything
        // else (Trojan, Shadowsocks, SOCKS5, NaiveProxy), leave
        // `pendingData` intact — `onProxyConnected` will forward it via the
        // proxy connection AND ACK it back to lwIP via `nativeTcpRecved`.
        val initialData = if (configuration.outboundProtocol.handshakeCarriesInitialData
            && pendingData.size() > 0) {
            val data = pendingData.toByteArray()
            pendingData.reset()
            data
        } else null

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
                onProxyConnected(connection, handshakeAckBytes = initialData?.size ?: 0)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        logTransportFailure("Connect", e)
                        abort()
                    }
                }
            }
        }
    }

    /**
     * Handles post-connection setup common to all protocol paths.
     * Sets up activity timer, flushes pending data, and starts the receive loop.
     *
     * [handshakeAckBytes] is the byte count of any initialData that the protocol
     * consumed inside its handshake (extracted by `connectProxy` for VLESS-style
     * protocols where `handshakeCarriesInitialData` is true). Those bytes were
     * never `nativeTcpRecved`'d; ack them here so lwIP's recv window reopens.
     * Mirrors iOS `LWIPTCPConnection.swift:602-606`.
     */
    private fun onProxyConnected(connection: ProxyConnection, handshakeAckBytes: Int = 0) {
        lwipExecutor.execute {
            vlessConnecting = false
            if (closed) {
                connection.cancel()
                return@execute
            }

            vlessConnection = connection
            handshakeTimer?.cancel(false)
            handshakeTimer = null
            activityTimer = ActivityTimer(lwipExecutor, TunnelConstants.connectionIdleTimeoutMs) {
                if (!closed) close()
            }

            // Drain any pendingData arrived during connect, then ack the
            // combined byte count (handshake-carried + pendingData) in one shot.
            val followup = if (pendingData.size() > 0) {
                val data = pendingData.toByteArray()
                pendingData.reset()
                data
            } else null

            if (followup != null) {
                scope.launch {
                    try {
                        connection.send(followup)
                        lwipExecutor.execute {
                            if (closed) return@execute
                            ackBytesToLwip(handshakeAckBytes + followup.size)
                        }
                    } catch (_: CancellationException) {
                    } catch (e: Exception) {
                        if (!closed) logTransportFailure("Send", e, LwipStack.LogLevel.WARNING)
                        lwipExecutor.execute { abort() }
                    }
                }
            } else if (handshakeAckBytes > 0) {
                ackBytesToLwip(handshakeAckBytes)
            }

            tryArmReceive()
        }
    }

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
                var previousConnection: ProxyConnection? = null

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
                onProxyConnected(connection, handshakeAckBytes = initialData?.size ?: 0)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        logTransportFailure("Connect", e)
                        abort()
                    }
                }
            }
        }
    }

    /**
     * Flushes the coalesce buffer, sending accumulated segments through the
     * proxy in `tcpMaxCoalesceSize` chunks. All chunks for a single flush
     * land in one coroutine so the proxy connection sees strictly serial
     * `send` calls — a hard requirement for protocols whose framing uses
     * 2-byte length fields (Vision padding) or shared sequence numbers
     * (HTTP/2, gRPC). Mirrors iOS `UploadPipeline.pumpUploadSends`
     * (LWIPTCPConnection.swift:299-326).
     *
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
                var sent = 0
                while (sent < dataToSend.size) {
                    val chunkSize = minOf(
                        dataToSend.size - sent,
                        TunnelConstants.tcpMaxCoalesceSize
                    )
                    val chunk = if (sent == 0 && chunkSize == dataToSend.size) {
                        dataToSend
                    } else {
                        dataToSend.copyOfRange(sent, sent + chunkSize)
                    }
                    if (relay != null) {
                        relay.send(chunk)
                    } else {
                        connection!!.send(chunk)
                    }
                    // Per-chunk ack mirrors iOS — keeps lwIP's recv window
                    // opening in step with upstream throughput rather than
                    // batching the whole buffer's worth of credit at once.
                    lwipExecutor.execute {
                        if (!closed) ackBytesToLwip(chunkSize)
                    }
                    sent += chunkSize
                }
                lwipExecutor.execute {
                    coalesceFlushInFlight = false
                    if (!closed) {
                        // Immediately flush data that accumulated during the in-flight send.
                        // Data coalesces while the previous POST + delay runs, then flushes
                        // as one large POST instead of many small per-segment POSTs.
                        if (coalesceBuffer != null && coalesceBuffer!!.size() > 0) {
                            flushCoalesceBuffer()
                        }
                    }
                }
            } catch (_: CancellationException) {
                lwipExecutor.execute { coalesceFlushInFlight = false }
            } catch (e: Exception) {
                if (!closed) logTransportFailure("Send", e, LwipStack.LogLevel.WARNING)
                lwipExecutor.execute {
                    coalesceFlushInFlight = false
                    abort()
                }
            }
        }
    }

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
            val chunkSize = minOf(sndbuf, count - offset, TunnelConstants.tcpMaxWriteSize)
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
     * Appends data received from the proxy onto [pendingWrite], then drains
     * as much as lwIP will accept. All order-preservation lives in
     * [pendingWrite], so a concurrently prefetched receive can land without
     * racing ahead of the chunk currently being drained.
     */
    fun writeToLwip(data: ByteArray) {
        if (closed || data.isEmpty()) return
        pendingWrite.write(data)
        drainPendingWrite()
    }

    /**
     * Drains [pendingWrite] into lwIP's TCP send buffer and, on progress,
     * arms the next proxy receive if we've dropped below
     * [TunnelConstants.drainLowWaterMark].
     *
     * Called from [handleSent] on every client ACK, from [writeToLwip]
     * after new proxy data is appended, and from a [TunnelConstants.drainRetryDelayMs]
     * fallback timer when `tcp_write` couldn't place any bytes (snd_buf
     * full / zero window).
     */
    private fun drainPendingWrite() {
        if (closed) return

        if (pendingWrite.size() > 0) {
            val data = pendingWrite.backingArray()
            val dataSize = pendingWrite.size()
            val written = feedLwip(data, 0, dataSize, retryOnEmpty = true)
            if (written == -1) {
                val sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
                logger.error("[TCP] tcp_write fatal: $dstHost:$dstPort (pending=$dataSize, sndbuf=$sndbuf)")
                abort()
                return
            }
            if (closed) return

            if (written > 0) {
                if (written >= dataSize) {
                    pendingWrite.reset()
                } else {
                    pendingWrite.consume(written)
                }
                NativeBridge.nativeTcpOutput(pcb)
                // Flush the egress queue inline so freed pbufs leave the host
                // within the same drain cycle that consumed them.
                LwipStack.instance?.flushOutputInline()
            } else {
                // Nothing drained (ERR_MEM / zero window) — schedule a delayed
                // retry. Skip `tryArmReceive` on purpose: piling more upstream
                // bytes onto a stalled connection only grows `pendingWrite`.
                // Once the retry makes progress, the tail call re-arms.
                lwipExecutor.schedule(
                    { if (!closed) drainPendingWrite() },
                    TunnelConstants.drainRetryDelayMs,
                    TimeUnit.MILLISECONDS
                )
                return
            }
        }

        // Made progress (or nothing was pending): prefetch the next chunk if
        // the backlog is below the low-water mark.
        tryArmReceive()
    }

    /**
     * Issues the next proxy receive if the downlink backlog is below the
     * low-water mark and no receive is already in flight.
     *
     * Overlapping the next receive with the ongoing drain keeps lwIP's send
     * buffer saturated: by the time a client ACK frees space, a fresh chunk
     * is already queued in [pendingWrite] ready to push. Without this
     * overlap, a big receive (e.g. a speed-test server pushing >1 MB per
     * read) forces stop-and-wait — the proxy socket's receive window stays
     * closed for the entire drain, and upstream throttles.
     *
     * Backpressure still applies: when `pendingWrite.size()` is at or above
     * [TunnelConstants.drainLowWaterMark], this is a no-op, so receives
     * naturally pause whenever lwIP can't keep up.
     */
    private fun tryArmReceive() {
        if (closed || receiveInFlight) return
        if (pendingWrite.size() >= TunnelConstants.drainLowWaterMark) return

        val relay = directRelay
        val connection = vlessConnection
        if (relay == null && connection == null) return

        receiveInFlight = true
        scope.launch {
            var data: ByteArray? = null
            var error: Throwable? = null
            var cancelled = false
            try {
                data = relay?.receive() ?: connection?.receive()
            } catch (_: CancellationException) {
                cancelled = true
            } catch (e: Exception) {
                error = e
            }

            lwipExecutor.execute {
                receiveInFlight = false
                if (closed || cancelled) return@execute

                if (error != null) {
                    logTransportFailure("Receive", error, LwipStack.LogLevel.WARNING)
                    abort()
                    return@execute
                }

                if (data == null || data.isEmpty()) {
                    downlinkDone = true
                    if (uplinkDone) {
                        close()
                    } else {
                        activityTimer?.setTimeout(TunnelConstants.uplinkOnlyTimeoutMs)
                    }
                    return@execute
                }

                activityTimer?.update()
                writeToLwip(data)
            }
        }
    }

    /** Best-effort flush of pending data into lwIP send buffer before close. */
    private fun flushPendingToLwip() {
        if (pendingWrite.size() == 0) return
        val written = feedLwip(pendingWrite.backingArray(), 0, pendingWrite.size())
        if (written > 0) {
            NativeBridge.nativeTcpOutput(pcb)
        }
    }

    fun close() {
        if (closed) return
        closed = true
        flushPendingToLwip()
        NativeBridge.nativeTcpClose(pcb)
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    /**
     * Tears the connection down with a clean FIN instead of a RST.
     *
     * `tcp_close` in lwIP downgrades to RST whenever the receive window
     * is below `TCP_WND_MAX` — i.e. when bytes were delivered via
     * `tcp_recv_cb` but never acknowledged via `tcp_recved`. The sniffed
     * ClientHello in `pendingData` is exactly that: received but
     * unacknowledged because we never forwarded it upstream. A mid-
     * handshake RST is widely interpreted by TLS stacks as a transient
     * failure, which drives browsers and HTTP clients to retry
     * aggressively — defeating the point of the reject rule. Advancing
     * the window first lets `close()` send a real FIN, which clients
     * treat as a deliberate peer close and don't retry.
     */
    private fun rejectGracefully() {
        if (closed) return
        var remaining = pendingData.size()
        while (remaining > 0) {
            val chunk = remaining.coerceAtMost(65535)
            NativeBridge.nativeTcpRecved(pcb, chunk)
            remaining -= chunk
        }
        close()
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
        cancelSniffDeadline()
        sniffer = null
        activityTimer?.cancel()
        activityTimer = null
        val relay = directRelay
        val connection = vlessConnection
        directRelay = null
        vlessConnection = null
        vlessConnecting = false
        directConnecting = false
        pendingData.reset()
        pendingWrite.reset()
        coalesceBuffer = null
        coalesceScheduled = false
        receiveInFlight = false

        relay?.cancel()
        connection?.cancel()
    }

    companion object {
        private val logger = AnywhereLogger("LWIP-TCP")
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
