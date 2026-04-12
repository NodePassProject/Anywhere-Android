package com.argsment.anywhere.vpn.protocol.vless

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.HttpUpgradeConfiguration
import com.argsment.anywhere.data.model.RealityConfiguration
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.data.model.WebSocketConfiguration
import com.argsment.anywhere.data.model.XHttpConfiguration
import com.argsment.anywhere.data.model.XHttpMode
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.httpupgrade.HttpUpgradeConnection
import com.argsment.anywhere.vpn.protocol.reality.RealityClient
import com.argsment.anywhere.vpn.protocol.tls.TlsClient
import com.argsment.anywhere.vpn.protocol.tls.TlsError
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.websocket.WebSocketConnection
import com.argsment.anywhere.vpn.protocol.xhttp.TransportClosures
import com.argsment.anywhere.vpn.protocol.xhttp.XHttpConnection
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.delay
import java.util.UUID

private val logger = AnywhereLogger("VlessClient")

/**
 * Client for establishing VLESS proxy connections over TCP or UDP.
 *
 * Supports transport selection (TCP / WebSocket / HTTP Upgrade / XHTTP),
 * security selection (None / TLS / Reality), and flow control (None / Vision).
 *
 * Retry logic: 5 attempts with linear backoff 0/200/400/600/800ms (matching Xray-core).
 */
class VlessClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: VlessConnection? = null
) {

    private var connection: NioSocket? = null
    private var tunnelTransport: TunneledTransport? = null
    private var realityClient: RealityClient? = null
    private var realityConnection: TlsRecordConnection? = null
    private var tlsClient: TlsClient? = null
    private var tlsConnection: TlsRecordConnection? = null
    private var webSocketConnection: WebSocketConnection? = null
    private var httpUpgradeConnection: HttpUpgradeConnection? = null
    private var xhttpConnection: XHttpConnection? = null

    companion object {
        /** Retry configuration matching Xray-core: ExponentialBackoff(5, 200) */
        /** Delays: 0, 200, 400, 600, 800 ms (linear backoff) */
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L

        /** The base Vision flow string sent on the wire (suffix stripped). */
        private const val VISION_FLOW = "xtls-rprx-vision"
    }

    /** Whether the configured flow is a Vision variant. */
    private val isVisionFlow: Boolean
        get() = configuration.flow == VISION_FLOW || configuration.flow == "$VISION_FLOW-udp443"

    /** Whether UDP port 443 is allowed (only with the `-udp443` suffix). */
    private val allowUDP443: Boolean
        get() = configuration.flow == "$VISION_FLOW-udp443"

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Connects to a destination through the VLESS server using TCP.
     *
     * @param destinationHost The destination hostname or IP address.
     * @param destinationPort The destination port number.
     * @param initialData Optional initial data to send with the VLESS request header.
     * @return The established [VlessConnection].
     */
    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): VlessConnection {
        return connectWithCommand(
            command = VlessCommand.TCP,
            destinationHost = destinationHost,
            destinationPort = destinationPort,
            initialData = initialData
        )
    }

    /**
     * Connects to a destination through the VLESS server using UDP.
     *
     * @param destinationHost The destination hostname or IP address.
     * @param destinationPort The destination port number.
     * @return The established [VlessConnection].
     */
    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): VlessConnection {
        return connectWithCommand(
            command = VlessCommand.UDP,
            destinationHost = destinationHost,
            destinationPort = destinationPort,
            initialData = null
        )
    }

    /**
     * Connects a mux control channel through the VLESS server.
     *
     * Uses command=MUX with destination "v1.mux.cool:666" (matching Xray-core).
     * When Vision flow is active, the mux connection is wrapped with Vision.
     *
     * @return The established [VlessConnection].
     */
    suspend fun connectMux(): VlessConnection {
        return connectWithCommand(
            command = VlessCommand.MUX,
            destinationHost = "v1.mux.cool",
            destinationPort = 666,
            initialData = null
        )
    }

    /** Cleans up resources from a failed retry attempt before the next one. */
    private fun cleanupRetryResources() {
        xhttpConnection?.cancel()
        xhttpConnection = null
        httpUpgradeConnection?.cancel()
        httpUpgradeConnection = null
        webSocketConnection?.cancel()
        webSocketConnection = null
        connection?.forceCancel()
        connection = null
        tunnelTransport = null
        realityConnection?.cancel()
        realityConnection = null
        realityClient?.cancel()
        realityClient = null
        tlsConnection?.cancel()
        tlsConnection = null
        tlsClient?.cancel()
        tlsClient = null
    }

    /**
     * Cancels the connection and releases all resources.
     */
    fun cancel() {
        xhttpConnection?.cancel()
        xhttpConnection = null
        httpUpgradeConnection?.cancel()
        httpUpgradeConnection = null
        webSocketConnection?.cancel()
        webSocketConnection = null
        connection?.forceCancel()
        connection = null
        realityConnection?.cancel()
        realityConnection = null
        realityClient?.cancel()
        realityClient = null
        tlsConnection?.cancel()
        tlsConnection = null
        tlsClient?.cancel()
        tlsClient = null
    }

    private fun requireTunnelTransport(): TunneledTransport {
        val activeTunnel = tunnel
            ?: throw ProxyError.ConnectionFailed("Missing tunnel transport")
        return tunnelTransport ?: TunneledTransport(activeTunnel).also { tunnelTransport = it }
    }

    private suspend fun buildUploadTunnel(): VlessConnection {
        val chain = configuration.chain
        if (chain.isNullOrEmpty()) {
            return tunnel ?: throw ProxyError.ConnectionFailed("Missing upload tunnel")
        }

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

        return previousConnection
            ?: throw ProxyError.ConnectionFailed("Failed to build upload tunnel")
    }

    // =========================================================================
    // Connection Routing
    // =========================================================================

    /**
     * Routes the connection through the appropriate transport and security layers
     * based on configuration.
     */
    private suspend fun connectWithCommand(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        // Vision silently drops UDP/443 (QUIC) unless the -udp443 flow variant is used
        if (command == VlessCommand.UDP && destinationPort == 443 && isVisionFlow && !allowUDP443) {
            throw ProxyError.Dropped()
        }

        return when (configuration.transport) {
            "ws" -> {
                // Vision over WebSocket is not supported
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over WebSocket transport")
                }
                connectWithWebSocket(command, destinationHost, destinationPort, initialData)
            }

            "httpupgrade" -> {
                // Vision over HTTP upgrade is not supported
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over HTTP upgrade transport")
                }
                connectWithHttpUpgrade(command, destinationHost, destinationPort, initialData)
            }

            "xhttp" -> {
                // Vision over XHTTP is not supported
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over XHTTP transport")
                }
                connectWithXHttp(command, destinationHost, destinationPort, initialData)
            }

            else -> {
                // TCP transport -- route based on security
                when {
                    configuration.tls != null -> connectWithTls(
                        configuration.tls, command, destinationHost, destinationPort, initialData
                    )

                    configuration.reality != null -> connectWithReality(
                        configuration.reality, command, destinationHost, destinationPort, initialData
                    )

                    else -> connectDirect(command, destinationHost, destinationPort, initialData)
                }
            }
        }
    }

    // =========================================================================
    // WebSocket Connection
    // =========================================================================

    /**
     * Connects to the VLESS server using WebSocket transport.
     * Routes to WSS (TLS + WebSocket) or plain WS based on TLS configuration.
     */
    private suspend fun connectWithWebSocket(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        val wsConfig = configuration.websocket
            ?: throw ProxyError.ConnectionFailed("WebSocket transport specified but no WebSocket configuration")

        return if (configuration.tls != null) {
            connectWssWithRetry(wsConfig, command, destinationHost, destinationPort, initialData)
        } else {
            connectWsWithRetry(wsConfig, command, destinationHost, destinationPort, initialData)
        }
    }

    // -- Plain WS (TCP -> WebSocket -> VLESS) --

    private suspend fun connectWsWithRetry(
        wsConfig: WebSocketConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val wsConnection = if (tunnel != null) {
                    WebSocketConnection(transport = requireTunnelTransport(), configuration = wsConfig)
                } else {
                    val socket = NioSocket()
                    this.connection = socket
                    socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
                    WebSocketConnection(socket = socket, configuration = wsConfig)
                }
                this.webSocketConnection = wsConnection

                wsConnection.performUpgrade()

                return performWebSocketHandshake(
                    wsConnection, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("WS connection attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- WSS (TCP -> TLS -> WebSocket -> VLESS) --

    private suspend fun connectWssWithRetry(
        wsConfig: WebSocketConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val baseTlsConfig = configuration.tls
                    ?: throw ProxyError.ConnectionFailed("WSS requires TLS configuration")

                // Force ALPN to http/1.1 for WebSocket -- matches Xray-core's
                // tls.WithNextProto("http/1.1") in websocket/dialer.go.
                // HTTP/2 negotiation would break the WebSocket upgrade handshake.
                val wsTlsConfig = TlsConfiguration(
                    serverName = baseTlsConfig.serverName,
                    alpn = listOf("http/1.1"),
                    allowInsecure = baseTlsConfig.allowInsecure,
                    fingerprint = baseTlsConfig.fingerprint
                )

                val tlsClient = TlsClient(wsTlsConfig)
                val tlsConn = if (tunnel != null) {
                    tlsClient.connect(requireTunnelTransport())
                } else {
                    tlsClient.connect(configuration.serverAddress, configuration.serverPort.toInt())
                }
                this.tlsClient = tlsClient
                this.tlsConnection = tlsConn

                val wsConnection = WebSocketConnection(tlsConnection = tlsConn, configuration = wsConfig)
                this.webSocketConnection = wsConnection

                wsConnection.performUpgrade()

                return performWebSocketHandshake(
                    wsConnection, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("WSS connection attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- WebSocket VLESS Handshake --

    /**
     * Performs the VLESS handshake over an established WebSocket connection.
     */
    private suspend fun performWebSocketHandshake(
        wsConnection: WebSocketConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null  // Vision is rejected before reaching here
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        wsConnection.send(requestData)

        return if (command == VlessCommand.UDP) {
            VlessWebSocketUdpConnection(wsConnection)
        } else {
            VlessWebSocketConnection(wsConnection)
        }
    }

    // =========================================================================
    // HTTP Upgrade Connection
    // =========================================================================

    /**
     * Connects to the VLESS server using HTTP upgrade transport.
     * Routes to HTTPS upgrade (TLS + HTTP upgrade) or plain HTTP upgrade based on TLS configuration.
     */
    private suspend fun connectWithHttpUpgrade(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        val huConfig = configuration.httpUpgrade
            ?: throw ProxyError.ConnectionFailed("HTTP upgrade transport specified but no configuration")

        return if (configuration.tls != null) {
            connectHttpsUpgradeWithRetry(huConfig, command, destinationHost, destinationPort, initialData)
        } else {
            connectHttpUpgradeWithRetry(huConfig, command, destinationHost, destinationPort, initialData)
        }
    }

    // -- Plain HTTP Upgrade (TCP -> HTTP Upgrade -> raw TCP -> VLESS) --

    private suspend fun connectHttpUpgradeWithRetry(
        huConfig: HttpUpgradeConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val huConnection = if (tunnel != null) {
                    HttpUpgradeConnection(transport = requireTunnelTransport(), configuration = huConfig)
                } else {
                    val socket = NioSocket()
                    this.connection = socket
                    socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
                    HttpUpgradeConnection(socket = socket, configuration = huConfig)
                }
                this.httpUpgradeConnection = huConnection

                huConnection.performUpgrade()

                return performHttpUpgradeHandshake(
                    huConnection, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("HTTP upgrade attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- HTTPS Upgrade (TCP -> TLS -> HTTP Upgrade -> raw TCP over TLS -> VLESS) --

    private suspend fun connectHttpsUpgradeWithRetry(
        huConfig: HttpUpgradeConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val baseTlsConfig = configuration.tls
                    ?: throw ProxyError.ConnectionFailed("HTTPS upgrade requires TLS configuration")

                val tlsClient = TlsClient(baseTlsConfig)
                val tlsConn = if (tunnel != null) {
                    tlsClient.connect(requireTunnelTransport())
                } else {
                    tlsClient.connect(configuration.serverAddress, configuration.serverPort.toInt())
                }
                this.tlsClient = tlsClient
                this.tlsConnection = tlsConn

                val huConnection = HttpUpgradeConnection(tlsConnection = tlsConn, configuration = huConfig)
                this.httpUpgradeConnection = huConnection

                huConnection.performUpgrade()

                return performHttpUpgradeHandshake(
                    huConnection, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("HTTPS upgrade attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- HTTP Upgrade VLESS Handshake --

    /**
     * Performs the VLESS handshake over an established HTTP upgrade connection.
     */
    private suspend fun performHttpUpgradeHandshake(
        huConnection: HttpUpgradeConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null  // Vision is rejected before reaching here
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        huConnection.send(requestData)

        return if (command == VlessCommand.UDP) {
            VlessHttpUpgradeUdpConnection(huConnection)
        } else {
            VlessHttpUpgradeConnection(huConnection)
        }
    }

    // =========================================================================
    // XHTTP Connection
    // =========================================================================

    /**
     * Connects to the VLESS server using XHTTP transport.
     * Routes to plain HTTP or HTTPS based on security configuration.
     *
     * Reality is not supported: Xray-core forces HTTP/2 for Reality (dialer.go:80-82),
     * and we only implement HTTP/1.1 over raw sockets.
     *
     * Mode auto-resolution (matching Xray-core dialer.go:280-289):
     * - Reality -> stream-one with HTTP/2 (Xray-core forces h2 for Reality)
     * - TLS/none -> packet-up (CDN-safe, GET + POST over HTTP/1.1)
     */
    /**
     * Decides the HTTP version for XHTTP, matching Xray-core's decideHTTPVersion.
     * - Reality always uses HTTP/2.
     * - No TLS means plain HTTP/1.1.
     * - TLS with a single "http/1.1" ALPN stays on HTTP/1.1.
     * - TLS with a single "h3" ALPN expects QUIC/HTTP/3 (not implemented).
     * - Everything else uses HTTP/2.
     */
    private enum class XHttpHttpVersion { HTTP11, HTTP2, HTTP3 }

    private fun decideXHttpHttpVersion(): XHttpHttpVersion {
        if (configuration.reality != null) return XHttpHttpVersion.HTTP2
        val tlsConfig = configuration.tls ?: return XHttpHttpVersion.HTTP11
        val alpn = tlsConfig.alpn ?: emptyList()
        if (alpn.size != 1) return XHttpHttpVersion.HTTP2
        return when (alpn[0].lowercase()) {
            "http/1.1" -> XHttpHttpVersion.HTTP11
            "h3" -> XHttpHttpVersion.HTTP3
            else -> XHttpHttpVersion.HTTP2
        }
    }

    /**
     * Sanitizes TLS ALPN for XHTTP-over-TCP handshakes.
     * Strips protocols like h3 that require QUIC, ensuring only TCP-compatible
     * ALPN values are advertised (matching iOS sanitizedXHTTPTLSConfiguration).
     */
    private fun sanitizedXHttpTlsConfig(
        base: TlsConfiguration,
        httpVersion: XHttpHttpVersion
    ): TlsConfiguration {
        val sanitizedAlpn: List<String>? = when (httpVersion) {
            XHttpHttpVersion.HTTP11 -> listOf("http/1.1")
            XHttpHttpVersion.HTTP2 -> {
                val configured = base.alpn
                if (configured != null) {
                    val filtered = configured.filter {
                        it.equals("h2", ignoreCase = true) || it.equals("http/1.1", ignoreCase = true)
                    }
                    if (filtered.isEmpty() || (filtered.size == 1 && filtered[0].equals("http/1.1", ignoreCase = true))) {
                        listOf("h2", "http/1.1")
                    } else {
                        filtered
                    }
                } else {
                    null
                }
            }
            XHttpHttpVersion.HTTP3 -> listOf("h3")
        }
        return TlsConfiguration(
            serverName = base.serverName,
            alpn = sanitizedAlpn,
            allowInsecure = base.allowInsecure,
            fingerprint = base.fingerprint
        )
    }

    private suspend fun connectWithXHttp(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        val xhttpConfig = configuration.xhttp
            ?: throw ProxyError.ConnectionFailed("XHTTP transport specified but no XHTTP configuration")

        val httpVersion = decideXHttpHttpVersion()
        if (httpVersion == XHttpHttpVersion.HTTP3) {
            throw ProxyError.ProtocolError(
                "XHTTP over TLS with ALPN h3 requires QUIC/HTTP/3, which is not implemented yet"
            )
        }

        val useHTTP2 = httpVersion == XHttpHttpVersion.HTTP2

        // Resolve mode: auto -> actual mode based on security
        val resolvedMode: XHttpMode = if (xhttpConfig.mode == XHttpMode.AUTO) {
            // Reality -> stream-one (direct connection, HTTP/2)
            // TLS/none -> packet-up (CDN-safe, HTTP/1.1)
            if (configuration.reality != null) XHttpMode.STREAM_ONE else XHttpMode.PACKET_UP
        } else {
            xhttpConfig.mode
        }

        // Generate session ID for packet-up and stream-up modes (matching iOS)
        val sessionId = if (resolvedMode == XHttpMode.PACKET_UP || resolvedMode == XHttpMode.STREAM_UP) {
            UUID.randomUUID().toString()
        } else {
            ""
        }

        return when {
            configuration.reality != null -> connectXHttpRealityWithRetry(
                configuration.reality, xhttpConfig, resolvedMode, sessionId,
                command, destinationHost, destinationPort, initialData
            )

            configuration.tls != null -> connectXHttpsWithRetry(
                xhttpConfig, resolvedMode, sessionId, useHTTP2,
                command, destinationHost, destinationPort, initialData
            )

            else -> connectXHttpWithRetry(
                xhttpConfig, resolvedMode, sessionId,
                command, destinationHost, destinationPort, initialData
            )
        }
    }

    // -- Plain XHTTP (TCP -> XHTTP -> VLESS) --

    private suspend fun connectXHttpWithRetry(
        xhttpConfig: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                // Upload connection factory for packet-up and stream-up modes (matching iOS)
                val needsUpload = mode == XHttpMode.PACKET_UP || mode == XHttpMode.STREAM_UP
                val uploadFactory: (suspend () -> TransportClosures)? =
                    if (needsUpload) {
                        {
                            if (tunnel != null) {
                                val uploadTunnel = buildUploadTunnel()
                                val uploadTransport = TunneledTransport(uploadTunnel)
                                TransportClosures(
                                    send = { data -> uploadTransport.send(data) },
                                    sendAsync = { data -> uploadTransport.sendAsync(data) },
                                    receive = { uploadTransport.receive() },
                                    cancel = { uploadTransport.forceCancel() }
                                )
                            } else {
                                val uploadSocket = NioSocket()
                                uploadSocket.connect(configuration.serverAddress, configuration.serverPort.toInt())
                                TransportClosures(
                                    send = { data -> uploadSocket.send(data) },
                                    sendAsync = { data -> uploadSocket.sendAsync(data) },
                                    receive = { uploadSocket.receive() },
                                    cancel = { uploadSocket.forceCancel() }
                                )
                            }
                        }
                    } else {
                        null
                    }

                val xhttpConn = XHttpConnection(
                    transport = if (tunnel != null) requireTunnelTransport() else run {
                        val socket = NioSocket()
                        this.connection = socket
                        socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
                        socket
                    },
                    configuration = xhttpConfig,
                    mode = mode,
                    sessionId = sessionId,
                    uploadConnectionFactory = uploadFactory
                )
                this.xhttpConnection = xhttpConn

                xhttpConn.performSetup()

                return performXHttpHandshake(
                    xhttpConn, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("XHTTP attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- XHTTPS (TCP -> TLS -> XHTTP -> VLESS) --

    private suspend fun connectXHttpsWithRetry(
        xhttpConfig: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        useHTTP2: Boolean,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val baseTlsConfig = configuration.tls
                    ?: throw ProxyError.ConnectionFailed("XHTTPS requires TLS configuration")

                // Sanitize ALPN: strip h3 (requires QUIC), ensure h2 present for HTTP/2
                val httpVersion = if (useHTTP2) XHttpHttpVersion.HTTP2 else XHttpHttpVersion.HTTP11
                val tlsConfig = sanitizedXHttpTlsConfig(baseTlsConfig, httpVersion)

                val tlsClient = TlsClient(tlsConfig)
                val tlsConn = if (tunnel != null) {
                    tlsClient.connect(requireTunnelTransport())
                } else {
                    tlsClient.connect(configuration.serverAddress, configuration.serverPort.toInt())
                }
                this.tlsClient = tlsClient
                this.tlsConnection = tlsConn

                // Upload connection factory for packet-up and stream-up modes (matching iOS)
                val needsUpload = !useHTTP2 && (mode == XHttpMode.PACKET_UP || mode == XHttpMode.STREAM_UP)
                val uploadFactory: (suspend () -> TransportClosures)? =
                    if (needsUpload) {
                        {
                            val uploadTlsClient = TlsClient(tlsConfig)
                            val uploadTlsConn = if (tunnel != null) {
                                uploadTlsClient.connect(TunneledTransport(buildUploadTunnel()))
                            } else {
                                uploadTlsClient.connect(
                                    configuration.serverAddress, configuration.serverPort.toInt()
                                )
                            }
                            TransportClosures(
                                send = { data -> uploadTlsConn.send(data) },
                                sendAsync = { data -> uploadTlsConn.sendAsync(data) },
                                receive = { uploadTlsConn.receive() },
                                cancel = { uploadTlsConn.cancel() }
                            )
                        }
                    } else {
                        null
                    }

                val xhttpConn = XHttpConnection(
                    tlsConnection = tlsConn,
                    configuration = xhttpConfig,
                    mode = mode,
                    sessionId = sessionId,
                    useHTTP2 = useHTTP2,
                    uploadConnectionFactory = uploadFactory
                )
                this.xhttpConnection = xhttpConn

                xhttpConn.performSetup()

                return performXHttpHandshake(
                    xhttpConn, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("XHTTPS attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- XHTTP Reality (TCP -> Reality TLS -> HTTP/2 -> XHTTP -> VLESS) --

    private suspend fun connectXHttpRealityWithRetry(
        realityConfig: RealityConfiguration,
        xhttpConfig: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val realityClient = RealityClient(realityConfig)
                val realityConn = if (tunnel != null) {
                    realityClient.connect(requireTunnelTransport())
                } else {
                    realityClient.connect(
                        configuration.serverAddress, configuration.serverPort.toInt()
                    )
                }
                this.realityClient = realityClient
                this.realityConnection = realityConn

                // Reality + xhttp uses HTTP/2 (Xray-core dialer.go:80-82)
                val xhttpConn = XHttpConnection(
                    tlsConnection = realityConn,
                    configuration = xhttpConfig,
                    mode = mode,
                    sessionId = sessionId,
                    useHTTP2 = true
                )
                this.xhttpConnection = xhttpConn

                xhttpConn.performSetup()

                return performXHttpHandshake(
                    xhttpConn, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("XHTTP Reality attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // -- XHTTP VLESS Handshake --

    /**
     * Performs the VLESS handshake over an established XHTTP connection.
     */
    private suspend fun performXHttpHandshake(
        xhttpConnection: XHttpConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null  // Vision is rejected before reaching here
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        xhttpConnection.send(requestData)

        return if (command == VlessCommand.UDP) {
            VlessXHttpUdpConnection(xhttpConnection)
        } else {
            VlessXHttpConnection(xhttpConnection)
        }
    }

    // =========================================================================
    // Direct Connection
    // =========================================================================

    /**
     * Connects directly to the VLESS server using a NIO socket.
     * Retries with linear backoff (0, 200, 400, 600, 800 ms) on connection failure,
     * matching Xray-core.
     */
    private suspend fun connectDirect(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        // Tunneled: use existing tunnel connection (no NioSocket, no retries)
        if (tunnel != null) {
            tunnelTransport = TunneledTransport(tunnel)
            return performHandshake(
                command, destinationHost, destinationPort, initialData
            )
        }

        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val socket = NioSocket()
                this.connection = socket

                socket.connect(configuration.serverAddress, configuration.serverPort.toInt())

                return performHandshake(
                    command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("Connection attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // =========================================================================
    // Reality Connection
    // =========================================================================

    /**
     * Connects to the VLESS server through the Reality protocol.
     * Retries with linear backoff (0, 200, 400, 600, 800 ms) on connection failure,
     * matching Xray-core.
     */
    private suspend fun connectWithReality(
        realityConfig: RealityConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val realityClient = RealityClient(realityConfig)
                val realityConn = if (tunnel != null) {
                    realityClient.connect(requireTunnelTransport())
                } else {
                    realityClient.connect(
                        configuration.serverAddress, configuration.serverPort.toInt()
                    )
                }
                this.realityClient = realityClient
                this.realityConnection = realityConn

                return performRealityHandshake(
                    command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("Reality attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // =========================================================================
    // TLS Connection
    // =========================================================================

    /**
     * Connects to the VLESS server through standard TLS.
     * Retries with linear backoff (0, 200, 400, 600, 800 ms) on connection failure,
     * matching Xray-core.
     */
    private suspend fun connectWithTls(
        tlsConfig: TlsConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        // Tunneled: TLS handshake over existing tunnel connection (no retries)
        if (tunnel != null) {
            val tlsClient = TlsClient(tlsConfig)
            val tlsConn = tlsClient.connect(TunneledTransport(tunnel))
            this.tlsClient = tlsClient
            this.tlsConnection = tlsConn
            return performTlsHandshake(command, destinationHost, destinationPort, initialData)
        }

        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val tlsClient = TlsClient(tlsConfig)
                val tlsConn = tlsClient.connect(
                    configuration.serverAddress, configuration.serverPort.toInt()
                )
                this.tlsClient = tlsClient
                this.tlsConnection = tlsConn

                return performTlsHandshake(
                    command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("TLS attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    // =========================================================================
    // TLS Handshake
    // =========================================================================

    /**
     * Performs the VLESS handshake over a TLS connection.
     *
     * Sends the VLESS request header through the TLS tunnel and returns
     * a [VlessConnection] wrapper.
     */
    private suspend fun performTlsHandshake(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        val isVision = isVisionFlow && (command == VlessCommand.TCP || command == VlessCommand.MUX)

        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = if (isVision) VISION_FLOW else null
        )

        if (initialData != null && !isVision) {
            requestData = requestData + initialData
        }

        val tlsConn = tlsConnection
            ?: throw ProxyError.ConnectionFailed("Connection cancelled")
        tlsConn.send(requestData)

        var vlessConnection: VlessConnection = if (command == VlessCommand.UDP) {
            VlessTlsUdpConnection(tlsConn)
        } else {
            VlessTlsConnection(tlsConn)
        }

        if (isVision) {
            // Verify outer TLS is 1.3 (matches Xray-core outbound.go:346-355)
            validateOuterTlsForVision(vlessConnection)?.let { throw it }

            val vision = wrapWithVision(vlessConnection)
            if (initialData != null) {
                vision.send(initialData)
            } else {
                vision.sendEmptyPadding()
            }
            vlessConnection = vision
        }

        return vlessConnection
    }

    // =========================================================================
    // Direct Handshake
    // =========================================================================

    /**
     * Performs the VLESS handshake over a direct NioSocket connection.
     *
     * Sends the VLESS request header and returns a [VlessConnection] wrapper.
     * For Vision flow, the connection is additionally wrapped in [VlessVisionConnection].
     */
    private suspend fun performHandshake(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        val isVision = isVisionFlow && (command == VlessCommand.TCP || command == VlessCommand.MUX)

        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = if (isVision) VISION_FLOW else null
        )

        // For Vision flow, initial data needs separate padding -- don't append to header
        if (initialData != null && !isVision) {
            requestData = requestData + initialData
        }

        val transport: Transport = tunnelTransport ?: connection
            ?: throw ProxyError.ConnectionFailed("Connection cancelled")
        transport.send(requestData)

        var vlessConnection: VlessConnection = if (command == VlessCommand.UDP) {
            VlessDirectUdpConnection(transport)
        } else {
            VlessDirectConnection(transport)
        }

        if (isVision) {
            // Verify outer TLS is 1.3 (matches Xray-core outbound.go:346-355)
            validateOuterTlsForVision(vlessConnection)?.let { throw it }

            val vision = wrapWithVision(vlessConnection)
            if (initialData != null) {
                vision.send(initialData)
            } else {
                vision.sendEmptyPadding()
            }
            vlessConnection = vision
        }

        return vlessConnection
    }

    // =========================================================================
    // Reality Handshake
    // =========================================================================

    /**
     * Performs the VLESS handshake over a Reality connection.
     *
     * Sends the VLESS request header through the Reality tunnel and returns
     * a [VlessConnection] wrapper.
     */
    private suspend fun performRealityHandshake(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): VlessConnection {
        val isVision = isVisionFlow && (command == VlessCommand.TCP || command == VlessCommand.MUX)

        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = if (isVision) VISION_FLOW else null
        )

        if (initialData != null && !isVision) {
            requestData = requestData + initialData
        }

        val realityConn = realityConnection
            ?: throw ProxyError.ConnectionFailed("Connection cancelled")
        realityConn.send(requestData)

        var vlessConnection: VlessConnection = if (command == VlessCommand.UDP) {
            VlessRealityUdpConnection(realityConn)
        } else {
            VlessRealityConnection(realityConn)
        }

        if (isVision) {
            // Verify outer TLS is 1.3 (matches Xray-core outbound.go:346-355)
            validateOuterTlsForVision(vlessConnection)?.let { throw it }

            val vision = wrapWithVision(vlessConnection)
            if (initialData != null) {
                vision.send(initialData)
            } else {
                vision.sendEmptyPadding()
            }
            vlessConnection = vision
        }

        return vlessConnection
    }

    // =========================================================================
    // TLS Version Check
    // =========================================================================

    /**
     * Validates that the outer TLS connection is TLS 1.3 when using Vision flow.
     * Matches Xray-core outbound.go lines 346-355.
     * Returns an error if the check fails, null if OK or not applicable.
     */
    private fun validateOuterTlsForVision(connection: VlessConnection): Exception? {
        val version = connection.outerTlsVersion
            ?: return ProxyError.ProtocolError("Vision requires outer TLS or REALITY transport")  // Reject raw TCP (matching iOS)
        if (version != TlsVersion.TLS13) {
            return ProxyError.ProtocolError("Vision requires outer TLS 1.3, found $version")
        }
        return null
    }

    // =========================================================================
    // Vision Wrapping
    // =========================================================================

    /**
     * Wraps a VLESS connection with the XTLS Vision layer.
     *
     * @param connection The base VLESS connection to wrap.
     * @return A [VlessVisionConnection] wrapping the provided connection.
     */
    private fun wrapWithVision(connection: VlessConnection): VlessVisionConnection {
        val uuidBytes = VlessProtocol.uuidToBytes(configuration.uuid)
        val testseed = configuration.testseed.map { it.toInt() }.toIntArray()
        return VlessVisionConnection(connection, uuidBytes, testseed)
    }
}
