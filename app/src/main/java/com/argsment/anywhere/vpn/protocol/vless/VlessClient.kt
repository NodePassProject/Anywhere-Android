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
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.grpc.GrpcClient
import com.argsment.anywhere.vpn.protocol.grpc.GrpcConfiguration
import com.argsment.anywhere.vpn.protocol.grpc.GrpcConnection
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
 * Client for establishing VLESS proxy connections over TCP or UDP. Supports
 * TCP / WebSocket / HTTP Upgrade / XHTTP transports, None / TLS / Reality
 * security, and None / Vision flow.
 */
class VlessClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
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
    private var grpcConnection: GrpcConnection? = null

    companion object {
        /** Linear backoff: 0, 200, 400, 600, 800 ms across 5 attempts. */
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L

        /** Base Vision flow string sent on the wire (suffix stripped). */
        private const val VISION_FLOW = "xtls-rprx-vision"
    }

    private val isVisionFlow: Boolean
        get() = configuration.flow == VISION_FLOW || configuration.flow == "$VISION_FLOW-udp443"

    /** Whether UDP port 443 is allowed (only with the `-udp443` flow suffix). */
    private val allowUDP443: Boolean
        get() = configuration.flow == "$VISION_FLOW-udp443"

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): ProxyConnection {
        return connectWithCommand(
            command = VlessCommand.TCP,
            destinationHost = destinationHost,
            destinationPort = destinationPort,
            initialData = initialData
        )
    }

    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): ProxyConnection {
        return connectWithCommand(
            command = VlessCommand.UDP,
            destinationHost = destinationHost,
            destinationPort = destinationPort,
            initialData = null
        )
    }

    /**
     * Connects a mux control channel: command=MUX with destination "v1.mux.cool:666".
     * When Vision flow is active, the mux connection is wrapped with Vision.
     */
    suspend fun connectMux(): ProxyConnection {
        return connectWithCommand(
            command = VlessCommand.MUX,
            destinationHost = "v1.mux.cool",
            destinationPort = 666,
            initialData = null
        )
    }

    private fun cleanupRetryResources() {
        grpcConnection?.cancel()
        grpcConnection = null
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

    fun cancel() {
        grpcConnection?.cancel()
        grpcConnection = null
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

    private suspend fun buildUploadTunnel(): ProxyConnection {
        val chain = configuration.chain
        if (chain.isNullOrEmpty()) {
            return tunnel ?: throw ProxyError.ConnectionFailed("Missing upload tunnel")
        }

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

        return previousConnection
            ?: throw ProxyError.ConnectionFailed("Failed to build upload tunnel")
    }

    private suspend fun connectWithCommand(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        // Vision silently drops UDP/443 unless the -udp443 flow variant is configured.
        if (command == VlessCommand.UDP && destinationPort == 443 && isVisionFlow && !allowUDP443) {
            throw ProxyError.Dropped()
        }

        return when (configuration.transport) {
            "ws" -> {
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over WebSocket transport")
                }
                connectWithWebSocket(command, destinationHost, destinationPort, initialData)
            }

            "httpupgrade" -> {
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over HTTP upgrade transport")
                }
                connectWithHttpUpgrade(command, destinationHost, destinationPort, initialData)
            }

            "xhttp" -> {
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over XHTTP transport")
                }
                connectWithXHttp(command, destinationHost, destinationPort, initialData)
            }

            "grpc" -> {
                if (isVisionFlow) {
                    throw ProxyError.ProtocolError("Vision flow is not supported over gRPC transport")
                }
                connectWithGrpc(command, destinationHost, destinationPort, initialData)
            }

            else -> {
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

    private suspend fun connectWithWebSocket(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        val wsConfig = configuration.websocket
            ?: throw ProxyError.ConnectionFailed("WebSocket transport specified but no WebSocket configuration")

        return if (configuration.tls != null) {
            connectWssWithRetry(wsConfig, command, destinationHost, destinationPort, initialData)
        } else {
            connectWsWithRetry(wsConfig, command, destinationHost, destinationPort, initialData)
        }
    }

    private suspend fun connectWsWithRetry(
        wsConfig: WebSocketConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

    private suspend fun connectWssWithRetry(
        wsConfig: WebSocketConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

                // Force ALPN to http/1.1; HTTP/2 negotiation would break the
                // WebSocket upgrade handshake.
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

    private suspend fun performWebSocketHandshake(
        wsConnection: WebSocketConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        wsConnection.send(requestData)

        val baseConn = VlessWebSocketConnection(wsConnection)
        return if (command == VlessCommand.UDP) {
            VlessUdpConnection(baseConn)
        } else {
            baseConn
        }
    }

    private suspend fun connectWithHttpUpgrade(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        val huConfig = configuration.httpUpgrade
            ?: throw ProxyError.ConnectionFailed("HTTP upgrade transport specified but no configuration")

        return if (configuration.tls != null) {
            connectHttpsUpgradeWithRetry(huConfig, command, destinationHost, destinationPort, initialData)
        } else {
            connectHttpUpgradeWithRetry(huConfig, command, destinationHost, destinationPort, initialData)
        }
    }

    private suspend fun connectHttpUpgradeWithRetry(
        huConfig: HttpUpgradeConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

    private suspend fun connectHttpsUpgradeWithRetry(
        huConfig: HttpUpgradeConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

    private suspend fun performHttpUpgradeHandshake(
        huConnection: HttpUpgradeConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        huConnection.send(requestData)

        val baseConn = VlessHttpUpgradeConnection(huConnection)
        return if (command == VlessCommand.UDP) {
            VlessUdpConnection(baseConn)
        } else {
            baseConn
        }
    }

    /**
     * HTTP version selection for XHTTP:
     * - Reality always uses HTTP/2.
     * - No TLS means plain HTTP/1.1.
     * - TLS with a single "http/1.1" ALPN stays on HTTP/1.1.
     * - TLS with a single "h3" ALPN requires QUIC/HTTP/3 and is rejected.
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
     * Sanitizes TLS ALPN for XHTTP-over-TCP handshakes so only TCP-compatible
     * ALPN values are advertised.
     */
    private fun sanitizedXHttpTlsConfig(
        base: TlsConfiguration,
        httpVersion: XHttpHttpVersion
    ): TlsConfiguration {
        val sanitizedAlpn: List<String>? = when (httpVersion) {
            XHttpHttpVersion.HTTP11 -> listOf("http/1.1")
            XHttpHttpVersion.HTTP3 -> listOf("h3")
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
    ): ProxyConnection {
        val xhttpConfig = configuration.xhttp
            ?: throw ProxyError.ConnectionFailed("XHTTP transport specified but no XHTTP configuration")

        val httpVersion = decideXHttpHttpVersion()
        if (httpVersion == XHttpHttpVersion.HTTP3) {
            throw ProxyError.ConnectionFailed(
                "XHTTP over TLS with ALPN h3 requires QUIC/HTTP/3, which is not implemented"
            )
        }
        val useHTTP2 = httpVersion == XHttpHttpVersion.HTTP2

        val resolvedMode: XHttpMode = if (xhttpConfig.mode == XHttpMode.AUTO) {
            // Reality -> stream-one (direct, HTTP/2); TLS/none -> packet-up (CDN-safe).
            if (configuration.reality != null) XHttpMode.STREAM_ONE else XHttpMode.PACKET_UP
        } else {
            xhttpConfig.mode
        }

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

    private suspend fun connectXHttpWithRetry(
        xhttpConfig: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
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

    private suspend fun connectXHttpsWithRetry(
        xhttpConfig: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        useHTTP2: Boolean,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

    private suspend fun connectXHttpRealityWithRetry(
        realityConfig: RealityConfiguration,
        xhttpConfig: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

                // Reality + xhttp requires HTTP/2.
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

    private suspend fun performXHttpHandshake(
        xhttpConnection: XHttpConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        xhttpConnection.send(requestData)

        val baseConn = VlessXHttpConnection(xhttpConnection)
        return if (command == VlessCommand.UDP) {
            VlessUdpConnection(baseConn)
        } else {
            baseConn
        }
    }

    private suspend fun connectDirect(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        // Tunneled connections reuse the existing tunnel — no NioSocket, no retries.
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

    private suspend fun connectWithReality(
        realityConfig: RealityConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

    private suspend fun connectWithTls(
        tlsConfig: TlsConfiguration,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        // Tunneled: TLS handshake over the existing tunnel — no retries.
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

    private suspend fun performTlsHandshake(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

        val baseConn = VlessTlsConnection(tlsConn)

        if (command == VlessCommand.UDP) {
            return VlessUdpConnection(baseConn)
        }

        if (isVision) {
            // Vision requires outer TLS 1.3.
            validateOuterTlsForVision(baseConn)?.let { throw it }

            val vision = wrapWithVision(baseConn)
            if (initialData != null) {
                vision.send(initialData)
            } else {
                vision.sendEmptyPadding()
            }
            return vision
        }

        return baseConn
    }

    private suspend fun performHandshake(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        val isVision = isVisionFlow && (command == VlessCommand.TCP || command == VlessCommand.MUX)

        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = if (isVision) VISION_FLOW else null
        )

        // Vision needs initialData passed through its own padding path; don't append to header.
        if (initialData != null && !isVision) {
            requestData = requestData + initialData
        }

        val transport: Transport = tunnelTransport ?: connection
            ?: throw ProxyError.ConnectionFailed("Connection cancelled")
        transport.send(requestData)

        val baseConn = VlessDirectConnection(transport)

        if (command == VlessCommand.UDP) {
            return VlessUdpConnection(baseConn)
        }

        if (isVision) {
            // Vision requires outer TLS 1.3.
            validateOuterTlsForVision(baseConn)?.let { throw it }

            val vision = wrapWithVision(baseConn)
            if (initialData != null) {
                vision.send(initialData)
            } else {
                vision.sendEmptyPadding()
            }
            return vision
        }

        return baseConn
    }

    private suspend fun performRealityHandshake(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
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

        val baseConn = VlessRealityConnection(realityConn)

        if (command == VlessCommand.UDP) {
            return VlessUdpConnection(baseConn)
        }

        if (isVision) {
            // Vision requires outer TLS 1.3.
            validateOuterTlsForVision(baseConn)?.let { throw it }

            val vision = wrapWithVision(baseConn)
            if (initialData != null) {
                vision.send(initialData)
            } else {
                vision.sendEmptyPadding()
            }
            return vision
        }

        return baseConn
    }

    /**
     * Vision requires outer TLS 1.3 — rejects raw TCP and lower TLS versions.
     */
    private fun validateOuterTlsForVision(connection: ProxyConnection): Exception? {
        val version = connection.outerTlsVersion
            ?: return ProxyError.ProtocolError("Vision requires outer TLS or REALITY transport")
        if (version != TlsVersion.TLS13) {
            return ProxyError.ProtocolError("Vision requires outer TLS 1.3, found $version")
        }
        return null
    }

    private fun wrapWithVision(connection: VlessConnection): VlessVisionConnection {
        val uuidBytes = VlessProtocol.uuidToBytes(configuration.uuid)
        val testseed = configuration.testseed.map { it.toInt() }.toIntArray()
        return VlessVisionConnection(connection, uuidBytes, testseed)
    }

    /**
     * gRPC transport (bidirectional HTTP/2 stream). Routes through Reality, TLS,
     * or plain TCP; TLS connections force ALPN to `h2`.
     */
    private suspend fun connectWithGrpc(
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        val grpcConfig = configuration.grpc
            ?: throw ProxyError.ConnectionFailed("gRPC transport specified but no gRPC configuration")

        val authority = GrpcClient.resolveAuthority(grpcConfig, configuration)

        return when {
            configuration.reality != null -> connectGrpcRealityWithRetry(
                configuration.reality, grpcConfig, authority,
                command, destinationHost, destinationPort, initialData
            )

            configuration.tls != null -> connectGrpcsWithRetry(
                configuration.tls, grpcConfig, authority,
                command, destinationHost, destinationPort, initialData
            )

            else -> connectGrpcPlainWithRetry(
                grpcConfig, authority,
                command, destinationHost, destinationPort, initialData
            )
        }
    }

    private suspend fun connectGrpcPlainWithRetry(
        grpcConfig: GrpcConfiguration,
        authority: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                val grpcConn = if (tunnel != null) {
                    GrpcConnection(requireTunnelTransport(), grpcConfig, authority)
                } else {
                    val socket = NioSocket()
                    this.connection = socket
                    socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
                    GrpcConnection(socket, grpcConfig, authority)
                }
                this.grpcConnection = grpcConn

                grpcConn.performSetup()

                return performGrpcHandshake(
                    grpcConn, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("gRPC attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    private suspend fun connectGrpcsWithRetry(
        baseTlsConfig: TlsConfiguration,
        grpcConfig: GrpcConfiguration,
        authority: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                // gRPC requires HTTP/2 — force ALPN to h2.
                val tlsConfig = GrpcClient.sanitizedTlsConfiguration(baseTlsConfig)
                val tlsClient = TlsClient(tlsConfig)
                val tlsConn = if (tunnel != null) {
                    tlsClient.connect(requireTunnelTransport())
                } else {
                    tlsClient.connect(configuration.serverAddress, configuration.serverPort.toInt())
                }
                this.tlsClient = tlsClient
                this.tlsConnection = tlsConn

                val grpcConn = GrpcConnection(tlsConn, grpcConfig, authority)
                this.grpcConnection = grpcConn

                grpcConn.performSetup()

                return performGrpcHandshake(
                    grpcConn, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("gRPC+TLS attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    private suspend fun connectGrpcRealityWithRetry(
        realityConfig: RealityConfiguration,
        grpcConfig: GrpcConfiguration,
        authority: String,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var lastError: Exception? = null

        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }

            try {
                // Reality handles its own ALPN internally.
                val realityClientLocal = RealityClient(realityConfig)
                val realityConn = if (tunnel != null) {
                    realityClientLocal.connect(requireTunnelTransport())
                } else {
                    realityClientLocal.connect(
                        configuration.serverAddress, configuration.serverPort.toInt()
                    )
                }
                this.realityClient = realityClientLocal
                this.realityConnection = realityConn

                val grpcConn = GrpcConnection(realityConn, grpcConfig, authority)
                this.grpcConnection = grpcConn

                grpcConn.performSetup()

                return performGrpcHandshake(
                    grpcConn, command, destinationHost, destinationPort, initialData
                )
            } catch (e: Exception) {
                logger.debug("gRPC+Reality attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                if (e is TlsError.CertificateValidationFailed) throw e
                lastError = e
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    private suspend fun performGrpcHandshake(
        grpcConn: GrpcConnection,
        command: VlessCommand,
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        var requestData = VlessProtocol.encodeRequestHeader(
            uuid = configuration.uuid,
            command = command,
            destinationAddress = destinationHost,
            destinationPort = destinationPort,
            flow = null
        )

        if (initialData != null) {
            requestData = requestData + initialData
        }

        grpcConn.send(requestData)

        val baseConn = VlessGrpcConnection(grpcConn)
        return if (command == VlessCommand.UDP) {
            VlessUdpConnection(baseConn)
        } else {
            baseConn
        }
    }
}
