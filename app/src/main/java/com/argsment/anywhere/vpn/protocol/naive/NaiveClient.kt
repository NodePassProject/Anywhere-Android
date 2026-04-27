package com.argsment.anywhere.vpn.protocol.naive

import com.argsment.anywhere.data.model.NaiveProtocol
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.naive.http11.Http11Connection
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2Connection
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2SessionPool
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlin.coroutines.coroutineContext

private val logger = AnywhereLogger("NaiveClient")

/**
 * Client for establishing NaiveProxy connections over HTTP/1.1 or HTTP/2 CONNECT tunnels.
 */
class NaiveClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): ProxyConnection {
        val naiveProtocol = configuration.naiveProtocol
            ?: throw ProxyError.ProtocolError("NaiveProxy protocol variant not configured")

        var lastError: Exception? = null

        for (attempt in 1..MAX_RETRY_ATTEMPTS) {
            if (attempt > 1) {
                delay(RETRY_BASE_DELAY_MS * (attempt - 1))
            }

            try {
                val connection = connectOnce(naiveProtocol, destinationHost, destinationPort)

                if (initialData != null && initialData.isNotEmpty()) {
                    connection.send(initialData)
                }

                return connection
            } catch (e: Exception) {
                lastError = e
                logger.debug("Connect attempt $attempt failed: ${e.message}")
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts exhausted")
    }

    private suspend fun connectOnce(
        naiveProtocol: NaiveProtocol,
        destinationHost: String,
        destinationPort: Int
    ): NaiveProxyConnection {
        val destination = "$destinationHost:$destinationPort"

        val naiveConfig = NaiveConfiguration(
            proxyHost = configuration.serverAddress,
            proxyPort = configuration.serverPort.toInt(),
            username = configuration.naiveUsername,
            password = configuration.naivePassword,
            sni = configuration.tls?.serverName,
            scheme = when (naiveProtocol) {
                NaiveProtocol.HTTP11 -> NaiveConfiguration.NaiveScheme.HTTP11
                NaiveProtocol.HTTP2 -> NaiveConfiguration.NaiveScheme.HTTP2
            }
        )

        val naiveTunnel: NaiveTunnel = when (naiveProtocol) {
            NaiveProtocol.HTTP11 -> {
                val transport = NaiveTlsTransport(
                    host = naiveConfig.proxyHost,
                    port = naiveConfig.proxyPort,
                    sni = naiveConfig.effectiveSNI,
                    alpn = listOf("http/1.1"),
                    tunnel = tunnel
                )
                Http11Tunnel(Http11Connection(transport, naiveConfig, destination))
            }
            NaiveProtocol.HTTP2 -> {
                // Caller scope is only used for proxy-chained (tunnel != null) sessions; pooled
                // sessions use the pool's own scope so they survive caller cancellation
                // (e.g. LatencyTester withTimeoutOrNull or routine TCP-flow close).
                val tunnelScope = CoroutineScope(coroutineContext)
                Http2SessionPool.acquireStream(naiveConfig, destination, tunnelScope, tunnel)
            }
        }

        naiveTunnel.openTunnel()

        return NaiveProxyConnection(naiveTunnel, naiveTunnel.negotiatedPaddingType)
    }
}
