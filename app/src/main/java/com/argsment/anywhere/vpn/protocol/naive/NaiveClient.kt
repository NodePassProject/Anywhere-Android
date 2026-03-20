package com.argsment.anywhere.vpn.protocol.naive

import android.util.Log
import com.argsment.anywhere.data.model.NaiveProtocol
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.naive.http11.Http11Connection
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2Connection
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2SessionPool
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlin.coroutines.coroutineContext

private const val TAG = "NaiveClient"

/**
 * Client for establishing NaiveProxy connections.
 *
 * Supports HTTP/1.1 and HTTP/2 CONNECT tunnels through TLS.
 * Handles retry logic with linear backoff matching the other protocol clients.
 *
 * @param configuration The proxy configuration with naive credentials and protocol variant.
 * @param tunnel Optional existing connection to tunnel through (for proxy chaining).
 */
class NaiveClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: VlessConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    /**
     * Establishes a NaiveProxy connection to the given destination.
     *
     * @param destinationHost The target host to tunnel to.
     * @param destinationPort The target port to tunnel to.
     * @param initialData Optional data to send immediately after connection.
     * @return A [VlessConnection] wrapping the NaiveProxy tunnel.
     */
    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): VlessConnection {
        val naiveProtocol = configuration.naiveProtocol
            ?: throw ProxyError.ProtocolError("NaiveProxy protocol variant not configured")

        var lastError: Exception? = null

        for (attempt in 1..MAX_RETRY_ATTEMPTS) {
            if (attempt > 1) {
                delay(RETRY_BASE_DELAY_MS * (attempt - 1))
            }

            try {
                val connection = connectOnce(naiveProtocol, destinationHost, destinationPort)

                // Send initial data if provided
                if (initialData != null && initialData.isNotEmpty()) {
                    connection.send(initialData)
                }

                return connection
            } catch (e: Exception) {
                lastError = e
                Log.w(TAG, "Connect attempt $attempt failed: ${e.message}")
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
                // HTTP/2 stream multiplexing: multiple CONNECT tunnels share one TLS connection
                val scope = CoroutineScope(coroutineContext)
                Http2SessionPool.acquireStream(naiveConfig, destination, scope, tunnel)
            }
        }

        // Open the CONNECT tunnel
        naiveTunnel.openTunnel()

        return NaiveProxyConnection(naiveTunnel, naiveTunnel.negotiatedPaddingType)
    }
}
