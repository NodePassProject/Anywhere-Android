package com.argsment.anywhere.data.network

import android.util.Log
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.tls.TlsError
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException

sealed class LatencyResult {
    data object Testing : LatencyResult()
    data class Success(val ms: Int) : LatencyResult()
    data object Insecure : LatencyResult()
    data object Failed : LatencyResult()
}

/**
 * Tests full proxy round-trip latency by establishing a proxy connection
 * and sending an HTTP request through the proxy chain.
 *
 * Connects to the test endpoint through the full proxy chain, sends a
 * warmup request (to drain proxy-side buffers), then measures the
 * receive-only RTT of a second request — matching the iOS LatencyTester
 * timing methodology.
 */
object LatencyTester {

    private const val TAG = "LatencyTester"
    private const val TIMEOUT_MS = 10_000L

    /** Latency test endpoint. */
    private const val LATENCY_HOST = "www.gstatic.com"
    private const val LATENCY_PORT = 80

    suspend fun test(config: ProxyConfiguration): LatencyResult = withContext(Dispatchers.IO) {
        try {
            withTimeoutOrNull(TIMEOUT_MS) {
                try {
                    performTest(resolveConfig(config))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.d(TAG, "Latency test failed for ${config.name}: ${e.message}")
                    LatencyResult.Failed
                }
            } ?: LatencyResult.Failed
        } catch (e: TlsError.CertificateValidationFailed) {
            Log.d(TAG, "Latency test insecure for ${config.name}: ${e.message}")
            LatencyResult.Insecure
        }
    }

    fun testAll(configurations: List<ProxyConfiguration>): Flow<Pair<UUID, LatencyResult>> = channelFlow {
        // Pre-warm DNS cache for all hosts (including chain proxies)
        configurations.forEach { config ->
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }
        }

        // Run all tests concurrently, emitting each result as it completes
        // (matching iOS `for await pair in group { continuation.yield(pair) }`)
        for (config in configurations) {
            launch(Dispatchers.IO) {
                send(config.id to test(config))
            }
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Resolve DNS before connecting to avoid DNS-over-tunnel loop when VPN is active.
     * Uses [DnsCache] for efficient cached resolution. Also resolves chain proxy addresses.
     */
    private fun resolveConfig(config: ProxyConfiguration): ProxyConfiguration {
        val resolvedConfig = resolveAddress(config)
        val resolvedChain = config.chain?.map { resolveAddress(it) }
        return if (resolvedChain != null) resolvedConfig.copy(chain = resolvedChain) else resolvedConfig
    }

    private fun resolveAddress(config: ProxyConfiguration): ProxyConfiguration {
        if (config.resolvedIP != null) return config

        val address = config.serverAddress
        if (DnsCache.isIpAddress(address)) return config

        val resolved = DnsCache.resolveHost(address) ?: return config
        return config.copy(resolvedIP = resolved)
    }

    /**
     * Establishes a proxy connection and measures HTTP round-trip latency.
     *
     * Phase 1 (untimed): Establish proxy connection (TCP + proxy handshake).
     * Phase 2 (untimed): Warmup request — establishes the proxy-to-destination
     *                     TCP connection and drains any proxy-side buffers.
     * Phase 3 (untimed): Send the timed HTTP request.
     * Phase 4 (timed):   Wait for the response — measures actual network RTT:
     *                     client -> proxy chain -> destination -> back.
     */
    private suspend fun performTest(config: ProxyConfiguration): LatencyResult {
        val connections = mutableListOf<VlessConnection>()
        try {
            // Pre-warm DNS cache so resolution is excluded from timing
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }

            // Phase 1 (untimed): Establish proxy connection.
            var tunnelConnection: VlessConnection? = null

            val chain = config.chain
            if (!chain.isNullOrEmpty()) {
                for (i in chain.indices) {
                    val hopConfig = chain[i]
                    val nextConfig = if (i + 1 < chain.size) chain[i + 1] else config
                    tunnelConnection = ProxyClientFactory.connect(
                        hopConfig,
                        nextConfig.connectAddress,
                        nextConfig.serverPort.toInt(),
                        tunnel = tunnelConnection
                    )
                    connections.add(tunnelConnection)
                }
            }

            val connection = ProxyClientFactory.connect(
                config, LATENCY_HOST, LATENCY_PORT, tunnel = tunnelConnection
            )
            connections.add(connection)

            // Phase 2 (untimed warmup): Send a first request to establish the
            // proxy-to-destination connection and drain any proxy-side buffers.
            val warmupRequest = "HEAD /generate_204 HTTP/1.1\r\nHost: $LATENCY_HOST\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            connection.send(warmupRequest)
            val warmupData = connection.receive()

            // Validate warmup response
            val warmupStatus = warmupData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (warmupStatus == null || !warmupStatus.contains("204")) {
                throw LatencyTestError("Unexpected warmup status: ${warmupStatus ?: "no response"}")
            }

            // Phase 3 (untimed): Send the timed HTTP request.
            val httpRequest = "HEAD /generate_204 HTTP/1.1\r\nHost: $LATENCY_HOST\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            connection.send(httpRequest)

            // Phase 4 (timed): Wait for the response.
            // Timer starts after send completes — measures the actual network
            // round-trip: data traverses client -> proxy chain -> target -> back.
            val startNs = System.nanoTime()
            val responseData = connection.receive()
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            // Validate HTTP 204 response
            val statusLine = responseData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (statusLine == null || !statusLine.contains("204")) {
                throw LatencyTestError("Unexpected status: ${statusLine ?: "no response"}")
            }

            return LatencyResult.Success(elapsedMs.toInt())
        } catch (e: TlsError.CertificateValidationFailed) {
            Log.d(TAG, "Latency test insecure for ${config.name}: ${e.message}")
            return LatencyResult.Insecure
        } catch (e: Exception) {
            Log.d(TAG, "Latency test failed for ${config.name}: ${e.message}")
            return LatencyResult.Failed
        } finally {
            connections.forEach { it.cancel() }
        }
    }

    private class LatencyTestError(message: String) : Exception(message)
}
