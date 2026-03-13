package com.argsment.anywhere.data.network

import android.util.Log
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.tls.TlsError
import com.argsment.anywhere.vpn.protocol.vless.VlessClient
import com.argsment.anywhere.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
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
 * Tests proxy latency by establishing a full VLESS connection and
 * sending an HTTP request through the proxy chain.
 *
 * Measures only the HTTP round-trip time through the established VLESS
 * tunnel, excluding connection setup.
 */
object LatencyTester {

    private const val TAG = "LatencyTester"
    private const val TIMEOUT_MS = 10_000L

    suspend fun test(config: ProxyConfiguration): LatencyResult = withContext(Dispatchers.IO) {
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
    }

    fun testAll(configurations: List<ProxyConfiguration>): Flow<Pair<UUID, LatencyResult>> = flow {
        // Pre-warm DNS cache for all hosts (including chain proxies)
        configurations.forEach { config ->
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }
        }

        // Run all tests concurrently (no batching)
        coroutineScope {
            val results = configurations.map { config ->
                async(Dispatchers.IO) { config.id to test(config) }
            }.awaitAll()
            for (result in results) {
                emit(result)
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
     * Establishes a VLESS connection (optionally through a chain) and measures
     * HTTP round-trip latency.
     *
     * Phase 1 (not timed): Build chain connections (if any), then connect to test target.
     * Phase 2 (timed): Send HTTP HEAD request and wait for response.
     */
    private suspend fun performTest(config: ProxyConfiguration): LatencyResult {
        val clients = mutableListOf<VlessClient>()
        try {
            // Phase 1: Build connection chain and connect to test target (not timed)
            var tunnelConnection: com.argsment.anywhere.vpn.protocol.vless.VlessConnection? = null

            val chain = config.chain
            if (!chain.isNullOrEmpty()) {
                // Build chain: each hop tunnels through the previous
                for (i in chain.indices) {
                    val hopConfig = chain[i]
                    val nextConfig = if (i + 1 < chain.size) chain[i + 1] else config
                    val hopClient = VlessClient(hopConfig, tunnel = tunnelConnection)
                    clients.add(hopClient)
                    tunnelConnection = hopClient.connect(
                        nextConfig.connectAddress,
                        nextConfig.serverPort.toInt()
                    )
                }
            }

            val exitClient = VlessClient(config, tunnel = tunnelConnection)
            clients.add(exitClient)
            val connection = exitClient.connect("www.gstatic.com", 80)

            // Phase 2: Send HTTP request and measure round-trip (timed)
            val httpRequest = "HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)

            val startNs = System.nanoTime()
            connection.send(httpRequest)
            connection.receive()
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            return LatencyResult.Success(elapsedMs.toInt())
        } catch (e: TlsError.CertificateValidationFailed) {
            Log.d(TAG, "Latency test insecure for ${config.name}: ${e.message}")
            return LatencyResult.Insecure
        } catch (e: Exception) {
            Log.d(TAG, "Latency test failed for ${config.name}: ${e.message}")
            return LatencyResult.Failed
        } finally {
            clients.forEach { it.cancel() }
        }
    }
}
