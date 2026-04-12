package com.argsment.anywhere.data.network

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
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
 * and sending a plain HTTP request through the proxy chain.
 *
 * Uses captive.apple.com:80 (plain HTTP) matching the iOS LatencyTester —
 * no destination TLS handshake needed, which avoids certificate issues and
 * reduces test complexity.
 */
object LatencyTester {

    private val logger = AnywhereLogger("LatencyTester")
    private const val TIMEOUT_MS = 10_000L

    /** Latency test endpoint — plain HTTP, matching iOS captive.apple.com:80. */
    private const val LATENCY_HOST = "captive.apple.com"
    private const val LATENCY_PORT = 80

    /** Maximum number of latency tests running at the same time. Matches iOS. */
    private const val MAX_CONCURRENT_TESTS = 6

    suspend fun test(config: ProxyConfiguration): LatencyResult = withContext(Dispatchers.IO) {
        withTimeoutOrNull(TIMEOUT_MS) {
            try {
                performTest(resolveConfig(config))
            } catch (e: CancellationException) {
                throw e
            } catch (e: com.argsment.anywhere.vpn.protocol.tls.TlsError.CertificateValidationFailed) {
                logger.error("Latency test insecure for ${config.name}: ${e.message}")
                LatencyResult.Insecure
            } catch (e: Exception) {
                logger.error("Latency test failed for ${config.name}: ${e.message}")
                LatencyResult.Failed
            }
        } ?: LatencyResult.Failed
    }

    fun testAll(configurations: List<ProxyConfiguration>): Flow<Pair<UUID, LatencyResult>> = channelFlow {
        // Pre-warm DNS cache for all hosts (including chain proxies)
        configurations.forEach { config ->
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }
        }

        // Cap concurrent tests to avoid overwhelming network/proxy. Matches iOS
        // LatencyTester.maxConcurrentTests = 6.
        val semaphore = Semaphore(MAX_CONCURRENT_TESTS)
        for (config in configurations) {
            launch(Dispatchers.IO) {
                semaphore.withPermit {
                    send(config.id to test(config))
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Resolve DNS before connecting to avoid DNS-over-tunnel loop when VPN is active.
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
     * Matching iOS LatencyTester methodology:
     * Phase 1 (untimed): Establish proxy connection (TCP + TLS/Reality + VLESS/SS handshake).
     * Phase 2 (untimed): Warmup request — drains proxy-side buffers.
     * Phase 3 (untimed): Send the timed HTTP request.
     * Phase 4 (timed):   Wait for the response — measures actual network RTT.
     */
    private suspend fun performTest(config: ProxyConfiguration): LatencyResult = coroutineScope {
        val connections = mutableListOf<VlessConnection>()

        // Cancellation watcher: closes connections when this scope is cancelled
        // (e.g., by withTimeoutOrNull). NioSocket.receive() uses suspendCoroutine
        // which is not cancellation-aware, so we must actively close the underlying
        // sockets to unblock pending I/O.
        val watcher = launch {
            try { awaitCancellation() } finally {
                connections.forEach { it.cancel() }
            }
        }

        try {
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }

            // Phase 1 (untimed): Establish proxy connection through chain.
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

            val proxyConnection = ProxyClientFactory.connect(
                config, LATENCY_HOST, LATENCY_PORT, tunnel = tunnelConnection
            )
            connections.add(proxyConnection)

            // Phase 2 (untimed warmup): Drain proxy-side buffers.
            val warmupRequest = "HEAD / HTTP/1.1\r\nHost: $LATENCY_HOST\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            proxyConnection.send(warmupRequest)
            val warmupData = proxyConnection.receive()

            val warmupStatus = warmupData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (warmupStatus == null || !warmupStatus.contains("200")) {
                throw LatencyTestError("Unexpected warmup status: ${warmupStatus ?: "no response"}")
            }

            // Phase 3 (untimed): Send the timed HTTP request.
            val httpRequest = "HEAD / HTTP/1.1\r\nHost: $LATENCY_HOST\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            proxyConnection.send(httpRequest)

            // Phase 4 (timed): Wait for the response.
            val startNs = System.nanoTime()
            val responseData = proxyConnection.receive()
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            val statusLine = responseData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (statusLine == null || !statusLine.contains("200")) {
                throw LatencyTestError("Unexpected status: ${statusLine ?: "no response"}")
            }

            LatencyResult.Success(elapsedMs.toInt())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.error("Latency test failed for ${config.name}: ${e.message}")
            LatencyResult.Failed
        } finally {
            watcher.cancel()
            connections.forEach { it.cancel() }
        }
    }

    private class LatencyTestError(message: String) : Exception(message)
}
