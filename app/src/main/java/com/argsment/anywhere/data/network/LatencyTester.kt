package com.argsment.anywhere.data.network

import android.util.Log
import com.argsment.anywhere.data.model.VlessConfiguration
import com.argsment.anywhere.vpn.protocol.vless.VlessClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet4Address
import java.net.InetAddress
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException

sealed class LatencyResult {
    data object Testing : LatencyResult()
    data class Success(val ms: Int) : LatencyResult()
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

    suspend fun test(config: VlessConfiguration): LatencyResult = withContext(Dispatchers.IO) {
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

    fun testAll(configurations: List<VlessConfiguration>): Flow<Pair<UUID, LatencyResult>> = flow {
        val batches = configurations.chunked(3)
        for (batch in batches) {
            coroutineScope {
                val results = batch.map { config ->
                    async(Dispatchers.IO) { config.id to test(config) }
                }.awaitAll()
                for (result in results) {
                    emit(result)
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Resolve DNS before connecting to avoid DNS-over-tunnel loop when VPN is active.
     */
    private fun resolveConfig(config: VlessConfiguration): VlessConfiguration {
        if (config.resolvedIP != null) return config

        val address = config.serverAddress
        try {
            val addr = InetAddress.getByName(address)
            if (addr.hostAddress == address) return config
        } catch (_: Exception) {}

        return try {
            val all = InetAddress.getAllByName(address)
            val resolved = all.firstOrNull { it is Inet4Address } ?: all.firstOrNull()
            config.copy(resolvedIP = resolved?.hostAddress ?: address)
        } catch (_: Exception) {
            config
        }
    }

    /**
     * Establishes a VLESS connection and measures HTTP round-trip latency.
     *
     * Phase 1 (not timed): TCP + TLS/Reality + VLESS handshake to proxy server,
     * requesting connection to www.gstatic.com:80.
     *
     * Phase 2 (timed): Send HTTP HEAD request and wait for response through
     * the established VLESS tunnel.
     */
    private suspend fun performTest(config: VlessConfiguration): LatencyResult {
        val client = VlessClient(config)
        try {
            // Phase 1: Establish VLESS connection (not timed)
            val connection = client.connect("www.gstatic.com", 80)

            // Phase 2: Send HTTP request and measure round-trip (timed)
            val httpRequest = "HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)

            val startNs = System.nanoTime()
            connection.send(httpRequest)
            connection.receive()
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            return LatencyResult.Success(elapsedMs.toInt())
        } catch (e: Exception) {
            Log.d(TAG, "VLESS latency test failed for ${config.name}: ${e.message}")
            return LatencyResult.Failed
        } finally {
            client.cancel()
        }
    }
}
