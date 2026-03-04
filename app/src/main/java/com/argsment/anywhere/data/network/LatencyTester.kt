package com.argsment.anywhere.data.network

import android.util.Log
import com.argsment.anywhere.data.model.VlessConfiguration
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.util.UUID

sealed class LatencyResult {
    data object Testing : LatencyResult()
    data class Success(val ms: Int) : LatencyResult()
    data object Failed : LatencyResult()
}

object LatencyTester {

    private const val TAG = "LatencyTester"
    private const val TIMEOUT_MS = 10_000L

    suspend fun test(config: VlessConfiguration): LatencyResult {
        return withTimeoutOrNull(TIMEOUT_MS) {
            runCatching { performTest(config) }.getOrElse {
                Log.d(TAG, "Latency test failed for ${config.name}: ${it.message}")
                LatencyResult.Failed
            }
        } ?: LatencyResult.Failed
    }

    fun testAll(configurations: List<VlessConfiguration>): Flow<Pair<UUID, LatencyResult>> = flow {
        val batches = configurations.chunked(3)
        for (batch in batches) {
            coroutineScope {
                val results = batch.map { config ->
                    async { config.id to test(config) }
                }.awaitAll()
                for (result in results) {
                    emit(result)
                }
            }
        }
    }

    private fun performTest(config: VlessConfiguration): LatencyResult {
        val address = config.connectAddress
        val port = config.serverPort.toInt()

        val channel = SocketChannel.open()
        channel.configureBlocking(false)

        try {
            val startMs = System.nanoTime()
            channel.connect(InetSocketAddress(address, port))

            // Wait for connection (poll with 50ms intervals)
            val deadline = System.currentTimeMillis() + TIMEOUT_MS
            while (!channel.finishConnect()) {
                if (System.currentTimeMillis() > deadline) return LatencyResult.Failed
                Thread.sleep(50)
            }

            val elapsed = (System.nanoTime() - startMs) / 1_000_000
            return LatencyResult.Success(elapsed.toInt())
        } catch (e: Exception) {
            Log.d(TAG, "TCP connect failed for ${config.name}: ${e.message}")
            return LatencyResult.Failed
        } finally {
            runCatching { channel.close() }
        }
    }
}
