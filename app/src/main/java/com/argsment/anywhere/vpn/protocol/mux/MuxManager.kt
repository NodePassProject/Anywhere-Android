package com.argsment.anywhere.vpn.protocol.mux

import com.argsment.anywhere.data.model.ProxyConfiguration
import kotlin.coroutines.CoroutineContext

/**
 * Pool of [MuxClient] instances. Dispatches sessions to non-full clients and
 * creates new clients on demand.
 */
class MuxManager(
    val configuration: ProxyConfiguration,
    private val coroutineContext: CoroutineContext
) {
    private val clients = mutableListOf<MuxClient>()

    suspend fun dispatch(
        network: MuxNetwork,
        host: String,
        port: Int,
        globalID: ByteArray?
    ): MuxSession {
        clients.removeAll { it.closed }

        val existing = clients.firstOrNull { !it.isFull }
        if (existing != null) {
            return existing.createSession(network, host, port, globalID)
        }

        val client = MuxClient(configuration, coroutineContext)
        clients.add(client)

        return client.createSession(network, host, port, globalID)
    }

    fun closeAll() {
        for (client in clients) {
            client.closeAll()
        }
        clients.clear()
    }
}
