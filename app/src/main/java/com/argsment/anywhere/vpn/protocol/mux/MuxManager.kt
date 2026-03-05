package com.argsment.anywhere.vpn.protocol.mux

import com.argsment.anywhere.data.model.VlessConfiguration
import kotlin.coroutines.CoroutineContext

/**
 * Manages a pool of MuxClient instances.
 * Dispatches sessions to non-full clients, creates new clients as needed.
 */
class MuxManager(
    val configuration: VlessConfiguration,
    private val coroutineContext: CoroutineContext
) {
    private val clients = mutableListOf<MuxClient>()

    /**
     * Dispatches a new session to a non-full MuxClient, creating one if needed.
     */
    suspend fun dispatch(
        network: MuxNetwork,
        host: String,
        port: Int,
        globalID: ByteArray?
    ): MuxSession {
        // Remove dead clients
        clients.removeAll { it.closed }

        // Find a non-full client
        val existing = clients.firstOrNull { !it.isFull }
        if (existing != null) {
            return existing.createSession(network, host, port, globalID)
        }

        // Create a new client
        val client = MuxClient(configuration, coroutineContext)
        clients.add(client)

        return client.createSession(network, host, port, globalID)
    }

    /**
     * Closes all clients and their sessions.
     */
    fun closeAll() {
        for (client in clients) {
            client.closeAll()
        }
        clients.clear()
    }
}
