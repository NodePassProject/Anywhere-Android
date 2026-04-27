package com.argsment.anywhere.vpn.protocol.naive.http2

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

private val logger = AnywhereLogger("HTTP2Pool")

/**
 * Pool that lets multiple CONNECT tunnels to the same server share a single TLS
 * connection via HTTP/2 stream multiplexing. Sessions are keyed by `"host:port:sni"`.
 *
 * Pooled sessions run on [poolScope] (not the first caller's scope) so the persistent
 * read loop is not torn down by caller cancellation — e.g. `LatencyTester`'s
 * `withTimeoutOrNull` or a routine TCP-connection close would otherwise kill the
 * shared session and break every other multiplexed tunnel.
 */
object Http2SessionPool {

    private val sessions = mutableMapOf<String, MutableList<Http2Session>>()

    private val poolScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Acquires an [Http2Stream] for [destination]. When [tunnel] is non-null
     * (proxy chaining), a dedicated session is created on [tunnelScope] (not pooled)
     * since its lifetime is bounded by the outer tunnel.
     */
    suspend fun acquireStream(
        config: NaiveConfiguration,
        destination: String,
        tunnelScope: CoroutineScope,
        tunnel: ProxyConnection? = null
    ): Http2Stream {
        if (tunnel != null) {
            val session = Http2Session(config, tunnelScope, tunnel)
            return session.acquireStream(destination)
        }

        val key = "${config.proxyHost}:${config.proxyPort}:${config.effectiveSNI}"

        // Loop: an existing READY session may race-fill (lose its slot to a
        // concurrent caller) between hasCapacity check and tryReserveStream.
        // tryReserveStream returns null on race; we reset and try again.
        while (true) {
            val (session, isNew) = synchronized(this) {
                sessions[key]?.removeAll { it.isClosed }

                val existing = sessions[key]?.firstOrNull { it.hasCapacity }
                if (existing != null) {
                    return@synchronized existing to false
                }

                val newSession = Http2Session(config, poolScope)
                newSession.onClose = {
                    synchronized(this) {
                        sessions[key]?.remove(newSession)
                        if (sessions[key]?.isEmpty() == true) {
                            sessions.remove(key)
                        }
                    }
                }
                sessions.getOrPut(key) { mutableListOf() }.add(newSession)
                newSession to true
            }

            if (isNew) {
                // First call ensures handshake completes, then reserves slot.
                return session.acquireStream(destination)
            }

            // Existing session: atomic reservation. Null = lost race; retry.
            session.tryReserveStream(destination)?.let { return it }
        }
    }

    fun closeAll() {
        val allSessions: List<Http2Session>
        synchronized(this) {
            allSessions = sessions.values.flatten()
            sessions.clear()
        }
        for (session in allSessions) {
            try {
                session.onClose = null // Prevent re-entrant eviction.
                session.close()
            } catch (e: Exception) {
                logger.warning("Error closing session: ${e.message}")
            }
        }
    }
}
