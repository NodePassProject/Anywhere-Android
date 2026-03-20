package com.argsment.anywhere.vpn.protocol.naive.http2

import android.util.Log
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import kotlinx.coroutines.CoroutineScope

private const val TAG = "Http2SessionPool"

/**
 * Singleton pool for HTTP/2 session reuse.
 *
 * Multiple CONNECT tunnels to the same proxy server share a single TLS connection
 * via HTTP/2 stream multiplexing, matching browser behavior and the iOS implementation.
 *
 * Sessions are keyed by `"$host:$port:$sni"` derived from [NaiveConfiguration].
 * When a tunnel is provided (proxy chaining), a dedicated session is created (not pooled).
 */
object Http2SessionPool {

    /** Pooled sessions keyed by "$host:$port:$sni". */
    private val sessions = mutableMapOf<String, MutableList<Http2Session>>()

    /**
     * Acquires an [Http2Stream] for a CONNECT tunnel to [destination].
     *
     * @param config Proxy configuration (host, port, auth, SNI).
     * @param destination Target "host:port" for the CONNECT tunnel.
     * @param scope Coroutine scope for the session's read loop.
     * @param tunnel Optional tunnel for proxy chaining (creates a dedicated, non-pooled session).
     */
    suspend fun acquireStream(
        config: NaiveConfiguration,
        destination: String,
        scope: CoroutineScope,
        tunnel: VlessConnection? = null
    ): Http2Stream {
        // Tunneled connections get dedicated sessions (not pooled)
        if (tunnel != null) {
            val session = Http2Session(config, scope, tunnel)
            return session.acquireStream(destination)
        }

        val key = "${config.proxyHost}:${config.proxyPort}:${config.effectiveSNI}"

        val session = synchronized(this) {
            // Evict closed sessions
            sessions[key]?.removeAll { it.isClosed }

            // Find existing session with capacity
            val existing = sessions[key]?.firstOrNull { it.hasCapacity }
            if (existing != null) return@synchronized existing

            // Create new session with eviction callback
            val newSession = Http2Session(config, scope)
            newSession.onClose = {
                synchronized(this) {
                    sessions[key]?.remove(newSession)
                    if (sessions[key]?.isEmpty() == true) {
                        sessions.remove(key)
                    }
                }
            }
            sessions.getOrPut(key) { mutableListOf() }.add(newSession)
            newSession
        }

        return session.acquireStream(destination)
    }

    /**
     * Closes all pooled sessions. Called from [LwipStack.shutdownInternal].
     */
    fun closeAll() {
        val allSessions: List<Http2Session>
        synchronized(this) {
            allSessions = sessions.values.flatten()
            sessions.clear()
        }
        for (session in allSessions) {
            try {
                session.onClose = null // Prevent re-entrant eviction
                session.close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing session: ${e.message}")
            }
        }
    }
}
