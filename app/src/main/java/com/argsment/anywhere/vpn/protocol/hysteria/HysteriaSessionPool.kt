package com.argsment.anywhere.vpn.protocol.hysteria

import com.argsment.anywhere.vpn.util.AnywhereLogger
import java.util.concurrent.ConcurrentHashMap

private val logger = AnywhereLogger("Hysteria-Pool")

/**
 * Process-wide cache of Hysteria sessions keyed by `(host, port, sni, password)`.
 * Direct port of iOS `HysteriaSessionPool.swift`.
 *
 * Multiple TCP/UDP flows to the same Hysteria server share a single
 * authenticated QUIC connection; the pool evicts a session when it closes
 * (via the [HysteriaSession.onClose] hook).
 */
object HysteriaSessionPool {

    private data class Key(
        val host: String,
        val port: Int,
        val sni: String,
        val password: String
    )

    private val lock = Any()
    private val sessions = ConcurrentHashMap<Key, HysteriaSession>()

    /** Returns a [HysteriaSession] in [HysteriaSession.State.READY] for the
     *  given configuration, opening a new one if necessary. Suspends until
     *  the session is ready or fails. */
    suspend fun acquire(configuration: HysteriaConfiguration): HysteriaSession {
        val key = Key(
            host = configuration.proxyHost,
            port = configuration.proxyPort,
            sni = configuration.effectiveSni,
            password = configuration.password
        )

        synchronized(lock) {
            val existing = sessions[key]
            if (existing != null && !existing.poolIsClosed) {
                // Fall through; ensureReady is async-safe.
                existing.let { s ->
                    // Avoid double-await holding the lock.
                    return@synchronized s.also { /* return after lock */ }
                }
            }
        }
        // Re-check + create outside the lock.
        var session = synchronized(lock) {
            val cached = sessions[key]
            if (cached != null && !cached.poolIsClosed) cached
            else {
                val s = HysteriaSession(configuration)
                sessions[key] = s
                s.onClose = {
                    synchronized(lock) {
                        if (sessions[key] === s) sessions.remove(key)
                    }
                }
                s
            }
        }

        try {
            session.ensureReady()
        } catch (e: Throwable) {
            // Evict failed sessions immediately so the next caller retries.
            synchronized(lock) { if (sessions[key] === session) sessions.remove(key) }
            throw e
        }
        return session
    }

    /** Cancels every cached session and clears the pool. Called on stack
     *  shutdown / restart / device wake — the underlying QUIC sockets the
     *  kernel kept open are stale once we're invalidating outbound state. */
    fun closeAll() {
        val snapshot = synchronized(lock) {
            val copy = sessions.values.toList()
            sessions.clear()
            copy
        }
        for (session in snapshot) {
            try { session.close() } catch (_: Throwable) {}
        }
    }
}
