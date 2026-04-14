package com.argsment.anywhere.vpn.protocol.naive.http3

import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

private val logger = AnywhereLogger("HTTP3Pool")

/**
 * HTTP/3 session pool — mirrors iOS `HTTP3SessionPool`.
 *
 * Sessions are keyed by "host:port:sni". Per-key soft cap is
 * [maxSessionsPerKey] (prefer creating a new session up to this bound so
 * streams don't queue behind each other). When all sessions are busy the
 * pool may grow up to [hardMaxSessionsPerKey]; beyond that we overflow
 * onto the least-loaded session rather than grow without bound. Sessions
 * idle for [idleTimeoutMs] with no active streams are evicted.
 */
object Http3SessionPool {

    private const val maxSessionsPerKey = 8
    private const val hardMaxSessionsPerKey = 16
    private const val idleTimeoutMs: Long = 60_000L

    private val mutex = Mutex()
    private val sessions = HashMap<String, MutableList<Http3Session>>()
    // System.nanoTime() keyed by identity hash of the session.
    private val lastActivity = ConcurrentHashMap<Http3Session, Long>()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    @Volatile private var cleanupJob: Job? = null

    init {
        startCleanupTimer()
    }

    private fun startCleanupTimer() {
        cleanupJob?.cancel()
        cleanupJob = scope.launch {
            while (isActive) {
                delay(idleTimeoutMs)
                try {
                    cleanupIdleSessions()
                } catch (t: Throwable) {
                    logger.warning("HTTP/3 pool cleanup failed: ${t.message}")
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Public entry points
    // ---------------------------------------------------------------------

    /**
     * Backward-compatible entry used by `NaiveClient`. Returns a pooled
     * [Http3Session] with a stream slot reserved; the caller must open
     * the request stream via [Http3Session.openRequestStream]. Equivalent
     * to the soft-cap branch of iOS `acquireStream`.
     */
    suspend fun acquire(host: String, port: Int, sni: String): Http3Session {
        return acquireSession(host, port, sni, configuration = null)
    }

    /**
     * Full iOS-parity entry: reserves a stream on a pooled session, waits
     * for its control stream to be ready, and returns an [Http3Tunnel]
     * bound to [destination].
     */
    suspend fun acquireStream(
        host: String,
        port: Int,
        sni: String,
        configuration: NaiveConfiguration,
        destination: String
    ): Http3Tunnel {
        val session = acquireSession(host, port, sni, configuration)
        // The session is already connecting (or ready); await readiness
        // before handing a tunnel to the caller.
        session.awaitReady()
        return Http3Tunnel(session, configuration, destination)
    }

    /**
     * Core pool acquire. If [configuration] is null the returned session
     * still has its connect() invoked by the pool (mirrors the old
     * behaviour of [acquire]).
     */
    private suspend fun acquireSession(
        host: String,
        port: Int,
        sni: String,
        configuration: NaiveConfiguration?
    ): Http3Session {
        val key = "$host:$port:$sni"

        // Decide which session to hand out under the pool lock. Starting
        // the actual QUIC connect happens OUTSIDE the lock so concurrent
        // acquires for disjoint keys don't serialize on the handshake.
        data class Pick(val session: Http3Session, val isNew: Boolean)

        val pick: Pick = mutex.withLock {
            evictStale(key)

            // Reuse an existing session with free capacity.
            sessions[key]?.firstOrNull { it.tryReserveStream() }?.let {
                lastActivity[it] = System.nanoTime()
                return@withLock Pick(it, isNew = false)
            }

            // Hard-cap overflow: pile onto the least-loaded session.
            overflowSession(key)?.let {
                lastActivity[it] = System.nanoTime()
                return@withLock Pick(it, isNew = false)
            }

            // Grow the pool. When we're past the soft cap, first try to
            // reap a session with no live streams; never close a session
            // with active streams just to stay under the soft cap.
            val bucket = sessions.getOrPut(key) { mutableListOf() }
            if (bucket.size >= maxSessionsPerKey) {
                val victim = bucket.firstOrNull { !it.hasActiveStreams }
                if (victim != null) {
                    bucket.remove(victim)
                    lastActivity.remove(victim)
                    // Close outside the lock later (see after withLock).
                    scope.launch { victim.close() }
                }
            }

            val session = Http3Session(host = host, port = port, serverName = sni)
            session.onClose = { removeSession(session, key) }
            // Reserve a slot atomically for the caller.
            session.tryReserveStream()
            bucket.add(session)
            lastActivity[session] = System.nanoTime()
            Pick(session, isNew = true)
        }

        // Kick off the QUIC handshake outside the lock. If it fails,
        // evict the session from the pool and rethrow.
        if (pick.isNew) {
            try {
                pick.session.connect()
            } catch (t: Throwable) {
                removeSession(pick.session, key)
                try { pick.session.close() } catch (_: Throwable) {}
                throw t
            }
        }

        return pick.session
    }

    /**
     * When the pool has already grown to the hard cap for [key] and every
     * session is saturated, pick the least-loaded non-blocked session and
     * reserve a stream on it bypassing `maxConcurrentStreams`. Must be
     * called with [mutex] held.
     */
    private fun overflowSession(key: String): Http3Session? {
        val bucket = sessions[key] ?: return null
        if (bucket.size < hardMaxSessionsPerKey) return null
        val candidate = bucket
            .filter { !it.poolIsClosed && !it.poolIsStreamBlocked }
            .minByOrNull { it.currentStreamLoad }
            ?: return null
        if (!candidate.forceReserveStream()) return null
        logger.warning("HTTP/3 pool hit hard cap ($hardMaxSessionsPerKey) for $key; overflowing onto existing session")
        return candidate
    }

    // ---------------------------------------------------------------------
    // Eviction
    // ---------------------------------------------------------------------

    /** Must be called with [mutex] held. */
    private fun evictStale(key: String) {
        val bucket = sessions[key] ?: return
        val now = System.nanoTime()
        val idleNs = idleTimeoutMs * 1_000_000L
        val iter = bucket.iterator()
        while (iter.hasNext()) {
            val s = iter.next()
            if (s.poolIsClosed || s.poolIsStreamBlocked) {
                lastActivity.remove(s)
                iter.remove()
                continue
            }
            if (!s.hasActiveStreams) {
                val last = lastActivity[s] ?: now
                if (now - last > idleNs) {
                    lastActivity.remove(s)
                    iter.remove()
                    scope.launch { s.close() }
                }
            }
        }
        if (bucket.isEmpty()) sessions.remove(key)
    }

    private fun removeSession(session: Http3Session, key: String) {
        scope.launch {
            mutex.withLock {
                sessions[key]?.remove(session)
                if (sessions[key]?.isEmpty() == true) sessions.remove(key)
                lastActivity.remove(session)
            }
        }
    }

    private suspend fun cleanupIdleSessions() {
        val toClose = mutableListOf<Http3Session>()
        mutex.withLock {
            val now = System.nanoTime()
            val idleNs = idleTimeoutMs * 1_000_000L
            val keys = sessions.keys.toList()
            for (key in keys) {
                val bucket = sessions[key] ?: continue
                val iter = bucket.iterator()
                while (iter.hasNext()) {
                    val s = iter.next()
                    if (s.poolIsClosed) {
                        lastActivity.remove(s)
                        iter.remove()
                        continue
                    }
                    if (!s.hasActiveStreams) {
                        val last = lastActivity[s] ?: now
                        if (now - last > idleNs) {
                            lastActivity.remove(s)
                            iter.remove()
                            toClose.add(s)
                        }
                    }
                }
                if (bucket.isEmpty()) sessions.remove(key)
            }
        }
        for (s in toClose) {
            try { s.close() } catch (t: Throwable) {
                logger.warning("Error closing idle HTTP/3 session: ${t.message}")
            }
        }
    }

    /** Closes all pooled sessions. */
    fun closeAll() {
        scope.launch {
            val all: List<Http3Session>
            mutex.withLock {
                all = sessions.values.flatten()
                sessions.clear()
                lastActivity.clear()
            }
            for (s in all) {
                try {
                    s.onClose = null // avoid re-entrant eviction
                    s.close()
                } catch (t: Throwable) {
                    logger.warning("Error closing HTTP/3 session: ${t.message}")
                }
            }
        }
    }

    /** Back-compat release hook — drops the session for a key if it matches. */
    fun release(host: String, port: Int, sni: String) {
        val key = "$host:$port:$sni"
        scope.launch {
            val victims: List<Http3Session>
            mutex.withLock {
                victims = sessions.remove(key) ?: emptyList()
                for (v in victims) lastActivity.remove(v)
            }
            for (v in victims) {
                try { v.close() } catch (_: Throwable) {}
            }
        }
    }
}
