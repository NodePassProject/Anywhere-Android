package com.argsment.anywhere.vpn.protocol.naive.http3

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * One HTTP/3 session per (proxyHost, proxyPort, sni) reused across tunnels.
 *
 * Mirrors `HTTP3SessionPool.swift` — much simpler: we keep at most one
 * connected session per key and lazily connect on first access.
 */
object Http3SessionPool {

    private data class Key(val host: String, val port: Int, val sni: String)

    private val sessions = mutableMapOf<Key, Http3Session>()
    private val mutex = Mutex()

    suspend fun acquire(host: String, port: Int, sni: String): Http3Session {
        val key = Key(host, port, sni)
        mutex.withLock {
            sessions[key]?.let { return it }
            val s = Http3Session(host = host, port = port, serverName = sni)
            sessions[key] = s
            // Connect outside the lock to avoid serialising handshakes.
            try {
                s.connect()
            } catch (t: Throwable) {
                sessions.remove(key)
                throw t
            }
            return s
        }
    }

    fun release(host: String, port: Int, sni: String) {
        val key = Key(host, port, sni)
        val s = sessions.remove(key) ?: return
        s.close()
    }
}
