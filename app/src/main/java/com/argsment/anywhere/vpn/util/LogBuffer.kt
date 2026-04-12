package com.argsment.anywhere.vpn.util

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Thread-safe ring buffer for user-facing logs forwarded from [AnywhereLogger.logSink].
 *
 * Mirrors iOS `LWIPStack` log buffer: entries older than [RETENTION_SECONDS]
 * are evicted on every write, and the buffer is capped at [MAX_ENTRIES].
 */
object LogBuffer {

    /** Retention window in seconds; matches iOS `TunnelConstants.logRetentionInterval`. */
    private const val RETENTION_SECONDS = 300L

    /** Maximum entries; matches iOS `TunnelConstants.logMaxEntries`. */
    private const val MAX_ENTRIES = 50

    data class Entry(
        val timestamp: Long,  // epoch milliseconds
        val level: AnywhereLogger.Level,
        val message: String
    )

    private val lock = ReentrantLock()
    private val entries = ArrayDeque<Entry>(MAX_ENTRIES + 1)

    private val _state = MutableStateFlow<List<Entry>>(emptyList())
    val state: StateFlow<List<Entry>> = _state

    fun append(message: String, level: AnywhereLogger.Level) {
        val now = System.currentTimeMillis()
        val snapshot = lock.withLock {
            entries.addLast(Entry(now, level, message))
            compact(now)
            entries.toList()
        }
        _state.value = snapshot
    }

    fun fetchLogs(): List<Entry> = lock.withLock {
        compact(System.currentTimeMillis())
        entries.toList()
    }

    fun clear() {
        lock.withLock { entries.clear() }
        _state.value = emptyList()
    }

    /** Caller must hold [lock]. */
    private fun compact(now: Long) {
        val cutoff = now - RETENTION_SECONDS * 1000L
        while (entries.isNotEmpty() && entries.first().timestamp < cutoff) {
            entries.removeFirst()
        }
        while (entries.size > MAX_ENTRIES) {
            entries.removeFirst()
        }
    }
}
