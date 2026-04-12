package com.argsment.anywhere.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.LogBuffer
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * Exposes the user-facing log buffer to the UI layer. Mirrors iOS
 * `LogsModel`: entries are refreshed while polling is active and can
 * be paused (e.g. while the user is in select mode).
 *
 * Unlike iOS (which polls the Network Extension over IPC every second),
 * Android's VPN service runs in the same process as the UI, so we observe
 * [LogBuffer.state] directly via a coroutine.
 */
class LogsModel : ViewModel() {

    enum class LogLevel { info, warning, error }

    data class LogEntry(
        val id: UUID = UUID.randomUUID(),
        val timestamp: Long,   // epoch milliseconds
        val level: LogLevel,
        val message: String
    )

    private val _logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val logs: StateFlow<List<LogEntry>> = _logs.asStateFlow()

    private var pollingJob: Job? = null

    fun startPolling() {
        if (pollingJob != null) return
        pollingJob = viewModelScope.launch {
            LogBuffer.state.collect { entries ->
                _logs.value = entries.map { it.toLogEntry() }
            }
        }
    }

    fun stopPolling(clearLogs: Boolean = true) {
        pollingJob?.cancel()
        pollingJob = null
        if (clearLogs) _logs.value = emptyList()
    }

    private fun LogBuffer.Entry.toLogEntry(): LogEntry = LogEntry(
        timestamp = timestamp,
        level = when (level) {
            AnywhereLogger.Level.info -> LogLevel.info
            AnywhereLogger.Level.warning -> LogLevel.warning
            AnywhereLogger.Level.error -> LogLevel.error
        },
        message = message
    )
}
