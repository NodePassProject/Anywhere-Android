package com.argsment.anywhere.vpn.util

import android.util.Log

/**
 * Unified logger for the Anywhere app, mirroring iOS `AnywhereLogger`.
 *
 * `info`, `warning`, and `error` write to android.util.Log and optionally
 * to a log sink (user-facing log viewer wired by the VPN service).
 * `debug` writes to android.util.Log only — use for verbose/internal diagnostics.
 */
class AnywhereLogger(private val category: String) {

    enum class Level { info, warning, error }

    fun info(message: String) {
        Log.i(category, message)
        logSink?.invoke(message, Level.info)
    }

    fun warning(message: String) {
        Log.w(category, message)
        logSink?.invoke(message, Level.warning)
    }

    fun error(message: String) {
        Log.e(category, message)
        logSink?.invoke(message, Level.error)
    }

    /** Logs to android.util.Log only. Not shown in the user-facing log viewer. */
    fun debug(message: String) {
        Log.d(category, message)
    }

    companion object {
        /**
         * Optional log sink for dual logging. Set by the VPN service at
         * startup to forward logs to the user-facing log buffer; nil otherwise.
         */
        @Volatile
        var logSink: ((String, Level) -> Unit)? = null
    }
}
