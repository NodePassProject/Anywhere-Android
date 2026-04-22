package com.argsment.anywhere.vpn.util

import android.util.Log

/**
 * Unified logger for the Anywhere app, mirroring iOS `AnywhereLogger`.
 *
 * `info`, `warning`, and `error` write to LogCat and optionally to a log
 * sink (user-facing log viewer wired by the VPN service).
 * `debug` writes to LogCat only — use for verbose/internal diagnostics.
 *
 * iOS `AnywhereLogger.debug` is `#if DEBUG`-gated. Android relies on LogCat's
 * runtime log-level filter (`adb logcat *:I` suppresses debug) to achieve the
 * same end result without a build-variant split.
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

    /** Logs to LogCat only. Not shown in the user-facing log viewer. */
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
