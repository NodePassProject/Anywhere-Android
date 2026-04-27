package com.argsment.anywhere.vpn.util

import android.util.Log
import com.argsment.anywhere.BuildConfig

/**
 * Unified logger for the Anywhere app.
 *
 * `info`, `warning`, and `error` write to LogCat and optionally to a log
 * sink (user-facing log viewer wired by the VPN service).
 * `debug` writes to LogCat only and is stripped in Release builds, mirroring
 * iOS's `#if DEBUG` gate in AnywhereLogger.swift.
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

    fun debug(message: String) {
        if (BuildConfig.DEBUG) {
            Log.d(category, message)
        }
    }

    companion object {
        @Volatile
        var logSink: ((String, Level) -> Unit)? = null
    }
}
