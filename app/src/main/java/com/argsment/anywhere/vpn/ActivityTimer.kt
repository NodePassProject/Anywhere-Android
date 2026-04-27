package com.argsment.anywhere.vpn

import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Detects inactivity by periodically checking whether [update] has been called
 * since the last check. If no activity is detected within the configured interval,
 * the [onTimeout] callback fires.
 *
 * All operations must run on the provided executor (single-threaded lwIP thread).
 */
class ActivityTimer(
    private val executor: ScheduledExecutorService,
    timeoutMs: Long,
    private val onTimeout: () -> Unit
) {
    private var future: ScheduledFuture<*>? = null
    @Volatile
    private var hasActivity = false
    private var cancelled = false

    init {
        startTimer(timeoutMs)
    }

    /** Signals that activity has occurred. */
    fun update() {
        hasActivity = true
    }

    /** Changes the check interval, restarting the timer. */
    fun setTimeout(timeoutMs: Long) {
        if (cancelled) return
        future?.cancel(false)
        if (timeoutMs <= 0) {
            cancel()
            onTimeout()
            return
        }
        // Do NOT reset hasActivity here. The next timer tick will check for
        // actual activity since the timeout was changed.
        startTimer(timeoutMs)
    }

    fun cancel() {
        if (cancelled) return
        cancelled = true
        future?.cancel(false)
        future = null
    }

    private fun startTimer(timeoutMs: Long) {
        future = executor.scheduleAtFixedRate({
            if (cancelled) return@scheduleAtFixedRate
            if (hasActivity) {
                hasActivity = false
            } else {
                cancel()
                onTimeout()
            }
        }, timeoutMs, timeoutMs, TimeUnit.MILLISECONDS)
    }
}
