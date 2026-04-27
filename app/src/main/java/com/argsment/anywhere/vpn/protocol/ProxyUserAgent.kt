package com.argsment.anywhere.vpn.protocol

import java.util.Calendar
import java.util.TimeZone
import kotlin.math.max

/**
 * Shared Chrome User-Agent string. Uses a fixed base version (Chrome 144,
 * released 2026-01-13) and advances by one version every ~35 days so the UA
 * tracks current Chrome stable releases.
 */
object ProxyUserAgent {
    val chrome: String by lazy { computeChromeUA() }

    private fun computeChromeUA(): String {
        val baseVersion = 144
        val baseDate = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply {
            clear()
            set(2026, Calendar.JANUARY, 13)
        }.timeInMillis
        val now = System.currentTimeMillis()
        val daysSinceBase = max(0L, (now - baseDate) / 86_400_000L).toInt()
        val version = baseVersion + daysSinceBase / 35
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$version.0.0.0 Safari/537.36"
    }
}
