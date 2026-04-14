package com.argsment.anywhere.vpn.protocol.hysteria

/**
 * Configuration for a Hysteria v2 session. Direct port of iOS
 * `HysteriaConfiguration.swift`.
 */
data class HysteriaConfiguration(
    val proxyHost: String,
    val proxyPort: Int,
    /** Authentication password (sent in the `Hysteria-Auth` header). */
    val password: String,
    /** TLS SNI override. Defaults to [proxyHost] when null. */
    val sni: String? = null,
    /** Client's receive bandwidth estimate in bytes/sec. Advertised to the
     *  server in `Hysteria-CC-RX` so the server can cap its send rate.
     *  0 means "please probe" / "I don't know". */
    val clientRxBytesPerSec: Long = 0,
    /** Client-declared upload bandwidth in Mbit/s (1…100). Drives both the
     *  initial Brutal target rate (before the server's CC-RX is known) and
     *  the post-auth `min(server_rx, client_max_tx)` cap. */
    val uploadMbps: Int = 10
) {
    /** Upload bandwidth expressed in bytes/sec — the unit Brutal uses. */
    val uploadBytesPerSec: Long get() = uploadMbps.toLong() * 1_000_000L / 8L
    val effectiveSni: String get() = sni ?: proxyHost
}
