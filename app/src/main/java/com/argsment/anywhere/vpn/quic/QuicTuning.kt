package com.argsment.anywhere.vpn.quic

/**
 * Per-protocol tuning knobs for [QuicConnection]. Mirror of iOS
 * `QUICTuning.swift` — covers congestion control, flow-control windows,
 * stream limits, and timeouts so a higher-layer protocol can adjust the
 * QUIC stack without touching `QuicConnection` internals.
 *
 * Use one of the static presets ([naive], [hysteria]) unless you have a
 * reason to diverge.
 */
data class QuicTuning(
    /** Congestion controller selection. */
    val cc: CongestionControl,

    /** Per-stream receive window ceiling (auto-tuning upper bound). */
    val maxStreamWindow: Long,
    /** Connection-level receive window ceiling (auto-tuning upper bound). */
    val maxWindow: Long,

    /** Initial transport parameters we advertise. */
    val initialMaxData: Long,
    val initialMaxStreamDataBidiLocal: Long,
    val initialMaxStreamDataBidiRemote: Long,
    val initialMaxStreamDataUni: Long,
    val initialMaxStreamsBidi: Long,
    val initialMaxStreamsUni: Long,

    /** Connection-level idle timeout (nanoseconds). */
    val maxIdleTimeoutNs: Long,
    /** Handshake completion timeout (nanoseconds). */
    val handshakeTimeoutNs: Long,

    val disableActiveMigration: Boolean
) {
    /**
     * Which congestion controller [QuicConnection] should run.
     *
     * The three ngtcp2-native algorithms (RENO/CUBIC/BBR) are passed
     * straight through. [Brutal] keeps ngtcp2 initialized with CUBIC
     * (for a valid fallback state) and then replaces `conn->cc`'s
     * callbacks with the native Brutal implementation in
     * `ngtcp2_android_brutal.c` — no ngtcp2 source changes.
     */
    sealed class CongestionControl {
        object Reno : CongestionControl()
        object Cubic : CongestionControl()
        object Bbr : CongestionControl()
        /**
         * Hysteria Brutal CC with an initial target send rate (bytes/sec).
         * The rate is typically refined post-auth once the server's
         * Hysteria-CC-RX is known via [QuicConnection.setBrutalBandwidth].
         */
        data class Brutal(val initialBps: Long) : CongestionControl()
    }

    /** ngtcp2 cc_algo enum value used at conn-init time. */
    val ngtcp2CcAlgo: Int
        get() = when (cc) {
            CongestionControl.Reno -> NGTCP2_CC_ALGO_RENO
            CongestionControl.Cubic -> NGTCP2_CC_ALGO_CUBIC
            CongestionControl.Bbr -> NGTCP2_CC_ALGO_BBR
            is CongestionControl.Brutal -> NGTCP2_CC_ALGO_CUBIC
        }

    companion object {
        // Mirrors `enum ngtcp2_cc_algo` in ngtcp2.h.
        const val NGTCP2_CC_ALGO_RENO = 0x00
        const val NGTCP2_CC_ALGO_CUBIC = 0x01
        const val NGTCP2_CC_ALGO_BBR = 0x02

        /**
         * Matches naiveproxy/Chromium defaults. CUBIC is what the upstream
         * server stack is tuned against; BBR is a reasonable proxy-side
         * choice but deviates from the reference implementation.
         *
         * Flow-control windows are sized after upstream naiveproxy
         * (`naive_proxy_bin.cc`): 64 MB stream / 128 MB connection, the
         * 2× BDP target for 125 Mbps × 256 ms links. Initial per-stream
         * window is bumped to 16 MB so the first RTT after CONNECT can
         * fill a high-BDP pipe before the ngtcp2 auto-scaler ramps.
         *
         * Handshake timeout matches naive's `kMaxTimeForCryptoHandshakeSecs = 10`
         * (quic_constants.h). Covers ~three PTO retransmissions (1/2/4 s)
         * before the pool's one-shot retry kicks in — tight enough to
         * recover from a stale PSK quickly, loose enough not to trip on
         * high-RTT / lossy mobile paths.
         */
        val naive = QuicTuning(
            cc = CongestionControl.Cubic,
            maxStreamWindow = 64L * 1024 * 1024,
            maxWindow = 128L * 1024 * 1024,
            initialMaxData = 64L * 1024 * 1024,
            initialMaxStreamDataBidiLocal = 16L * 1024 * 1024,
            initialMaxStreamDataBidiRemote = 16L * 1024 * 1024,
            initialMaxStreamDataUni = 16L * 1024 * 1024,
            initialMaxStreamsBidi = 1024,
            initialMaxStreamsUni = 100,
            maxIdleTimeoutNs = 30L * 1_000_000_000,
            handshakeTimeoutNs = 10L * 1_000_000_000,
            disableActiveMigration = true
        )

        /**
         * Hysteria v2 runs Brutal congestion control with a user-configured
         * upload rate (Mbit/s). The rate applies from the moment the QUIC
         * connection opens; [HysteriaSession][com.argsment.anywhere.vpn.protocol.hysteria.HysteriaSession]
         * replaces it with `min(server_rx, client_max_tx)` once the auth
         * response lands.
         *
         * Flow-control windows match the reference Hysteria client
         * (`core/client/config.go`): 8 MB per stream, 20 MB per connection,
         * with `max == initial` to disable ngtcp2's receive-window auto-tuner.
         * Brutal sends at a fixed configured rate with no backoff, so a larger
         * receive window doesn't raise useful throughput — it only deepens the
         * in-flight pipe, turning path-capacity mismatches into multi-megabyte
         * loss bursts that trip the server's idle/loss detection.
         */
        fun hysteria(uploadMbps: Int): QuicTuning {
            val bps = uploadMbps.toLong() * 1_000_000L / 8L
            return QuicTuning(
                cc = CongestionControl.Brutal(initialBps = bps),
                maxStreamWindow = 8L * 1024 * 1024,
                maxWindow = 20L * 1024 * 1024,
                initialMaxData = 20L * 1024 * 1024,
                initialMaxStreamDataBidiLocal = 8L * 1024 * 1024,
                initialMaxStreamDataBidiRemote = 8L * 1024 * 1024,
                initialMaxStreamDataUni = 8L * 1024 * 1024,
                initialMaxStreamsBidi = 1024,
                initialMaxStreamsUni = 16,
                maxIdleTimeoutNs = 30L * 1_000_000_000,
                handshakeTimeoutNs = 10L * 1_000_000_000,
                disableActiveMigration = true
            )
        }
    }
}
