package com.argsment.anywhere.vpn

/**
 * Centralized tunnel tuning constants. Mirrors iOS `TunnelConstants.swift`.
 *
 * All values expressed in their natural unit (seconds, milliseconds, bytes, etc.)
 * and in one place so Android stays in lock-step with iOS.
 */
object TunnelConstants {

    // -- Connection Timeouts --

    /** Inactivity timeout for TCP connections (Xray-core `connIdle`, default 300s). */
    const val connectionIdleTimeoutMs: Long = 300_000L

    /** Timeout after uplink (local → remote) finishes (Xray-core `downlinkOnly`, default 1s). */
    const val downlinkOnlyTimeoutMs: Long = 1_000L

    /** Timeout after downlink (remote → local) finishes (Xray-core `uplinkOnly`, default 1s). */
    const val uplinkOnlyTimeoutMs: Long = 1_000L

    /**
     * Handshake timeout matching Xray-core's `Timeout.Handshake` (60 seconds).
     * Bounds the entire connection setup phase (TCP + TLS + WS/HTTPUpgrade + VLESS header).
     */
    const val handshakeTimeoutMs: Long = 60_000L

    /**
     * Maximum time to wait for a TLS ClientHello on a real-IP TCP connection
     * before falling back to IP-based routing. Covers server-speaks-first
     * protocols (SSH, SMTP, FTP) so they don't stall inside the sniff phase.
     * TLS clients typically send ClientHello within a few ms of TCP accept.
     */
    const val sniffDeadlineMs: Long = 500L

    // -- TCP Buffer Sizes --

    /**
     * Maximum bytes per tcp_write call (16 KB ≈ 12 TCP segments at TCP_MSS=1360).
     * With MEMP_NUM_TCP_SEG=32768, this lets many connections make progress without
     * exhausting the segment pool. Must stay in sync with lwipopts.h.
     */
    const val tcpMaxWriteSize: Int = 16 * 1024

    /**
     * Maximum upload coalesce buffer size, capped at UInt16.max because downstream
     * protocols (Vision padding) use 2-byte content length fields.
     */
    const val tcpMaxCoalesceSize: Int = 65535

    /**
     * Safety cap on per-connection `pendingData` (bytes accumulated while the
     * sniff phase runs or the proxy is dialing). Bounded naturally by TCP_WND
     * since we defer `tcp_recved` until the route is committed; this cap
     * defends against pathological states where the window bookkeeping drifts.
     * Set to 2 × TCP_WND so it only fires on runaway growth.
     */
    const val tcpMaxPendingDataSize: Int = 2 * 512 * 1360

    /**
     * Low-water mark for the per-connection downlink backlog (`pendingWrite`).
     * When the backlog drops below this we prefetch the next proxy receive in
     * parallel with the ongoing drain — without this overlap, big chunks turn
     * the downlink into stop-and-wait and throughput collapses. Sized to match
     * TCP_SND_BUF in lwipopts.h so a prefetched chunk can be pushed into lwIP
     * the moment space frees up.
     */
    const val drainLowWaterMark: Int = 512 * 1360

    // -- UDP Settings --

    /** Maximum buffer size for queued UDP datagrams. */
    const val udpMaxBufferSize: Int = 16 * 1024

    /** Idle timeout for UDP flows (seconds). */
    const val udpIdleTimeoutSec: Double = 60.0

    // -- Log Buffer --

    /** Retention interval for log entries (seconds). */
    const val logRetentionIntervalSec: Long = 300L

    /** Maximum number of log entries in the buffer. */
    const val logMaxEntries: Int = 50

    /** Time window to attribute connection errors to a recent tunnel interruption. */
    const val recentTunnelInterruptionWindowNanos: Long = 8_000_000_000L

    // -- Timer Intervals --

    /** lwIP periodic timeout interval (milliseconds). */
    const val lwipTimeoutIntervalMs: Long = 250L

    /** UDP flow cleanup timer interval (seconds). */
    const val udpCleanupIntervalSec: Long = 1L

    /** Retry delay when TCP overflow drain makes no progress (milliseconds). */
    const val drainRetryDelayMs: Long = 250L

    // -- Stack Lifecycle --

    /**
     * Minimum sleep duration (seconds) before proactively restarting the stack on wake.
     * Short sleeps leave TCP connections intact — they likely survive.
     * Long sleeps almost certainly leave dead proxy connections behind,
     * so we restart immediately instead of waiting for keepalive timeouts.
     */
    const val wakeRestartThresholdSec: Long = 60L

    /**
     * Minimum interval between stack restarts (nanoseconds).
     * 2s absorbs bursts where a path update and a settings/routing notification arrive
     * back-to-back (e.g., user toggling a setting while Wi-Fi is handing off).
     */
    const val restartThrottleNanos: Long = 2_000_000_000L

    // -- TLS Sniffer --

    /**
     * Maximum bytes buffered while parsing a TLS ClientHello for SNI.
     * Typical ClientHellos fit in under 2 KB; post-quantum key shares push
     * that to ~4 KB. 8 KB is a safe ceiling that still bounds memory.
     */
    const val tlsSnifferBufferLimit: Int = 8192

    // -- Fake-IP Pool --

    /** Base IPv4 address for the fake-IP pool (198.18.0.0 in 198.18.0.0/15). */
    const val fakeIPPoolBaseIPv4: Long = 0xC612_0000L

    /**
     * Usable offsets in the fake-IP pool. Bounds the three backing
     * dictionaries (~200 B per entry × 3 maps) in a long-running tunnel.
     */
    const val fakeIPPoolSize: Int = 16_384
}
