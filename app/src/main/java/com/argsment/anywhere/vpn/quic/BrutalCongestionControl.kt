package com.argsment.anywhere.vpn.quic

/**
 * Thin Kotlin handle for the Hysteria Brutal congestion controller.
 *
 * The full state machine (ack/loss slot windows, cwnd/pacing math) lives
 * in native code — see `app/src/main/jni/ngtcp2_android_brutal.c`, which
 * is a direct port of `Shared/QUIC/BrutalCongestionControl.swift`. We
 * keep the state native so per-ACK / per-loss callbacks don't have to
 * cross the JNI boundary on the hot path.
 *
 * Lifecycle: constructed by [QuicConnection] once the ngtcp2 connection
 * exists, released in [QuicConnection.close]. Thread-safe — the
 * bandwidth setter is guarded by a native mutex.
 */
internal class BrutalCongestionControl(
    /** Native `AndroidQuicConn *` — the same handle [QuicConnection] holds. */
    private val connHandle: Long
) {
    /**
     * True iff the native install succeeded. A false value means Brutal
     * is not active on this connection — all setters become no-ops and
     * ngtcp2's built-in CC (CUBIC) continues to drive the cwnd.
     */
    var isInstalled: Boolean = false
        private set

    /**
     * Overwrites `conn->cc`'s callback table with Brutal trampolines.
     * Must be called at most once per instance; idempotent thereafter.
     */
    fun install(initialBytesPerSec: Long) {
        if (isInstalled || connHandle == 0L) return
        val ok = QuicBridge.nativeInstallBrutalCC(connHandle, initialBytesPerSec)
        isInstalled = ok != 0
    }

    /** Updates the target send rate (bytes/sec). No-op if not installed. */
    fun setTargetBandwidth(bytesPerSec: Long) {
        if (!isInstalled || connHandle == 0L) return
        QuicBridge.nativeSetBrutalBandwidth(connHandle, bytesPerSec)
    }
}
