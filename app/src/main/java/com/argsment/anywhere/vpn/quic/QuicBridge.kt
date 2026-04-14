package com.argsment.anywhere.vpn.quic

/**
 * JNI bridge to ngtcp2. Every connection holds a native handle (`long`) to an
 * AndroidQuicConn struct owned by the C side. Events from ngtcp2 are delivered
 * via the [NativeCallbacks] interface registered at install time.
 *
 * Mirrors the iOS `QUICConnection` — the C side structure is identical to
 * the Apple backend; only the crypto primitive callbacks differ.
 */
object QuicBridge {

    /** Delivered to by ngtcp2 (via JNI) on the connection's own thread. */
    interface NativeCallbacks {
        /**
         * Called when ngtcp2 needs the initial TLS ClientHello. The TLS handler
         * wraps [transportParams] in a `quic_transport_parameters` extension
         * and returns the raw Handshake-level ClientHello bytes.
         */
        fun buildClientHello(transportParams: ByteArray): ByteArray?

        /** TLS Handshake bytes received from the server at [level]. Returns 0 on success. */
        fun processCryptoData(level: Int, data: ByteArray): Int

        fun onStreamData(streamId: Long, data: ByteArray, fin: Boolean)
        fun onAckedStreamData(streamId: Long, offset: Long, dataLen: Long)
        fun onStreamClose(streamId: Long, appErrorCode: Long)
        fun onRecvDatagram(data: ByteArray)
        fun onHandshakeCompleted()

        /** Called when ngtcp2 has a UDP packet to send. */
        fun sendUdpPacket(packet: ByteArray)
    }

    init {
        System.loadLibrary("anywhere_native")
        nativeInstall(NativeCallbacks::class.java, QuicNativeCrypto::class.java)
    }

    @JvmStatic external fun nativeInstall(callbacksClass: Class<*>, cryptoClass: Class<*>)

    /**
     * Creates a new ngtcp2 client connection. [tuningParams] is a packed
     * `long[]` carrying the [QuicTuning] knobs in the order the native
     * bridge expects (see `quic_jni_bridge.c::nativeCreate`):
     *
     * `[ccAlgo, maxStreamWindow, maxWindow, initialMaxData,
     *   initialMaxStreamDataBidiLocal, initialMaxStreamDataBidiRemote,
     *   initialMaxStreamDataUni, initialMaxStreamsBidi, initialMaxStreamsUni,
     *   maxIdleTimeoutNs, handshakeTimeoutNs, disableActiveMigration,
     *   keepAliveNs]`
     *
     * `disableActiveMigration` is encoded as 0/1.
     */
    @JvmStatic external fun nativeCreate(
        callbacks: NativeCallbacks,
        host: String,
        port: Int,
        ipv6: Boolean,
        hostAddrBytes: ByteArray,
        datagramsEnabled: Boolean,
        tuningParams: LongArray
    ): Long

    @JvmStatic external fun nativeDestroy(handle: Long)
    @JvmStatic external fun nativeOpenBidiStream(handle: Long): Long
    @JvmStatic external fun nativeOpenUniStream(handle: Long): Long
    @JvmStatic external fun nativeExtendStreamOffset(handle: Long, streamId: Long, count: Long)
    @JvmStatic external fun nativeShutdownStream(handle: Long, streamId: Long, appErrCode: Long): Int
    @JvmStatic external fun nativeWriteLoop(handle: Long, streamId: Long, data: ByteArray?, fin: Boolean): Int
    @JvmStatic external fun nativeReadPacket(handle: Long, packet: ByteArray): Int
    @JvmStatic external fun nativeWriteDatagram(handle: Long, dgram: ByteArray): Int
    @JvmStatic external fun nativeGetExpiry(handle: Long): Long
    @JvmStatic external fun nativeHandleExpiry(handle: Long): Int
    @JvmStatic external fun nativeMaxDatagramPayload(handle: Long): Long
    @JvmStatic external fun nativeSetTlsCipherSuite(handle: Long, cipherSuite: Int)
    @JvmStatic external fun nativeSubmitCryptoData(handle: Long, level: Int, data: ByteArray): Int
    @JvmStatic external fun nativeInstallHandshakeKeys(handle: Long, rxSecret: ByteArray, txSecret: ByteArray): Int
    @JvmStatic external fun nativeInstallApplicationKeys(handle: Long, rxSecret: ByteArray, txSecret: ByteArray): Int

    /**
     * Overwrites the connection's CC callback table with Hysteria Brutal
     * trampolines. Must be called after [nativeCreate] and before any
     * ACK/loss has been processed. Returns 0 on failure, non-zero on
     * success.
     */
    @JvmStatic external fun nativeInstallBrutalCC(handle: Long, initialBps: Long): Int

    /** Updates the Brutal target send rate. No-op if Brutal isn't installed. */
    @JvmStatic external fun nativeSetBrutalBandwidth(handle: Long, bps: Long)

    /** ngtcp2 encryption levels. */
    const val LEVEL_INITIAL = 0
    const val LEVEL_HANDSHAKE = 2
    const val LEVEL_1RTT = 3
    const val LEVEL_EARLY = 1
}
