package com.argsment.anywhere.vpn

/**
 * JNI bridge to native C libraries (lwIP, BLAKE3, TLS KDF, libyaml).
 *
 * All native functions are declared here and loaded from a single shared library.
 * Packet / DNS / GeoIP / VLESS utilities are pure Kotlin — see
 * [com.argsment.anywhere.vpn.util.PacketUtil] and [GeoIpDatabase].
 */
object NativeBridge {

    init {
        System.loadLibrary("anywhere_native")
    }

    // =========================================================================
    // Callback interface — implemented by LwipStack to receive lwIP events
    // =========================================================================

    interface LwipCallback {
        fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean)
        fun onTcpAccept(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, pcb: Long): Long

        /**
         * Pre-accept hook fired in tcp_listen_input before SYN-ACK is enqueued.
         * Implementations must fill [outResult]:
         *   outResult[0] = decision: 0 (ALLOW) / 1 (DEFER) / 2 (REJECT)
         *   outResult[1] = connId (only meaningful when decision is ALLOW or DEFER)
         *
         * Mirrors iOS [lwip_tcp_pre_accept_fn]; see lwip/ANYWHERE_PATCHES.md
         * "deferred SYN-ACK".
         */
        fun onTcpPreAccept(
            srcIp: ByteArray, srcPort: Int,
            dstIp: ByteArray, dstPort: Int,
            isIpv6: Boolean, pcb: Long,
            outResult: LongArray
        )

        fun onTcpRecv(connId: Long, data: ByteArray?)
        fun onTcpSent(connId: Long, length: Int)
        fun onTcpErr(connId: Long, err: Int)
        fun onUdpRecv(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, data: ByteArray)
    }

    @Volatile
    var callback: LwipCallback? = null

    // Called from JNI
    @JvmStatic
    fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean) {
        callback?.onOutput(packet, length, isIpv6)
    }

    @JvmStatic
    fun onTcpAccept(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, pcb: Long): Long {
        return callback?.onTcpAccept(srcIp, srcPort, dstIp, dstPort, isIpv6, pcb) ?: 0L
    }

    @JvmStatic
    fun onTcpPreAccept(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean, pcb: Long,
        outResult: LongArray
    ) {
        // JNI pre-fills outResult with REJECT defaults; only the callback
        // can override. If no callback is registered, fall through to the
        // legacy late-accept path (decision = ALLOW, conn = NULL — C-side
        // converts the missing conn to REJECT).
        val cb = callback ?: run {
            outResult[0] = 0L  // ALLOW (legacy path picks up via onTcpAccept)
            outResult[1] = 0L
            return
        }
        cb.onTcpPreAccept(srcIp, srcPort, dstIp, dstPort, isIpv6, pcb, outResult)
    }

    @JvmStatic
    fun onTcpRecv(connId: Long, data: ByteArray?) {
        callback?.onTcpRecv(connId, data)
    }

    @JvmStatic
    fun onTcpSent(connId: Long, length: Int) {
        callback?.onTcpSent(connId, length)
    }

    @JvmStatic
    fun onTcpErr(connId: Long, err: Int) {
        callback?.onTcpErr(connId, err)
    }

    @JvmStatic
    fun onUdpRecv(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, data: ByteArray) {
        callback?.onUdpRecv(srcIp, srcPort, dstIp, dstPort, isIpv6, data)
    }

    // =========================================================================
    // lwIP — Lifecycle & Packet I/O
    // =========================================================================

    /** Initialize the lwIP stack and register JNI callbacks. */
    @JvmStatic
    external fun nativeInit()

    /** Feed a raw IP packet (from the TUN fd) into lwIP. */
    @JvmStatic
    external fun nativeInput(packet: ByteArray, length: Int)

    /** Poll lwIP timers (call every ~250ms). */
    @JvmStatic
    external fun nativeTimerPoll()

    /**
     * Abort every active TCP PCB without tearing down the netif or
     * listeners. Used on device wake / underlying-network change to
     * invalidate outbound proxy sockets the kernel killed during sleep.
     */
    @JvmStatic
    external fun nativeAbortAllTcp()

    /** Shut down the lwIP stack and clean up. */
    @JvmStatic
    external fun nativeShutdown()

    // =========================================================================
    // lwIP — TCP Operations
    // =========================================================================

    /** Write data to a TCP connection. Returns 0 on success, negative on error. */
    @JvmStatic
    external fun nativeTcpWrite(pcb: Long, data: ByteArray, offset: Int, length: Int): Int

    /** Flush pending TCP data for a connection. */
    @JvmStatic
    external fun nativeTcpOutput(pcb: Long)

    /** Acknowledge received data (update TCP window). */
    @JvmStatic
    external fun nativeTcpRecved(pcb: Long, length: Int)

    /** Gracefully close a TCP connection. */
    @JvmStatic
    external fun nativeTcpClose(pcb: Long)

    /** Abort a TCP connection (immediate RST). */
    @JvmStatic
    external fun nativeTcpAbort(pcb: Long)

    /** Get available send buffer space for a TCP connection. */
    @JvmStatic
    external fun nativeTcpSndbuf(pcb: Long): Int

    /** Get the number of segments queued on a TCP connection. */
    @JvmStatic
    external fun nativeTcpSndQueuelen(pcb: Long): Int

    /**
     * Release a deferred SYN-ACK after the upstream dial has succeeded.
     * Must be called on the lwIP executor thread before any tcp_write.
     * See lwip/ANYWHERE_PATCHES.md "deferred SYN-ACK".
     */
    @JvmStatic
    external fun nativeTcpCompleteAccept(pcb: Long)

    /**
     * Abandon a deferred PCB with RST after the upstream dial has failed.
     * The local app sees ECONNREFUSED on connect(2). Must be called on
     * the lwIP executor thread.
     */
    @JvmStatic
    external fun nativeTcpRejectAccept(pcb: Long)

    // =========================================================================
    // lwIP — UDP Operations
    // =========================================================================

    /** Send a UDP datagram through lwIP (back to TUN). */
    @JvmStatic
    external fun nativeUdpSendto(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean,
        data: ByteArray, length: Int
    )

    // =========================================================================
    // lwIP — Utility
    // =========================================================================

    /** Convert raw IP address bytes to a string. */
    @JvmStatic
    external fun nativeIpToString(addr: ByteArray, isIpv6: Boolean): String?

    // =========================================================================
    // BLAKE3 Hashing
    // =========================================================================

    /** Compute BLAKE3 hash of input. Returns 32 bytes. */
    @JvmStatic
    external fun nativeBlake3Hash(input: ByteArray): ByteArray

    /** Compute BLAKE3 keyed hash. Key must be 32 bytes. Returns 32 bytes. */
    @JvmStatic
    external fun nativeBlake3KeyedHash(key: ByteArray, input: ByteArray): ByteArray

    /** Compute BLAKE3 DeriveKey. Uses context string for domain separation. Returns [outLen] bytes. */
    @JvmStatic
    external fun nativeBlake3DeriveKey(context: String, input: ByteArray, outLen: Int): ByteArray

    // =========================================================================
    // X25519 Key Exchange
    // =========================================================================

    /**
     * Generate an X25519 key pair.
     * @return 64 bytes: privateKey(32) + publicKey(32)
     */
    @JvmStatic
    external fun nativeX25519GenerateKeyPair(): ByteArray

    /**
     * Compute X25519 shared secret.
     * @param privateKey 32-byte private key
     * @param peerPublicKey 32-byte peer public key
     * @return 32-byte shared secret
     */
    @JvmStatic
    external fun nativeX25519KeyAgreement(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray

    // =========================================================================
    // TLS 1.3 Key Derivation
    // =========================================================================

    /**
     * Derive TLS 1.3 handshake keys.
     * @param cipherSuite 0x1301 (AES-128-GCM) or 0x1302 (AES-256-GCM)
     * @return Flat byte array: hsSecret + clientKey + clientIV(12) + serverKey + serverIV(12) + clientTrafficSecret + serverTrafficSecret
     */
    @JvmStatic
    external fun nativeTls13DeriveHandshakeKeys(cipherSuite: Int, sharedSecret: ByteArray, transcript: ByteArray): ByteArray?

    /**
     * Derive TLS 1.3 application keys.
     * @return Flat byte array: clientKey + clientIV(12) + serverKey + serverIV(12)
     */
    @JvmStatic
    external fun nativeTls13DeriveApplicationKeys(cipherSuite: Int, hsSecret: ByteArray, transcript: ByteArray): ByteArray?

    /**
     * Compute TLS 1.3 Client Finished verify data.
     * @return verifyData (32 or 48 bytes depending on cipher suite)
     */
    @JvmStatic
    external fun nativeTls13ComputeFinished(cipherSuite: Int, clientTrafficSecret: ByteArray, transcript: ByteArray): ByteArray?

    /**
     * Compute transcript hash.
     * @return hash (32 or 48 bytes depending on cipher suite)
     */
    @JvmStatic
    external fun nativeTls13TranscriptHash(cipherSuite: Int, messages: ByteArray): ByteArray?

    // =========================================================================
    // YAML Parsing (libyaml)
    // =========================================================================

    /** Parse YAML content and return JSON string representation. Returns null on failure. */
    @JvmStatic
    external fun nativeParseYaml(yamlContent: String): String?
}
