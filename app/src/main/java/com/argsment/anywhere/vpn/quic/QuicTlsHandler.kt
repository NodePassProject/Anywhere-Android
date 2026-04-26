package com.argsment.anywhere.vpn.quic

import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.protocol.tls.Tls13KeyDerivation
import com.argsment.anywhere.vpn.protocol.tls.TlsCipherSuite
import com.argsment.anywhere.vpn.util.AnywhereLogger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

private val logger = AnywhereLogger("QUIC-TLS")

/**
 * Runs a TLS 1.3 handshake inside a QUIC connection. Handshake messages are
 * exchanged via ngtcp2 CRYPTO frames instead of TLS records. After key
 * derivation, secrets are pushed back into ngtcp2 via the connection's
 * `installHandshakeKeys` / `installApplicationKeys` callbacks (which in turn
 * call the native derive-and-install wrappers).
 *
 * Mirrors `QUICTLSHandler.swift`. Session resumption (PSK/0-RTT) is
 * deliberately omitted in the Android port — full handshake only on first
 * release; extending to resumption is orthogonal to core correctness.
 */
class QuicTlsHandler(
    private val serverName: String,
    private val alpn: List<String>,
    private val onHandshakeKeys: (rxSecret: ByteArray, txSecret: ByteArray) -> Int,
    private val onApplicationKeys: (rxSecret: ByteArray, txSecret: ByteArray) -> Int,
    private val onCipherSuite: (Int) -> Unit
) {
    enum class State { INITIAL, CLIENT_HELLO_SENT, SERVER_HELLO_RECEIVED, COMPLETED }

    private var state = State.INITIAL
    private var keyDerivation: Tls13KeyDerivation? = null
    private var handshakeSecret: ByteArray? = null
    private var clientHandshakeTrafficSecret: ByteArray? = null

    private val clientRandom = ByteArray(32).also { SecureRandom().nextBytes(it) }

    // Offered key shares — X25519 and secp256r1.
    // X25519 uses our native (BoringSSL) implementation rather than JCE's `XDH`
    // + `NamedParameterSpec`: that combo is missing or rejects the spec type
    // on some vendor Conscrypt forks (throws "No AlgorithmParameterSpec
    // classes are supported"). Native X25519 is portable across all API levels.
    private val x25519PrivateKey: ByteArray
    private val x25519PublicBytes: ByteArray
    private val p256Pair: KeyPair
    private val p256PublicBytes: ByteArray

    // Transcript: concatenation of all handshake messages exchanged.
    private var transcript = ByteArray(0)

    /** Negotiated cipher suite — set from ServerHello. */
    var cipherSuite: Int = TlsCipherSuite.TLS_AES_128_GCM_SHA256
        private set

    /** ALPN selected by server, once EncryptedExtensions is parsed. */
    var negotiatedAlpn: String? = null
        private set

    var serverTransportParams: ByteArray? = null
        private set

    // Partial-message accumulator across CRYPTO frames.
    private val cryptoBuffer = java.io.ByteArrayOutputStream()

    init {
        // X25519 via native BoringSSL: returns 64 bytes = priv(32) || pub(32).
        val x25519Pair = NativeBridge.nativeX25519GenerateKeyPair()
        x25519PrivateKey = x25519Pair.copyOfRange(0, 32)
        x25519PublicBytes = x25519Pair.copyOfRange(32, 64)

        // secp256r1 (P-256) uncompressed point 0x04 || X || Y
        val p256Gen = KeyPairGenerator.getInstance("EC")
        p256Gen.initialize(ECGenParameterSpec("secp256r1"))
        p256Pair = p256Gen.generateKeyPair()
        p256PublicBytes = extractP256Uncompressed(p256Pair.public as ECPublicKey)
    }

    // ------------------------------------------------------------------
    //  ClientHello
    // ------------------------------------------------------------------

    fun buildClientHello(transportParams: ByteArray): ByteArray? {
        val ch = buildQuicClientHello(
            clientRandom = clientRandom,
            serverName = serverName,
            alpn = alpn,
            keyShares = listOf(
                NAMED_GROUP_X25519 to x25519PublicBytes,
                NAMED_GROUP_SECP256R1 to p256PublicBytes
            ),
            quicTransportParams = transportParams
        )
        transcript += ch
        state = State.CLIENT_HELLO_SENT
        return ch
    }

    // ------------------------------------------------------------------
    //  Incoming CRYPTO data
    // ------------------------------------------------------------------

    fun processCryptoData(handle: Long, level: Int, data: ByteArray): Int {
        cryptoBuffer.write(data)
        val buf = cryptoBuffer.toByteArray()
        var consumed = 0
        while (buf.size - consumed >= 4) {
            val msgType = buf[consumed].toInt() and 0xFF
            val msgLen = ((buf[consumed + 1].toInt() and 0xFF) shl 16) or
                ((buf[consumed + 2].toInt() and 0xFF) shl 8) or
                (buf[consumed + 3].toInt() and 0xFF)
            val total = 4 + msgLen
            if (buf.size - consumed < total) break

            val message = buf.copyOfRange(consumed, consumed + total)
            val body = if (message.size > 4) message.copyOfRange(4, message.size) else ByteArray(0)

            // Append to transcript BEFORE processing — Finished computation
            // needs the transcript to include this message.
            transcript += message

            val rv = processHandshakeMessage(msgType, body, handle)
            if (rv != 0) return rv

            consumed += total
        }
        // Keep only unconsumed tail.
        val remaining = buf.copyOfRange(consumed, buf.size)
        cryptoBuffer.reset()
        if (remaining.isNotEmpty()) cryptoBuffer.write(remaining)
        return 0
    }

    private fun processHandshakeMessage(msgType: Int, body: ByteArray, handle: Long): Int {
        return when (msgType) {
            2 -> processServerHello(body, handle)
            8 -> processEncryptedExtensions(body, handle)
            11 -> 0 // Certificate — parsed but we rely on X509 cert validation only when needed; QUIC handshake completes without explicit chain validation in this port (allowInsecure by default for anti-censorship).
            15 -> 0 // CertificateVerify — same note as above
            20 -> processServerFinished(body, handle)
            4 -> 0  // NewSessionTicket — ignored (no resumption in this port)
            else -> {
                logger.warning("Unknown TLS message type: $msgType")
                0
            }
        }
    }

    // ------------------------------------------------------------------
    //  ServerHello
    // ------------------------------------------------------------------

    private fun processServerHello(body: ByteArray, handle: Long): Int {
        if (body.size < 34) return -1

        val serverRandom = body.copyOfRange(2, 34)
        if (serverRandom.contentEquals(HELLO_RETRY_REQUEST_RANDOM)) {
            logger.error("HelloRetryRequest not supported")
            return -1
        }

        var offset = 34
        if (offset >= body.size) return -1
        val sessionIdLen = body[offset].toInt() and 0xFF
        offset += 1 + sessionIdLen

        if (offset + 2 > body.size) return -1
        cipherSuite = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
        offset += 2
        offset += 1 // legacy_compression_method

        if (offset + 2 > body.size) return -1
        val extLen = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
        offset += 2

        var serverKeyShareGroup = 0
        var serverPublicKey: ByteArray? = null
        var supportedVersionsSeen = false
        var negotiatedVersion = 0
        val extEnd = offset + extLen
        while (offset + 4 <= extEnd && offset + 4 <= body.size) {
            val t = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
            val l = ((body[offset + 2].toInt() and 0xFF) shl 8) or (body[offset + 3].toInt() and 0xFF)
            offset += 4
            when (t) {
                0x0033 -> if (offset + 4 <= body.size) {
                    serverKeyShareGroup = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
                    val klen = ((body[offset + 2].toInt() and 0xFF) shl 8) or (body[offset + 3].toInt() and 0xFF)
                    if (offset + 4 + klen <= body.size) {
                        serverPublicKey = body.copyOfRange(offset + 4, offset + 4 + klen)
                    }
                }
                0x002B -> if (l >= 2) {
                    negotiatedVersion = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
                    supportedVersionsSeen = true
                }
            }
            offset += l
        }

        if (!supportedVersionsSeen || negotiatedVersion != 0x0304) {
            logger.error("Invalid supported_versions: $negotiatedVersion")
            return -1
        }
        val spk = serverPublicKey ?: return -1

        val sharedSecret = when (serverKeyShareGroup) {
            NAMED_GROUP_X25519 -> ecdheX25519(spk)
            NAMED_GROUP_SECP256R1 -> ecdheP256(spk)
            else -> { logger.error("Unoffered group: $serverKeyShareGroup"); return -1 }
        } ?: return -1

        onCipherSuite(cipherSuite)
        val kd = Tls13KeyDerivation(cipherSuite)
        keyDerivation = kd

        val (hsSecret, keys) = kd.deriveHandshakeKeys(sharedSecret, transcript)
        handshakeSecret = hsSecret
        clientHandshakeTrafficSecret = keys.clientTrafficSecret

        // Install via native — ngtcp2 takes the *traffic secret* and derives
        // packet-protection keys (quic key / quic iv / quic hp) itself.
        val rv = onHandshakeKeys(keys.serverTrafficSecret, keys.clientTrafficSecret)
        if (rv != 0) { logger.error("install handshake keys failed: $rv"); return -1 }

        state = State.SERVER_HELLO_RECEIVED
        return 0
    }

    // ------------------------------------------------------------------
    //  EncryptedExtensions
    // ------------------------------------------------------------------

    private fun processEncryptedExtensions(body: ByteArray, handle: Long): Int {
        if (body.size < 2) return 0
        val extLen = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        var offset = 2
        val end = offset + extLen
        while (offset + 4 <= end && offset + 4 <= body.size) {
            val t = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
            val l = ((body[offset + 2].toInt() and 0xFF) shl 8) or (body[offset + 3].toInt() and 0xFF)
            offset += 4
            when (t) {
                0x0039 -> if (offset + l <= body.size) {
                    val tp = body.copyOfRange(offset, offset + l)
                    serverTransportParams = tp
                    // Push the decoded params into ngtcp2 so `conn->remote.transport_params`
                    // is non-NULL post-handshake. Mirrors iOS QUICTLSHandler.swift's
                    // ngtcp2_conn_decode_and_set_remote_transport_params call.
                    val rv = QuicBridge.nativeSetRemoteTransportParams(handle, tp)
                    if (rv != 0) {
                        logger.error("Failed to set remote transport params: $rv")
                        return -1
                    }
                }
                0x0010 -> if (l >= 3 && offset + l <= body.size) {
                    // list_len(2) + name_len(1) + name
                    val nameLen = body[offset + 2].toInt() and 0xFF
                    if (nameLen >= 1 && 3 + nameLen <= l) {
                        val nameStart = offset + 3
                        negotiatedAlpn = String(body, nameStart, nameLen, Charsets.UTF_8)
                    }
                }
            }
            offset += l
        }
        if (alpn.isNotEmpty()) {
            val picked = negotiatedAlpn
            if (picked == null || picked !in alpn) {
                logger.error("ALPN mismatch: picked=$picked offered=$alpn")
                return -1
            }
        }
        return 0
    }

    // ------------------------------------------------------------------
    //  Server Finished
    // ------------------------------------------------------------------

    private fun processServerFinished(body: ByteArray, handle: Long): Int {
        val kd = keyDerivation ?: return -1
        val hs = handshakeSecret ?: return -1
        val clientHTS = clientHandshakeTrafficSecret ?: return -1

        // transcript already includes the server Finished at this point (append
        // happened before dispatch). Derive application traffic secrets via
        // the master secret chain.
        val derivedHS = hkdfExpandLabel(kd, hs, "derived", kd.transcriptHash(ByteArray(0)), kd.hashLength)
        val master = hmacExtract(kd, derivedHS, ByteArray(kd.hashLength))
        val serverATS = hkdfExpandLabel(kd, master, "s ap traffic", kd.transcriptHash(transcript), kd.hashLength)
        val clientATS = hkdfExpandLabel(kd, master, "c ap traffic", kd.transcriptHash(transcript), kd.hashLength)

        val rv = onApplicationKeys(serverATS, clientATS)
        if (rv != 0) { logger.error("install app keys failed: $rv"); return -1 }

        val verifyData = kd.computeFinishedVerifyData(clientHTS, transcript)
        val finished = buildFinishedMessage(verifyData)

        val sv = QuicBridge.nativeSubmitCryptoData(handle, QuicBridge.LEVEL_HANDSHAKE, finished)
        if (sv != 0) { logger.error("submit client finished failed: $sv"); return -1 }

        // Append Finished to transcript — not used further here but keeps
        // transcript consistent with what iOS does for NewSessionTicket.
        transcript += finished
        state = State.COMPLETED
        return 0
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private fun buildFinishedMessage(verifyData: ByteArray): ByteArray {
        val out = ByteArray(4 + verifyData.size)
        out[0] = 20
        out[1] = ((verifyData.size shr 16) and 0xFF).toByte()
        out[2] = ((verifyData.size shr 8) and 0xFF).toByte()
        out[3] = (verifyData.size and 0xFF).toByte()
        System.arraycopy(verifyData, 0, out, 4, verifyData.size)
        return out
    }

    /**
     * ECDHE via X25519. Returns the 32-byte shared secret.
     * Server key is a 32-byte raw X25519 public key.
     */
    private fun ecdheX25519(serverPubBytes: ByteArray): ByteArray? = runCatching {
        if (serverPubBytes.size != 32) return@runCatching null
        NativeBridge.nativeX25519KeyAgreement(x25519PrivateKey, serverPubBytes)
    }.getOrNull()

    /**
     * ECDHE via secp256r1. Server key is 0x04 || X(32) || Y(32) uncompressed.
     */
    private fun ecdheP256(serverPubBytes: ByteArray): ByteArray? = runCatching {
        if (serverPubBytes.size != 65 || serverPubBytes[0].toInt() != 0x04) return@runCatching null
        val kf = java.security.KeyFactory.getInstance("EC")
        val params = (p256Pair.public as ECPublicKey).params
        val x = BigInteger(1, serverPubBytes.copyOfRange(1, 33))
        val y = BigInteger(1, serverPubBytes.copyOfRange(33, 65))
        val pub = kf.generatePublic(java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(x, y), params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(p256Pair.private)
        ka.doPhase(pub, true)
        ka.generateSecret()
    }.getOrNull()

    private fun extractP256Uncompressed(pub: ECPublicKey): ByteArray {
        val x = pub.w.affineX.toByteArray().let {
            if (it.size > 32) it.copyOfRange(it.size - 32, it.size)
            else ByteArray(32 - it.size) + it
        }
        val y = pub.w.affineY.toByteArray().let {
            if (it.size > 32) it.copyOfRange(it.size - 32, it.size)
            else ByteArray(32 - it.size) + it
        }
        val out = ByteArray(65)
        out[0] = 0x04
        System.arraycopy(x, 0, out, 1, 32)
        System.arraycopy(y, 0, out, 33, 32)
        return out
    }

    companion object {
        const val NAMED_GROUP_X25519 = 0x001D
        const val NAMED_GROUP_SECP256R1 = 0x0017

        // SHA-256("HelloRetryRequest") — marker server_random for HRR (RFC 8446 §4.1.3).
        private val HELLO_RETRY_REQUEST_RANDOM = byteArrayOf(
            0xCF.toByte(), 0x21, 0xAD.toByte(), 0x74, 0xE5.toByte(), 0x9A.toByte(), 0x61, 0x11,
            0xBE.toByte(), 0x1D, 0x8C.toByte(), 0x02, 0x1E, 0x65, 0xB8.toByte(), 0x91.toByte(),
            0xC2.toByte(), 0xA2.toByte(), 0x11, 0x16, 0x7A, 0xBB.toByte(), 0x8C.toByte(), 0x5E,
            0x07, 0x9E.toByte(), 0x09, 0xE2.toByte(), 0xC8.toByte(), 0xA8.toByte(), 0x33, 0x9C.toByte()
        )
    }
}

// ==========================================================================
//  TLS 1.3 ClientHello builder (QUIC-specific — simpler than full browser
//  fingerprinting, matches iOS QUIC path).
// ==========================================================================

private fun buildQuicClientHello(
    clientRandom: ByteArray,
    serverName: String,
    alpn: List<String>,
    keyShares: List<Pair<Int, ByteArray>>,
    quicTransportParams: ByteArray
): ByteArray {
    val body = java.io.ByteArrayOutputStream()

    // legacy_version
    body.write(0x03); body.write(0x03)
    // random
    body.write(clientRandom)
    // legacy_session_id (empty)
    body.write(0)
    // cipher_suites: AES_128_GCM_SHA256, AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256
    val cs = byteArrayOf(0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
    body.writeU16(cs.size); body.write(cs)
    // legacy_compression_methods
    body.write(1); body.write(0)

    // Extension order MUST match iOS `TLSClientHelloBuilder.buildQUICClientHello`
    // byte-for-byte. Some Hysteria 2 servers (and any front-door that does
    // uTLS-style fingerprint enforcement) accept the QUIC handshake but
    // silently drop inner traffic when the JA3/JA4 hash doesn't match the
    // expected client.
    val ext = java.io.ByteArrayOutputStream()

    // server_name (0x0000)
    run {
        val name = serverName.toByteArray(Charsets.US_ASCII)
        val sni = java.io.ByteArrayOutputStream()
        sni.writeU16(name.size + 3)     // server_name_list length
        sni.write(0)                     // name_type = host_name
        sni.writeU16(name.size); sni.write(name)
        writeExt(ext, 0x0000, sni.toByteArray())
    }
    // supported_groups (0x000A): X25519, secp256r1
    run {
        val sg = java.io.ByteArrayOutputStream()
        sg.writeU16(4); sg.writeU16(0x001D); sg.writeU16(0x0017)
        writeExt(ext, 0x000A, sg.toByteArray())
    }
    // signature_algorithms (0x000D): match iOS list and order exactly.
    run {
        val algos = intArrayOf(
            0x0403, 0x0804, 0x0401,     // ECDSA-P256-SHA256, RSA-PSS-RSAE-SHA256, RSA-PKCS1-SHA256
            0x0503, 0x0805, 0x0501,     // ECDSA-P384-SHA384, RSA-PSS-RSAE-SHA384, RSA-PKCS1-SHA384
            0x0806, 0x0601,             // RSA-PSS-RSAE-SHA512, RSA-PKCS1-SHA512
            0x0203, 0x0201              // ECDSA-SHA1, RSA-PKCS1-SHA1 (legacy)
        )
        val sa = java.io.ByteArrayOutputStream()
        sa.writeU16(algos.size * 2)
        for (a in algos) sa.writeU16(a)
        writeExt(ext, 0x000D, sa.toByteArray())
    }
    // ALPN (0x0010)
    if (alpn.isNotEmpty()) {
        val list = java.io.ByteArrayOutputStream()
        val entries = java.io.ByteArrayOutputStream()
        for (p in alpn) {
            val pb = p.toByteArray(Charsets.US_ASCII)
            entries.write(pb.size); entries.write(pb)
        }
        list.writeU16(entries.size()); list.write(entries.toByteArray())
        writeExt(ext, 0x0010, list.toByteArray())
    }
    // supported_versions (0x002B): TLS 1.3 only
    run {
        val sv = java.io.ByteArrayOutputStream()
        sv.write(2); sv.write(0x03); sv.write(0x04)
        writeExt(ext, 0x002B, sv.toByteArray())
    }
    // psk_key_exchange_modes (0x002D): psk_dhe_ke
    run {
        writeExt(ext, 0x002D, byteArrayOf(1, 1))
    }
    // key_share (0x0033)
    run {
        val ks = java.io.ByteArrayOutputStream()
        val entries = java.io.ByteArrayOutputStream()
        for ((group, pub) in keyShares) {
            entries.writeU16(group); entries.writeU16(pub.size); entries.write(pub)
        }
        ks.writeU16(entries.size()); ks.write(entries.toByteArray())
        writeExt(ext, 0x0033, ks.toByteArray())
    }
    // quic_transport_parameters (0x0039)
    writeExt(ext, 0x0039, quicTransportParams)

    val extBytes = ext.toByteArray()
    body.writeU16(extBytes.size); body.write(extBytes)

    // Wrap as Handshake message: type(1=ClientHello) + length(3) + body
    val bodyBytes = body.toByteArray()
    val out = java.io.ByteArrayOutputStream()
    out.write(1)
    out.write((bodyBytes.size ushr 16) and 0xFF)
    out.write((bodyBytes.size ushr 8) and 0xFF)
    out.write(bodyBytes.size and 0xFF)
    out.write(bodyBytes)
    return out.toByteArray()
}

private fun writeExt(out: java.io.ByteArrayOutputStream, type: Int, data: ByteArray) {
    out.writeU16(type); out.writeU16(data.size); out.write(data)
}

private fun java.io.ByteArrayOutputStream.writeU16(v: Int) {
    write((v ushr 8) and 0xFF); write(v and 0xFF)
}

// ==========================================================================
//  HKDF helpers — mirror iOS TLS13KeyDerivation extensions used by QUIC-TLS.
// ==========================================================================

private fun hmacExtract(kd: Tls13KeyDerivation, salt: ByteArray, ikm: ByteArray): ByteArray {
    // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
    val algo = if (kd.hashLength == 48) "HmacSHA384" else "HmacSHA256"
    val mac = javax.crypto.Mac.getInstance(algo)
    mac.init(javax.crypto.spec.SecretKeySpec(salt, algo))
    return mac.doFinal(ikm)
}

/**
 * HKDF-Expand-Label per RFC 8446 §7.1:
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *     HKDF-Expand(Secret, HkdfLabel, Length)
 * where HkdfLabel = uint16 length + opaque "tls13 " || label + opaque context.
 */
private fun hkdfExpandLabel(kd: Tls13KeyDerivation, secret: ByteArray, label: String,
                            context: ByteArray, length: Int): ByteArray {
    val fullLabel = ("tls13 " + label).toByteArray(Charsets.US_ASCII)
    val info = java.io.ByteArrayOutputStream()
    info.write((length ushr 8) and 0xFF); info.write(length and 0xFF)
    info.write(fullLabel.size); info.write(fullLabel)
    info.write(context.size); info.write(context)
    return hkdfExpand(kd, secret, info.toByteArray(), length)
}

private fun hkdfExpand(kd: Tls13KeyDerivation, prk: ByteArray, info: ByteArray, length: Int): ByteArray {
    val algo = if (kd.hashLength == 48) "HmacSHA384" else "HmacSHA256"
    val hashLen = kd.hashLength
    val mac = javax.crypto.Mac.getInstance(algo)
    mac.init(javax.crypto.spec.SecretKeySpec(prk, algo))
    val out = ByteArray(length)
    var t = ByteArray(0)
    var off = 0
    var counter = 1
    while (off < length) {
        mac.reset()
        if (t.isNotEmpty()) mac.update(t)
        mac.update(info)
        mac.update(counter.toByte())
        t = mac.doFinal()
        val toCopy = minOf(hashLen, length - off)
        System.arraycopy(t, 0, out, off, toCopy)
        off += toCopy
        counter++
    }
    return out
}
