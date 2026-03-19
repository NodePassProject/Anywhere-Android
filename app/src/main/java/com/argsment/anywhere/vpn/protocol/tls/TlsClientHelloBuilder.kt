package com.argsment.anywhere.vpn.protocol.tls

import com.argsment.anywhere.data.model.TlsFingerprint
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * TLS ClientHello builder with browser-specific fingerprint emulation.
 *
 * Each fingerprint produces a ClientHello matching the corresponding browser's
 * real TLS implementation (cipher suites, extensions, ordering) as defined by
 * the uTLS library v1.8.2 used by Xray-core.
 */
object TlsClientHelloBuilder {

    // -- GREASE --

    private val greaseTable: IntArray = intArrayOf(
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A.toUShort().toInt(), 0x9A9A.toUShort().toInt(),
        0xAAAA.toUShort().toInt(), 0xBABA.toUShort().toInt(),
        0xCACA.toUShort().toInt(), 0xDADA.toUShort().toInt(),
        0xEAEA.toUShort().toInt(), 0xFAFA.toUShort().toInt()
    )

    /** Returns a GREASE value deterministically selected by [seed]. */
    private fun grease(seed: Byte): Int {
        return greaseTable[(seed.toInt() and 0xFF) % greaseTable.size]
    }

    private fun isGREASE(value: Int): Boolean {
        return (value and 0x0F0F) == 0x0A0A
    }

    // -- Deterministic Pseudo-Random Derivation --

    /**
     * Derives deterministic pseudo-random bytes from the connection random + label.
     * Used for ECH GREASE enc/payload and P256 key derivation.
     */
    private fun derivePRBytes(random: ByteArray, label: String, length: Int): ByteArray {
        val result = ByteArray(length)
        var filled = 0
        var counter: Byte = 0
        val md = MessageDigest.getInstance("SHA-256")
        while (filled < length) {
            md.reset()
            md.update(random)
            md.update(label.toByteArray(Charsets.UTF_8))
            md.update(counter)
            val hash = md.digest()
            val toCopy = minOf(hash.size, length - filled)
            System.arraycopy(hash, 0, result, filled, toCopy)
            filled += toCopy
            counter = ((counter.toInt() and 0xFF) + 1).toByte()
        }
        return result
    }

    // -- Generic Extension Helpers --

    /** Appends a UInt16 in big-endian to a ByteArray builder. */
    private fun MutableList<Byte>.appendU16(value: Int) {
        add(((value shr 8) and 0xFF).toByte())
        add((value and 0xFF).toByte())
    }

    /** Wraps payload with a TLS extension header (type + length). */
    private fun ext(type: Int, payload: ByteArray): ByteArray {
        val result = mutableListOf<Byte>()
        result.appendU16(type)
        result.appendU16(payload.size)
        for (b in payload) result.add(b)
        return result.toByteArray()
    }

    /** Empty extension (type + zero-length). */
    private fun ext(type: Int): ByteArray {
        return ext(type, ByteArray(0))
    }

    // -- Individual Extension Builders --

    /** 0x0000 -- Server Name Indication (SNI). */
    fun buildSNIExtension(serverName: String): ByteArray {
        val nameBytes = serverName.toByteArray(Charsets.UTF_8)
        val payload = mutableListOf<Byte>()
        val listLen = nameBytes.size + 3
        payload.appendU16(listLen)
        payload.add(0x00) // Host name type: DNS
        payload.appendU16(nameBytes.size)
        for (b in nameBytes) payload.add(b)
        return ext(0x0000, payload.toByteArray())
    }

    /** 0x0005 -- OCSP status request. */
    private fun statusRequestExt(): ByteArray {
        return ext(0x0005, byteArrayOf(0x01, 0x00, 0x00, 0x00, 0x00))
    }

    /** 0x000A -- Supported groups / named curves. */
    private fun supportedGroupsExt(groups: IntArray): ByteArray {
        val payload = mutableListOf<Byte>()
        payload.appendU16(groups.size * 2)
        for (g in groups) payload.appendU16(g)
        return ext(0x000A, payload.toByteArray())
    }

    /** 0x000B -- EC point formats (uncompressed only). */
    private fun ecPointFormatsExt(): ByteArray {
        return ext(0x000B, byteArrayOf(0x01, 0x00))
    }

    /** 0x000D -- Signature algorithms. */
    private fun signatureAlgorithmsExt(algs: IntArray): ByteArray {
        val payload = mutableListOf<Byte>()
        payload.appendU16(algs.size * 2)
        for (a in algs) payload.appendU16(a)
        return ext(0x000D, payload.toByteArray())
    }

    /** 0x0010 -- ALPN. */
    private fun alpnExt(protocols: List<String>): ByteArray {
        val list = mutableListOf<Byte>()
        for (proto in protocols) {
            val bytes = proto.toByteArray(Charsets.UTF_8)
            list.add(bytes.size.toByte())
            for (b in bytes) list.add(b)
        }
        val payload = mutableListOf<Byte>()
        payload.appendU16(list.size)
        payload.addAll(list)
        return ext(0x0010, payload.toByteArray())
    }

    /** 0x0012 -- Signed certificate timestamp (empty, requesting SCTs). */
    private fun sctExt(): ByteArray = ext(0x0012)

    /** 0x0015 -- Padding extension. */
    private fun paddingExt(length: Int): ByteArray {
        return ext(0x0015, ByteArray(maxOf(0, length)))
    }

    /** 0x0017 -- Extended master secret. */
    private fun extendedMasterSecretExt(): ByteArray = ext(0x0017)

    /** 0x001B -- Compress certificate (RFC 8879). */
    private fun compressCertExt(algorithms: IntArray): ByteArray {
        val payload = mutableListOf<Byte>()
        payload.add((algorithms.size * 2).toByte())
        for (a in algorithms) payload.appendU16(a)
        return ext(0x001B, payload.toByteArray())
    }

    /** 0x001C -- Record size limit. */
    private fun recordSizeLimitExt(limit: Int): ByteArray {
        val payload = mutableListOf<Byte>()
        payload.appendU16(limit)
        return ext(0x001C, payload.toByteArray())
    }

    /** 0x0022 -- Delegated credentials (Firefox). */
    private fun delegatedCredentialsExt(algs: IntArray): ByteArray {
        val payload = mutableListOf<Byte>()
        payload.appendU16(algs.size * 2)
        for (a in algs) payload.appendU16(a)
        return ext(0x0022, payload.toByteArray())
    }

    /** 0x0023 -- Session ticket. */
    private fun sessionTicketExt(): ByteArray = ext(0x0023)

    /** 0x002B -- Supported versions. */
    private fun supportedVersionsExt(versions: IntArray): ByteArray {
        val payload = mutableListOf<Byte>()
        payload.add((versions.size * 2).toByte())
        for (v in versions) payload.appendU16(v)
        return ext(0x002B, payload.toByteArray())
    }

    /** 0x002D -- PSK key exchange modes. */
    private fun pskKeyExchangeModesExt(): ByteArray {
        return ext(0x002D, byteArrayOf(0x01, 0x01)) // 1 mode: psk_dhe_ke (0x01)
    }

    /** 0x0033 -- Key share. */
    private fun keyShareExt(entries: List<Pair<Int, ByteArray>>): ByteArray {
        val list = mutableListOf<Byte>()
        for ((group, keyData) in entries) {
            list.appendU16(group)
            list.appendU16(keyData.size)
            for (b in keyData) list.add(b)
        }
        val payload = mutableListOf<Byte>()
        payload.appendU16(list.size)
        payload.addAll(list)
        return ext(0x0033, payload.toByteArray())
    }

    /** 0x4469 (17513) -- Application settings (ALPS). */
    private fun applicationSettingsExt(protocols: List<String>): ByteArray {
        val list = mutableListOf<Byte>()
        for (proto in protocols) {
            val bytes = proto.toByteArray(Charsets.UTF_8)
            list.add(bytes.size.toByte())
            for (b in bytes) list.add(b)
        }
        val payload = mutableListOf<Byte>()
        payload.appendU16(list.size)
        payload.addAll(list)
        return ext(0x4469, payload.toByteArray())
    }

    /**
     * 0xFE0D -- GREASE Encrypted Client Hello.
     *
     * Wire format: type(1) + kdf(2) + aead(2) + configId(1) + encLen(2) + enc + payloadLen(2) + payload
     */
    private fun greaseECHExt(random: ByteArray, kdfId: Int, aeadId: Int, payloadLen: Int): ByteArray {
        val enc = derivePRBytes(random, "ech-enc", 32)
        val payload = derivePRBytes(random, "ech-payload", payloadLen)
        val configId = derivePRBytes(random, "ech-config", 1)[0]

        val data = mutableListOf<Byte>()
        data.add(0x00) // ClientHello type: outer
        data.appendU16(kdfId)
        data.appendU16(aeadId)
        data.add(configId)
        data.appendU16(enc.size)
        for (b in enc) data.add(b)
        data.appendU16(payload.size)
        for (b in payload) data.add(b)
        return ext(0xFE0D, data.toByteArray())
    }

    /** 0xFF01 -- Renegotiation info (empty, initial handshake). */
    private fun renegotiationInfoExt(): ByteArray {
        return ext(0xFF01.toUShort().toInt(), byteArrayOf(0x00))
    }

    /** GREASE extension (random type, empty data). */
    private fun greaseExt(value: Int): ByteArray = ext(value)

    // -- Cipher Suite Serialization --

    private fun cipherSuitesData(suites: IntArray): ByteArray {
        val data = mutableListOf<Byte>()
        for (s in suites) data.appendU16(s)
        return data.toByteArray()
    }

    // -- BoringSSL Padding --

    /**
     * Calculates BoringSSL-style padding: if the full record (5 + ClientHello) is 256-511 bytes,
     * pad to exactly 512. Returns the padding data length (excluding extension header), or null.
     */
    private fun boringPaddingDataLength(clientHelloLen: Int): Int? {
        val unpaddedLen = clientHelloLen
        if (unpaddedLen <= 0xFF || unpaddedLen >= 0x200) return null
        val needed = 0x200 - unpaddedLen
        // Matching iOS: return null if can't fit extension header (4 bytes)
        return if (needed >= 4) (needed - 4) else null
    }

    // -- Chrome Extension Shuffling --

    /**
     * Shuffles extension data blocks deterministically for the Chrome fingerprint.
     * GREASE extensions and padding are kept at their original positions.
     */
    private fun shuffleChromeExtensions(exts: MutableList<ByteArray>, random: ByteArray) {
        // Identify fixed-position extensions (GREASE type or padding type 0x0015)
        val fixed = mutableSetOf<Int>()
        for (i in exts.indices) {
            if (exts[i].size < 2) continue
            val type = ((exts[i][0].toInt() and 0xFF) shl 8) or (exts[i][1].toInt() and 0xFF)
            if (isGREASE(type) || type == 0x0015) {
                fixed.add(i)
            }
        }

        val shuffleable = (exts.indices).filter { it !in fixed }
        if (shuffleable.size <= 1) return

        // Deterministic PRNG seeded from random bytes 24-31
        var seed: Long = if (random.size >= 32) {
            var v = 0L
            for (i in 0..7) {
                v = v or ((random[24 + i].toLong() and 0xFF) shl (i * 8))
            }
            v
        } else {
            0L
        }

        // Fisher-Yates shuffle on shuffleable indices
        for (i in shuffleable.size - 1 downTo 1) {
            seed = seed * 6364136223846793005L + 1442695040888963407L
            val j = ((seed ushr 33) % (i + 1).toLong()).toInt()
            if (i != j) {
                val temp = exts[shuffleable[i]]
                exts[shuffleable[i]] = exts[shuffleable[j]]
                exts[shuffleable[j]] = temp
            }
        }
    }

    // -- P256 Key Derivation (Firefox) --

    /**
     * Derives a deterministic P256 public key from the connection random.
     * Used only for Firefox fingerprint (which offers both X25519 and P256 key shares).
     */
    private fun deriveP256PublicKey(random: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(random)
        md.update("p256-fingerprint".toByteArray(Charsets.UTF_8))
        val seed = md.digest()

        return try {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), java.security.SecureRandom(seed))
            val kp = kpg.generateKeyPair()
            val ecPub = kp.public as ECPublicKey
            val w = ecPub.w
            // Uncompressed point: 0x04 + x(32) + y(32) = 65 bytes
            val x = w.affineX.toByteArray().let { bytes ->
                when {
                    bytes.size == 32 -> bytes
                    bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
                    else -> ByteArray(32 - bytes.size) + bytes
                }
            }
            val y = w.affineY.toByteArray().let { bytes ->
                when {
                    bytes.size == 32 -> bytes
                    bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
                    else -> ByteArray(32 - bytes.size) + bytes
                }
            }
            byteArrayOf(0x04) + x + y
        } catch (_: Exception) {
            // Astronomically unlikely fallback (~2^-128 probability)
            ByteArray(65)
        }
    }

    // -- Public API --

    /**
     * Build a TLS ClientHello with browser-specific fingerprint emulation.
     *
     * @param fingerprint Which browser to emulate.
     * @param random 32-byte TLS random (also seeds deterministic GREASE and shuffle).
     * @param sessionId 32-byte session ID.
     * @param serverName SNI hostname.
     * @param publicKey X25519 ephemeral public key for the key_share extension.
     * @param alpn Optional ALPN override. When null, uses browser default (["h2", "http/1.1"]).
     */
    fun buildRawClientHello(
        fingerprint: TlsFingerprint,
        random: ByteArray,
        sessionId: ByteArray,
        serverName: String,
        publicKey: ByteArray,
        alpn: List<String>? = null
    ): ByteArray {
        val resolved: TlsFingerprint = if (fingerprint == TlsFingerprint.RANDOM) {
            val options = TlsFingerprint.concreteFingerprints
            options[(random[0].toInt() and 0xFF) % options.size]
        } else {
            fingerprint
        }

        val (suites, extensions, padded) = buildFingerprintedParts(
            fingerprint = resolved,
            random = random,
            serverName = serverName,
            publicKey = publicKey,
            alpn = alpn
        )

        return assembleClientHello(
            random = random,
            sessionId = sessionId,
            cipherSuites = suites,
            extensions = extensions,
            applyBoringPadding = padded
        )
    }

    /**
     * Assembles a complete ClientHello handshake message from pre-built parts.
     */
    private fun assembleClientHello(
        random: ByteArray,
        sessionId: ByteArray,
        cipherSuites: ByteArray,
        extensions: ByteArray,
        applyBoringPadding: Boolean
    ): ByteArray {
        val ch = mutableListOf<Byte>()
        ch.add(0x01) // Handshake type: ClientHello
        val lengthOffset = ch.size
        ch.add(0x00); ch.add(0x00); ch.add(0x00) // length placeholder
        ch.add(0x03); ch.add(0x03) // Legacy version: TLS 1.2
        for (b in random) ch.add(b)
        ch.add(sessionId.size.toByte())
        for (b in sessionId) ch.add(b)
        ch.appendU16(cipherSuites.size)
        for (b in cipherSuites) ch.add(b)
        ch.add(0x01) // Compression methods length
        ch.add(0x00) // null compression

        var exts = extensions.toMutableList()

        if (applyBoringPadding) {
            // BoringSSL pads if the total handshake message is 256-511 bytes to reach 512.
            val unpaddedLen = ch.size + 2 + exts.size
            val padLen = boringPaddingDataLength(unpaddedLen)
            if (padLen != null) {
                val padExt = paddingExt(padLen)
                for (b in padExt) exts.add(b)
            }
        }

        ch.appendU16(exts.size)
        ch.addAll(exts)

        // Fill handshake length (excludes type byte and 3-byte length field)
        val length = ch.size - 4
        ch[lengthOffset] = ((length shr 16) and 0xFF).toByte()
        ch[lengthOffset + 1] = ((length shr 8) and 0xFF).toByte()
        ch[lengthOffset + 2] = (length and 0xFF).toByte()

        return ch.toByteArray()
    }

    // -- Per-Browser Fingerprint Dispatch --

    private data class FingerprintParts(
        val cipherSuites: ByteArray,
        val extensions: ByteArray,
        val needsPadding: Boolean
    )

    private fun buildFingerprintedParts(
        fingerprint: TlsFingerprint,
        random: ByteArray,
        serverName: String,
        publicKey: ByteArray,
        alpn: List<String>?
    ): FingerprintParts {
        return when (fingerprint) {
            TlsFingerprint.CHROME_120 -> buildChrome120(random, serverName, publicKey, alpn)
            TlsFingerprint.FIREFOX_120 -> buildFirefox120(random, serverName, publicKey, alpn)
            TlsFingerprint.SAFARI_16 -> buildSafari16(random, serverName, publicKey, alpn)
            TlsFingerprint.IOS_14 -> buildIOS14(random, serverName, publicKey, alpn)
            TlsFingerprint.EDGE_106 -> buildEdge106(random, serverName, publicKey, alpn)
            TlsFingerprint.RANDOM -> error("random fingerprint must be resolved before dispatch")
        }
    }

    // -- Chrome 120 --

    private fun buildChrome120(
        random: ByteArray, serverName: String, publicKey: ByteArray, alpn: List<String>?
    ): FingerprintParts {
        // BoringSSL GREASE values
        val gCipher  = grease(random[24])
        val gExt1    = grease(random[25])
        val gGroup   = grease(random[26])
        val gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        // Ensure gExt2 != gExt1 to avoid duplicate extension types (matching iOS)
        if (gExt2 == gExt1) gExt2 = grease(((random[29].toInt() and 0xFF) + 1).toByte())

        val suites = cipherSuitesData(intArrayOf(
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02B, 0xC02F, 0xC02C, 0xC030,                 // ECDHE AES-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC013, 0xC014,                                   // ECDHE AES-CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ))

        val protocols = alpn ?: listOf("h2", "http/1.1")

        // BoringGREASEECH: KDF=HKDF-SHA256(0x0001), AEAD=AES-128-GCM(0x0001)
        // Payload length picked from [128,160,192,224] + 16 AEAD overhead
        val echPayloadLens = intArrayOf(144, 176, 208, 240)
        val echPayloadLen = echPayloadLens[(random[30].toInt() and 0xFF) % echPayloadLens.size]

        val exts = mutableListOf(
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(intArrayOf(gGroup, 0x001D, 0x0017, 0x0018)),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(intArrayOf(
                0x0403, 0x0804, 0x0401,  // ECDSA-P256-SHA256, PSS-SHA256, PKCS1-SHA256
                0x0503, 0x0805, 0x0501,  // ECDSA-P384-SHA384, PSS-SHA384, PKCS1-SHA384
                0x0806, 0x0601           // PSS-SHA512, PKCS1-SHA512
            )),
            sctExt(),
            keyShareExt(listOf(
                Pair(gGroup, byteArrayOf(0x00)),       // GREASE key share (must match supported_groups)
                Pair(0x001D, publicKey)                 // X25519
            )),
            pskKeyExchangeModesExt(),
            supportedVersionsExt(intArrayOf(gVersion, 0x0304, 0x0303)),
            compressCertExt(intArrayOf(0x0002)),                        // Brotli
            applicationSettingsExt(listOf("h2")),
            greaseECHExt(random, kdfId = 0x0001, aeadId = 0x0001, payloadLen = echPayloadLen),
            greaseExt(gExt2)
        )

        // Chrome 106+ shuffles non-GREASE, non-padding extensions
        shuffleChromeExtensions(exts, random)

        val extensionsData = concatenateArrays(exts)
        return FingerprintParts(suites, extensionsData, true)
    }

    // -- Firefox 120 --

    private fun buildFirefox120(
        random: ByteArray, serverName: String, publicKey: ByteArray, alpn: List<String>?
    ): FingerprintParts {
        // Firefox uses no GREASE values
        val suites = cipherSuitesData(intArrayOf(
            0x1301, 0x1303, 0x1302,                           // TLS 1.3 (ChaCha20 before AES-256)
            0xC02B, 0xC02F,                                   // ECDHE AES-128-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC02C, 0xC030,                                   // ECDHE AES-256-GCM
            0xC00A, 0xC009,                                   // ECDHE AES-CBC (ECDSA)
            0xC013, 0xC014,                                   // ECDHE AES-CBC (RSA)
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ))

        val protocols = alpn ?: listOf("h2", "http/1.1")

        // Firefox offers two key shares: X25519 + P256
        val p256PublicKey = deriveP256PublicKey(random)

        // Firefox ECH: pick AES-128-GCM or ChaCha20 deterministically
        val echAead = if ((random[30].toInt() and 0xFF) % 2 == 0) 0x0001 else 0x0003

        val exts = listOf(
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(intArrayOf(
                0x001D, 0x0017, 0x0018, 0x0019,              // X25519, P256, P384, P521
                0x0100, 0x0101                                // ffdhe2048, ffdhe3072
            )),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            delegatedCredentialsExt(intArrayOf(0x0403, 0x0503, 0x0603, 0x0203)),
            keyShareExt(listOf(
                Pair(0x001D, publicKey),                      // X25519
                Pair(0x0017, p256PublicKey)                    // P256
            )),
            supportedVersionsExt(intArrayOf(0x0304, 0x0303)),
            signatureAlgorithmsExt(intArrayOf(
                0x0403, 0x0503, 0x0603,                       // ECDSA P256/P384/P521
                0x0804, 0x0805, 0x0806,                       // PSS SHA256/384/512
                0x0401, 0x0501, 0x0601,                       // PKCS1 SHA256/384/512
                0x0203, 0x0201                                // ECDSA-SHA1, PKCS1-SHA1
            )),
            pskKeyExchangeModesExt(),
            recordSizeLimitExt(0x4001),
            greaseECHExt(random, kdfId = 0x0001, aeadId = echAead, payloadLen = 239)
        )

        val extensionsData = concatenateArrays(exts)
        return FingerprintParts(suites, extensionsData, false) // No BoringSSL padding
    }

    // -- Safari 16.0 --

    private fun buildSafari16(
        random: ByteArray, serverName: String, publicKey: ByteArray, alpn: List<String>?
    ): FingerprintParts {
        val gCipher  = grease(random[24])
        val gExt1    = grease(random[25])
        val gGroup   = grease(random[26])
        val gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if (gExt2 == gExt1) gExt2 = grease(((random[29].toInt() and 0xFF) + 1).toByte())

        val suites = cipherSuitesData(intArrayOf(
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,                         // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,                         // ECDHE RSA (GCM, ChaCha)
            0xC00A, 0xC009,                                   // ECDHE ECDSA CBC
            0xC014, 0xC013,                                   // ECDHE RSA CBC
            0x009D, 0x009C,                                   // RSA GCM
            0x0035, 0x002F,                                   // RSA CBC
            0xC008, 0xC012, 0x000A                           // 3DES (legacy)
        ))

        val protocols = alpn ?: listOf("h2", "http/1.1")

        val exts = listOf(
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(intArrayOf(gGroup, 0x001D, 0x0017, 0x0018, 0x0019)),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(intArrayOf(
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0203,
                0x0805, 0x0805,                               // Intentional duplicate (real Safari)
                0x0501,
                0x0806, 0x0601,
                0x0201
            )),
            sctExt(),
            keyShareExt(listOf(
                Pair(gGroup, byteArrayOf(0x00)),              // GREASE key share
                Pair(0x001D, publicKey)
            )),
            pskKeyExchangeModesExt(),
            supportedVersionsExt(intArrayOf(gVersion, 0x0304, 0x0303, 0x0302, 0x0301)),
            compressCertExt(intArrayOf(0x0001)),              // Zlib
            greaseExt(gExt2)
        )

        val extensionsData = concatenateArrays(exts)
        return FingerprintParts(suites, extensionsData, true)
    }

    // -- iOS 14 --

    private fun buildIOS14(
        random: ByteArray, serverName: String, publicKey: ByteArray, alpn: List<String>?
    ): FingerprintParts {
        val gCipher  = grease(random[24])
        val gExt1    = grease(random[25])
        val gGroup   = grease(random[26])
        val gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if (gExt2 == gExt1) gExt2 = grease(((random[29].toInt() and 0xFF) + 1).toByte())

        val suites = cipherSuitesData(intArrayOf(
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,                         // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,                         // ECDHE RSA (GCM, ChaCha)
            0xC024, 0xC023, 0xC00A, 0xC009,                 // ECDHE ECDSA CBC (SHA384, SHA256, SHA)
            0xC028, 0xC027, 0xC014, 0xC013,                 // ECDHE RSA CBC
            0x009D, 0x009C,                                   // RSA GCM
            0x003D, 0x003C,                                   // RSA CBC SHA256
            0x0035, 0x002F,                                   // RSA CBC SHA
            0xC008, 0xC012, 0x000A                           // 3DES (legacy)
        ))

        val protocols = alpn ?: listOf("h2", "http/1.1")

        val exts = listOf(
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(intArrayOf(gGroup, 0x001D, 0x0017, 0x0018, 0x0019)),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(intArrayOf(
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0203,
                0x0805, 0x0805,                               // Intentional duplicate (real iOS 14 TLS client)
                0x0501,
                0x0806, 0x0601,
                0x0201
            )),
            sctExt(),
            keyShareExt(listOf(
                Pair(gGroup, byteArrayOf(0x00)),              // GREASE key share
                Pair(0x001D, publicKey)
            )),
            pskKeyExchangeModesExt(),
            supportedVersionsExt(intArrayOf(gVersion, 0x0304, 0x0303, 0x0302, 0x0301)),
            greaseExt(gExt2)
        )

        val extensionsData = concatenateArrays(exts)
        return FingerprintParts(suites, extensionsData, true)
    }

    // -- Edge 106 --

    private fun buildEdge106(
        random: ByteArray, serverName: String, publicKey: ByteArray, alpn: List<String>?
    ): FingerprintParts {
        val gCipher  = grease(random[24])
        val gExt1    = grease(random[25])
        val gGroup   = grease(random[26])
        val gVersion = grease(random[28])
        var gExt2    = grease(random[29])
        if (gExt2 == gExt1) gExt2 = grease(((random[29].toInt() and 0xFF) + 1).toByte())

        val suites = cipherSuitesData(intArrayOf(
            gCipher,
            0x1301, 0x1302, 0x1303,                         // TLS 1.3
            0xC02B, 0xC02F, 0xC02C, 0xC030,                 // ECDHE AES-GCM
            0xCCA9, 0xCCA8,                                   // ECDHE ChaCha20
            0xC013, 0xC014,                                   // ECDHE AES-CBC
            0x009C, 0x009D,                                   // RSA AES-GCM
            0x002F, 0x0035                                    // RSA AES-CBC
        ))

        val protocols = alpn ?: listOf("h2", "http/1.1")

        val exts = listOf(
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(intArrayOf(gGroup, 0x001D, 0x0017, 0x0018)),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(intArrayOf(
                0x0403, 0x0804, 0x0401,
                0x0503, 0x0805, 0x0501,
                0x0806, 0x0601
            )),
            sctExt(),
            keyShareExt(listOf(
                Pair(gGroup, byteArrayOf(0x00)),              // GREASE key share
                Pair(0x001D, publicKey)
            )),
            pskKeyExchangeModesExt(),
            supportedVersionsExt(intArrayOf(gVersion, 0x0304, 0x0303)),
            compressCertExt(intArrayOf(0x0002)),              // Brotli
            applicationSettingsExt(listOf("h2")),
            greaseExt(gExt2)
        )

        val extensionsData = concatenateArrays(exts)
        return FingerprintParts(suites, extensionsData, true)
    }

    // -- Helpers --

    /** Concatenate a list of byte arrays into a single byte array. */
    private fun concatenateArrays(arrays: List<ByteArray>): ByteArray {
        val totalLen = arrays.sumOf { it.size }
        val result = ByteArray(totalLen)
        var offset = 0
        for (arr in arrays) {
            System.arraycopy(arr, 0, result, offset, arr.size)
            offset += arr.size
        }
        return result
    }

    /** Wrap a ClientHello message in a TLS record. */
    fun wrapInTLSRecord(clientHello: ByteArray): ByteArray {
        val record = mutableListOf<Byte>()
        record.add(0x16) // Content type: Handshake
        record.add(0x03)
        record.add(0x01) // TLS 1.0 for compatibility
        record.appendU16(clientHello.size)
        for (b in clientHello) record.add(b)
        return record.toByteArray()
    }
}
