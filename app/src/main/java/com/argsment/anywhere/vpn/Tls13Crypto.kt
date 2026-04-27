package com.argsment.anywhere.vpn

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * TLS 1.3 key derivation (RFC 8446).
 *
 * Uses [javax.crypto.Mac] for HMAC-SHA256/384 and [java.security.MessageDigest]
 * for SHA-256/384, both shipped with every JVM/Android device.
 */
internal object Tls13Crypto {

    // Cipher suite codepoints (RFC 8446 §B.4)
    private const val TLS_AES_128_GCM_SHA256 = 0x1301
    private const val TLS_AES_256_GCM_SHA384 = 0x1302
    private const val TLS_CHACHA20_POLY1305_SHA256 = 0x1303

    private data class SuiteParams(
        val hmacAlgo: String,
        val hashAlgo: String,
        val hashLen: Int,
        val keyLen: Int
    )

    private fun suiteParams(cipherSuite: Int): SuiteParams = when (cipherSuite) {
        TLS_AES_256_GCM_SHA384 -> SuiteParams("HmacSHA384", "SHA-384", 48, 32)
        TLS_CHACHA20_POLY1305_SHA256 -> SuiteParams("HmacSHA256", "SHA-256", 32, 32)
        TLS_AES_128_GCM_SHA256 -> SuiteParams("HmacSHA256", "SHA-256", 32, 16)
        else -> throw IllegalArgumentException("Unsupported cipher suite: 0x${cipherSuite.toString(16)}")
    }

    private fun hmac(algo: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algo)
        mac.init(SecretKeySpec(key, algo))
        return mac.doFinal(data)
    }

    /** HKDF-Extract: PRK = HMAC(salt, IKM). Empty salt is treated as a zero block of `hashLen`. */
    private fun hkdfExtract(algo: String, hashLen: Int, salt: ByteArray?, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt == null || salt.isEmpty()) ByteArray(hashLen) else salt
        return hmac(algo, effectiveSalt, ikm)
    }

    /** HKDF-Expand: T(1) || T(2) || ... truncated to [length]. */
    private fun hkdfExpand(
        algo: String,
        hashLen: Int,
        prk: ByteArray,
        info: ByteArray,
        length: Int
    ): ByteArray {
        val out = ByteArray(length)
        val mac = Mac.getInstance(algo)
        mac.init(SecretKeySpec(prk, algo))

        var prev = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.reset()
            if (prev.isNotEmpty()) mac.update(prev)
            mac.update(info)
            mac.update(counter.toByte())
            prev = mac.doFinal()

            val toCopy = minOf(hashLen, length - offset)
            System.arraycopy(prev, 0, out, offset, toCopy)
            offset += toCopy
            counter++
        }
        return out
    }

    /**
     * HKDF-Expand-Label per RFC 8446 §7.1:
     * `info = Length(2) || "tls13 " || Label || Context_len(1) || Context`
     */
    private fun hkdfExpandLabel(
        algo: String,
        hashLen: Int,
        secret: ByteArray,
        label: String,
        context: ByteArray,
        length: Int
    ): ByteArray {
        val labelBytes = label.toByteArray(Charsets.US_ASCII)
        val fullLabelLen = 6 + labelBytes.size  // "tls13 " prefix
        val info = ByteArray(2 + 1 + fullLabelLen + 1 + context.size)
        var idx = 0
        info[idx++] = ((length ushr 8) and 0xFF).toByte()
        info[idx++] = (length and 0xFF).toByte()
        info[idx++] = fullLabelLen.toByte()
        "tls13 ".toByteArray(Charsets.US_ASCII).copyInto(info, idx); idx += 6
        labelBytes.copyInto(info, idx); idx += labelBytes.size
        info[idx++] = context.size.toByte()
        if (context.isNotEmpty()) context.copyInto(info, idx)

        return hkdfExpand(algo, hashLen, secret, info, length)
    }

    /** Derive-Secret(Secret, Label, Messages) per RFC 8446 §7.1. */
    private fun deriveSecret(
        params: SuiteParams,
        secret: ByteArray,
        label: String,
        messages: ByteArray
    ): ByteArray {
        val transcriptHash = MessageDigest.getInstance(params.hashAlgo).digest(messages)
        return hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, secret, label, transcriptHash, params.hashLen
        )
    }

    /**
     * Derive TLS 1.3 handshake keys.
     *
     * Output layout:
     * `hsSecret(hashLen) || clientKey(keyLen) || clientIV(12) || serverKey(keyLen) ||
     *  serverIV(12) || clientTrafficSecret(hashLen) || serverTrafficSecret(hashLen)`
     */
    fun deriveHandshakeKeys(
        cipherSuite: Int,
        sharedSecret: ByteArray,
        transcript: ByteArray
    ): ByteArray {
        val params = suiteParams(cipherSuite)
        val zeroIkm = ByteArray(params.hashLen)

        // Early Secret = HKDF-Extract(salt=0, IKM=0)
        val earlySecret = hkdfExtract(params.hmacAlgo, params.hashLen, null, zeroIkm)

        // derived = Derive-Secret(EarlySecret, "derived", "")
        val derivedEarly = deriveSecret(params, earlySecret, "derived", ByteArray(0))

        // Handshake Secret = HKDF-Extract(salt=derived, IKM=sharedSecret)
        val hsSecret = hkdfExtract(params.hmacAlgo, params.hashLen, derivedEarly, sharedSecret)

        // client/server handshake traffic secrets
        val clientTrafficSecret = deriveSecret(params, hsSecret, "c hs traffic", transcript)
        val serverTrafficSecret = deriveSecret(params, hsSecret, "s hs traffic", transcript)

        // key + iv per side
        val clientKey = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, clientTrafficSecret, "key", ByteArray(0), params.keyLen
        )
        val clientIV = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, clientTrafficSecret, "iv", ByteArray(0), 12
        )
        val serverKey = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, serverTrafficSecret, "key", ByteArray(0), params.keyLen
        )
        val serverIV = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, serverTrafficSecret, "iv", ByteArray(0), 12
        )

        val total = params.hashLen + params.keyLen + 12 + params.keyLen + 12 +
                params.hashLen + params.hashLen
        val result = ByteArray(total)
        var offset = 0
        hsSecret.copyInto(result, offset); offset += params.hashLen
        clientKey.copyInto(result, offset); offset += params.keyLen
        clientIV.copyInto(result, offset); offset += 12
        serverKey.copyInto(result, offset); offset += params.keyLen
        serverIV.copyInto(result, offset); offset += 12
        clientTrafficSecret.copyInto(result, offset); offset += params.hashLen
        serverTrafficSecret.copyInto(result, offset)
        return result
    }

    /**
     * Derive TLS 1.3 application keys.
     *
     * Output layout: `clientKey(keyLen) || clientIV(12) || serverKey(keyLen) || serverIV(12)`
     */
    fun deriveApplicationKeys(
        cipherSuite: Int,
        hsSecret: ByteArray,
        transcript: ByteArray
    ): ByteArray {
        val params = suiteParams(cipherSuite)
        val zeroIkm = ByteArray(params.hashLen)

        // Derive-Secret(handshake_secret, "derived", "")
        val derivedHs = deriveSecret(params, hsSecret, "derived", ByteArray(0))

        // Master Secret = HKDF-Extract(salt=derived, IKM=0)
        val masterSecret = hkdfExtract(params.hmacAlgo, params.hashLen, derivedHs, zeroIkm)

        val clientATS = deriveSecret(params, masterSecret, "c ap traffic", transcript)
        val serverATS = deriveSecret(params, masterSecret, "s ap traffic", transcript)

        val clientKey = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, clientATS, "key", ByteArray(0), params.keyLen
        )
        val clientIV = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, clientATS, "iv", ByteArray(0), 12
        )
        val serverKey = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, serverATS, "key", ByteArray(0), params.keyLen
        )
        val serverIV = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, serverATS, "iv", ByteArray(0), 12
        )

        val total = params.keyLen + 12 + params.keyLen + 12
        val result = ByteArray(total)
        var offset = 0
        clientKey.copyInto(result, offset); offset += params.keyLen
        clientIV.copyInto(result, offset); offset += 12
        serverKey.copyInto(result, offset); offset += params.keyLen
        serverIV.copyInto(result, offset)
        return result
    }

    /** Compute Client Finished `verify_data` per RFC 8446 §4.4.4. */
    fun computeFinished(
        cipherSuite: Int,
        clientTrafficSecret: ByteArray,
        transcript: ByteArray
    ): ByteArray {
        val params = suiteParams(cipherSuite)
        val finishedKey = hkdfExpandLabel(
            params.hmacAlgo, params.hashLen, clientTrafficSecret, "finished",
            ByteArray(0), params.hashLen
        )
        val transcriptHash = MessageDigest.getInstance(params.hashAlgo).digest(transcript)
        return hmac(params.hmacAlgo, finishedKey, transcriptHash)
    }

    /** Compute the transcript hash (SHA-256 or SHA-384 depending on suite). */
    fun transcriptHash(cipherSuite: Int, messages: ByteArray): ByteArray {
        val params = suiteParams(cipherSuite)
        return MessageDigest.getInstance(params.hashAlgo).digest(messages)
    }
}
