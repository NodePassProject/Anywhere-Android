package com.argsment.anywhere.vpn.quic

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto primitives invoked from the ngtcp2 C backend via JNI. Mirrors
 * `QUICCrypto.swift` — all primitives are implemented via JCE (AES-GCM,
 * ChaCha20-Poly1305, HmacSHA256/384, AES-ECB).
 *
 * Static method signatures must match the JNI GetStaticMethodID lookups in
 * `quic_jni_bridge.c`.
 */
object QuicNativeCrypto {

    private const val AEAD_AES_128_GCM = 0
    private const val AEAD_AES_256_GCM = 1
    private const val AEAD_CHACHA20_POLY1305 = 2

    private const val MD_SHA256 = 0
    private const val MD_SHA384 = 1

    @JvmStatic
    fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray?,
                    aad: ByteArray?, type: Int): ByteArray? = runCatching {
        val pt = plaintext ?: ByteArray(0)
        val aadBytes = aad ?: ByteArray(0)
        when (type) {
            AEAD_AES_128_GCM, AEAD_AES_256_GCM -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"),
                            GCMParameterSpec(128, nonce))
                if (aadBytes.isNotEmpty()) cipher.updateAAD(aadBytes)
                cipher.doFinal(pt)
            }
            AEAD_CHACHA20_POLY1305 -> {
                val cipher = Cipher.getInstance("ChaCha20-Poly1305")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"),
                            IvParameterSpec(nonce))
                if (aadBytes.isNotEmpty()) cipher.updateAAD(aadBytes)
                cipher.doFinal(pt)
            }
            else -> null
        }
    }.getOrNull()

    @JvmStatic
    fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray,
                    aad: ByteArray?, type: Int): ByteArray? = runCatching {
        val aadBytes = aad ?: ByteArray(0)
        when (type) {
            AEAD_AES_128_GCM, AEAD_AES_256_GCM -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"),
                            GCMParameterSpec(128, nonce))
                if (aadBytes.isNotEmpty()) cipher.updateAAD(aadBytes)
                cipher.doFinal(ciphertext)
            }
            AEAD_CHACHA20_POLY1305 -> {
                val cipher = Cipher.getInstance("ChaCha20-Poly1305")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"),
                            IvParameterSpec(nonce))
                if (aadBytes.isNotEmpty()) cipher.updateAAD(aadBytes)
                cipher.doFinal(ciphertext)
            }
            else -> null
        }
    }.getOrNull()

    @JvmStatic
    fun hmac(key: ByteArray, data: ByteArray, mdType: Int): ByteArray? = runCatching {
        val algo = if (mdType == MD_SHA384) "HmacSHA384" else "HmacSHA256"
        val mac = Mac.getInstance(algo)
        mac.init(SecretKeySpec(key, algo))
        mac.doFinal(data)
    }.getOrNull()

    @JvmStatic
    fun aesEcb(key: ByteArray, block: ByteArray): ByteArray? = runCatching {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        cipher.doFinal(block)
    }.getOrNull()

    /**
     * ChaCha20 header protection: counter from sample[0..3] little-endian,
     * nonce from sample[4..15], take the first 5 bytes of the keystream
     * (equivalent to encrypting 5 zero bytes). Returns 5 bytes.
     *
     * Implemented as a pure-Kotlin ChaCha20 block (RFC 8439) instead of
     * JCE's `Cipher.getInstance("ChaCha20")` + `ChaCha20ParameterSpec`,
     * because that combination is rejected by some Android crypto providers
     * with "No AlgorithmParameterSpec classes are supported" — `ChaCha20`
     * raw stream cipher support is uneven across vendor Conscrypt forks.
     */
    @JvmStatic
    fun chacha20Hp(key: ByteArray, sample: ByteArray): ByteArray? = runCatching {
        if (key.size != 32 || sample.size < 16) return@runCatching null
        val counter = readLE32(sample, 0)
        val block = chacha20Block(key, counter, sample, 4)
        block.copyOfRange(0, 5)
    }.getOrNull()

    /** RFC 8439 ChaCha20 block: 32-byte key, 32-bit counter, 12-byte nonce → 64-byte keystream block. */
    private fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray, nonceOff: Int): ByteArray {
        val state = IntArray(16)
        // "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0..7) state[4 + i] = readLE32(key, i * 4)
        state[12] = counter
        state[13] = readLE32(nonce, nonceOff)
        state[14] = readLE32(nonce, nonceOff + 4)
        state[15] = readLE32(nonce, nonceOff + 8)

        val w = state.copyOf()
        repeat(10) {
            // Column rounds
            qr(w, 0, 4,  8, 12); qr(w, 1, 5,  9, 13)
            qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
            // Diagonal rounds
            qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12)
            qr(w, 2, 7,  8, 13); qr(w, 3, 4,  9, 14)
        }
        val out = ByteArray(64)
        for (i in 0..15) writeLE32(out, i * 4, w[i] + state[i])
        return out
    }

    private fun qr(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a], 16)
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c], 12)
        s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a],  8)
        s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c],  7)
    }

    private fun readLE32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
        ((b[off + 1].toInt() and 0xFF) shl 8) or
        ((b[off + 2].toInt() and 0xFF) shl 16) or
        ((b[off + 3].toInt() and 0xFF) shl 24)

    private fun writeLE32(b: ByteArray, off: Int, v: Int) {
        b[off]     = v.toByte()
        b[off + 1] = (v ushr 8).toByte()
        b[off + 2] = (v ushr 16).toByte()
        b[off + 3] = (v ushr 24).toByte()
    }
}
