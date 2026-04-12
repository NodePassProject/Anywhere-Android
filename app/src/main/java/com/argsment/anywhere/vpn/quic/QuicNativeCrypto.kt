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
     * nonce from sample[4..15], encrypt 5 zero bytes. Returns 5 bytes.
     */
    @JvmStatic
    fun chacha20Hp(key: ByteArray, sample: ByteArray): ByteArray? = runCatching {
        // ChaCha20 via JCE takes the nonce as 12 bytes; the counter is a
        // separate int initializer that JCE's IvParameterSpec doesn't set
        // directly. We build a 16-byte composite IV where the spec expects
        // nonce||counter, but JCE's algorithm param for "ChaCha20" takes the
        // nonce as the 12-byte IV and the counter as an AlgorithmParameterSpec
        // wrapper. We'll use the lower-level ChaCha20ParameterSpec (API 28+).
        val counter = (sample[0].toInt() and 0xFF) or
            ((sample[1].toInt() and 0xFF) shl 8) or
            ((sample[2].toInt() and 0xFF) shl 16) or
            ((sample[3].toInt() and 0xFF) shl 24)
        val nonce = sample.copyOfRange(4, 16)
        val cipher = Cipher.getInstance("ChaCha20")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "ChaCha20"),
            javax.crypto.spec.ChaCha20ParameterSpec(nonce, counter)
        )
        val zeros = ByteArray(5)
        cipher.doFinal(zeros)
    }.getOrNull()
}
