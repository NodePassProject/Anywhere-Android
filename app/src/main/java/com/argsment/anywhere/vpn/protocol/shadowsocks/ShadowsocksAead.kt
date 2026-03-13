package com.argsment.anywhere.vpn.protocol.shadowsocks

import android.util.Base64
import com.argsment.anywhere.vpn.NativeBridge
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// =============================================================================
// ShadowsocksCipher
// =============================================================================

/**
 * Supported Shadowsocks AEAD cipher methods.
 */
enum class ShadowsocksCipher(
    val keySize: Int,
    val isSS2022: Boolean = false
) {
    AES_128_GCM(16),
    AES_256_GCM(32),
    CHACHA20_POLY1305(32),
    NONE(0),
    // Shadowsocks 2022 (BLAKE3-based)
    BLAKE3_AES_128_GCM(16, true),
    BLAKE3_AES_256_GCM(32, true),
    BLAKE3_CHACHA20_POLY1305(32, true);

    /** Salt size — equals keySize for all ciphers. */
    val saltSize: Int get() = keySize

    /** AEAD authentication tag size (16 for all AEAD ciphers). */
    val tagSize: Int get() = if (this == NONE) 0 else 16

    /** AEAD nonce size (12 for GCM and ChaCha20-Poly1305). */
    val nonceSize: Int get() = if (this == NONE) 0 else 12

    /** Whether this cipher uses ChaCha20-Poly1305 (vs AES-GCM). */
    val isChaCha: Boolean
        get() = this == CHACHA20_POLY1305 || this == BLAKE3_CHACHA20_POLY1305

    companion object {
        fun fromMethod(method: String): ShadowsocksCipher? = when (method.lowercase()) {
            "aes-128-gcm" -> AES_128_GCM
            "aes-256-gcm" -> AES_256_GCM
            "chacha20-ietf-poly1305", "chacha20-poly1305" -> CHACHA20_POLY1305
            "none", "plain" -> NONE
            "2022-blake3-aes-128-gcm" -> BLAKE3_AES_128_GCM
            "2022-blake3-aes-256-gcm" -> BLAKE3_AES_256_GCM
            "2022-blake3-chacha20-poly1305" -> BLAKE3_CHACHA20_POLY1305
            else -> null
        }
    }
}

// =============================================================================
// Key Derivation
// =============================================================================

/**
 * Shadowsocks key derivation utilities.
 */
object ShadowsocksKeyDerivation {

    /**
     * Derives a master key from a password using EVP_BytesToKey (MD5-based).
     * Matches `passwordToCipherKey()` in Xray-core config.go.
     */
    fun deriveKey(password: String, keySize: Int): ByteArray {
        if (keySize <= 0) return byteArrayOf()
        val pass = password.toByteArray(Charsets.UTF_8)
        val md5 = MessageDigest.getInstance("MD5")
        var prev = byteArrayOf()
        val result = ByteArrayOutputStream()

        while (result.size() < keySize) {
            md5.reset()
            md5.update(prev)
            md5.update(pass)
            prev = md5.digest()
            result.write(prev)
        }

        return result.toByteArray().copyOf(keySize)
    }

    /**
     * Derives a subkey from the master key and salt using HKDF-SHA1.
     * info = "ss-subkey", matching Xray-core's `hkdfSHA1()`.
     */
    fun deriveSubkey(masterKey: ByteArray, salt: ByteArray, keySize: Int): ByteArray {
        val info = "ss-subkey".toByteArray(Charsets.UTF_8)
        return hkdfSha1(masterKey, salt, info, keySize)
    }

    /**
     * Decodes a base64-encoded PSK for Shadowsocks 2022.
     * Supports colon-separated multi-PSK (returns the last one for client).
     */
    fun decodePSK(password: String, keySize: Int): ByteArray? {
        val parts = password.split(":")
        val lastPart = parts.lastOrNull() ?: return null
        val psk = try {
            Base64.decode(padBase64(lastPart), Base64.DEFAULT)
        } catch (_: Exception) {
            return null
        }
        return if (psk.size == keySize) psk else null
    }

    /**
     * Decodes ALL colon-separated base64-encoded PSKs for multi-user mode.
     */
    fun decodePSKList(password: String, keySize: Int): List<ByteArray>? {
        val parts = password.split(":")
        val result = mutableListOf<ByteArray>()
        for (part in parts) {
            val psk = try {
                Base64.decode(padBase64(part), Base64.DEFAULT)
            } catch (_: Exception) {
                return null
            }
            if (psk.size != keySize) return null
            result.add(psk)
        }
        return result.ifEmpty { null }
    }

    /**
     * Computes the first 16 bytes of BLAKE3 hash of the given data.
     * Used for identity header pskHash computation.
     */
    fun blake3Hash16(data: ByteArray): ByteArray {
        val hash = NativeBridge.nativeBlake3Hash(data)
        return hash.copyOf(16)
    }

    /**
     * Derives an identity subkey using BLAKE3 DeriveKey mode.
     * context = "shadowsocks 2022 identity subkey", input = psk + salt.
     */
    fun deriveIdentitySubkey(psk: ByteArray, salt: ByteArray, keySize: Int): ByteArray {
        val input = psk + salt
        return NativeBridge.nativeBlake3DeriveKey(
            "shadowsocks 2022 identity subkey", input, keySize
        )
    }

    /**
     * Derives a session key using BLAKE3 DeriveKey mode.
     * context = "shadowsocks 2022 session subkey", input = psk + salt.
     * Matching sing-shadowsocks SessionKey().
     */
    fun deriveSessionKey(psk: ByteArray, salt: ByteArray, keySize: Int): ByteArray {
        val input = psk + salt
        return NativeBridge.nativeBlake3DeriveKey(
            "shadowsocks 2022 session subkey", input, keySize
        )
    }

    private fun padBase64(string: String): String {
        val remainder = string.length % 4
        return if (remainder == 0) string
        else string + "=".repeat(4 - remainder)
    }

    /**
     * HKDF-SHA1: Extract + Expand.
     */
    private fun hkdfSha1(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int
    ): ByteArray {
        val hmacAlgo = "HmacSHA1"
        val hashLen = 20

        // Extract
        val extractMac = Mac.getInstance(hmacAlgo)
        extractMac.init(SecretKeySpec(salt, hmacAlgo))
        val prk = extractMac.doFinal(ikm)

        // Expand
        val expandMac = Mac.getInstance(hmacAlgo)
        expandMac.init(SecretKeySpec(prk, hmacAlgo))
        val result = ByteArrayOutputStream()
        var prev = byteArrayOf()
        var counter: Byte = 1

        while (result.size() < length) {
            expandMac.reset()
            expandMac.update(prev)
            expandMac.update(info)
            expandMac.update(counter)
            prev = expandMac.doFinal()
            result.write(prev)
            counter++
        }

        return result.toByteArray().copyOf(length)
    }
}

// =============================================================================
// Nonce Generator
// =============================================================================

/**
 * Generates incrementing AEAD nonces matching Xray-core's GenerateAEADNonceWithSize.
 * Starts at all 0xFF, increments little-endian before each use.
 * First returned nonce = all zeros.
 */
class ShadowsocksNonce(size: Int) {
    private val bytes = ByteArray(size) { 0xFF.toByte() }

    /** Increments the nonce (little-endian) and returns the new value. */
    fun next(): ByteArray {
        for (i in bytes.indices) {
            bytes[i]++
            if (bytes[i] != 0.toByte()) break
        }
        return bytes.copyOf()
    }
}

// =============================================================================
// AEAD Seal/Open
// =============================================================================

/**
 * Low-level AEAD operations.
 */
object ShadowsocksAEADCrypto {

    private val random = SecureRandom()

    fun seal(cipher: ShadowsocksCipher, key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return plaintext

        return if (cipher.isChaCha) {
            chaCha20Poly1305Seal(key, nonce, plaintext)
        } else {
            aesGcmSeal(key, nonce, plaintext)
        }
    }

    fun open(cipher: ShadowsocksCipher, key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return ciphertext

        return if (cipher.isChaCha) {
            chaCha20Poly1305Open(key, nonce, ciphertext)
        } else {
            aesGcmOpen(key, nonce, ciphertext)
        }
    }

    fun generateRandomSalt(size: Int): ByteArray {
        val salt = ByteArray(size)
        random.nextBytes(salt)
        return salt
    }

    /**
     * AES-GCM seal. Returns ciphertext + tag (no nonce prefix).
     */
    private fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        return c.doFinal(plaintext)
    }

    /**
     * AES-GCM open. Input = ciphertext + tag.
     */
    private fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        return c.doFinal(ciphertext)
    }

    /**
     * ChaCha20-Poly1305 seal. Returns ciphertext + tag (no nonce prefix).
     */
    private fun chaCha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
        val spec = IvParameterSpec(nonce)
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), spec)
        return c.doFinal(plaintext)
    }

    /**
     * ChaCha20-Poly1305 open. Input = ciphertext + tag.
     */
    private fun chaCha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val c = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
        val spec = IvParameterSpec(nonce)
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), spec)
        return c.doFinal(ciphertext)
    }
}

// =============================================================================
// AES-ECB Single Block (for SS 2022 identity headers)
// =============================================================================

object AesEcb {
    fun encrypt(key: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16)
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block)
    }

    fun decrypt(key: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16)
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block)
    }
}

// =============================================================================
// ShadowsocksAEADWriter (Encrypt)
// =============================================================================

/**
 * Encrypts data into Shadowsocks AEAD chunk format.
 *
 * Chunk format: `[Encrypted 2-byte length + 16-byte tag] [Encrypted payload + 16-byte tag]`
 * Max payload per chunk: 0x3FFF (16383 bytes).
 * The salt is prepended to the first output.
 */
class ShadowsocksAEADWriter(
    private val cipher: ShadowsocksCipher,
    masterKey: ByteArray
) {
    private var nonce = ShadowsocksNonce(cipher.nonceSize)
    private val salt: ByteArray
    private val subkey: ByteArray
    private var saltWritten = false

    init {
        if (cipher == ShadowsocksCipher.NONE) {
            salt = byteArrayOf()
            subkey = byteArrayOf()
        } else {
            salt = ShadowsocksAEADCrypto.generateRandomSalt(cipher.saltSize)
            subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey, salt, cipher.keySize)
        }
    }

    /** Encrypts plaintext into AEAD chunks. Prepends salt on first call. */
    fun seal(plaintext: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return plaintext

        val output = ByteArrayOutputStream()

        if (!saltWritten) {
            output.write(salt)
            saltWritten = true
        }

        var offset = 0
        while (offset < plaintext.size) {
            val remaining = plaintext.size - offset
            val chunkSize = minOf(remaining, MAX_PAYLOAD_SIZE)
            val chunk = plaintext.copyOfRange(offset, offset + chunkSize)

            // Encrypt 2-byte length header
            val lengthBytes = byteArrayOf((chunkSize shr 8).toByte(), (chunkSize and 0xFF).toByte())
            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, nonce.next(), lengthBytes))

            // Encrypt payload
            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, nonce.next(), chunk))

            offset += chunkSize
        }

        return output.toByteArray()
    }

    companion object {
        /** Maximum payload bytes per chunk (matching Xray-core). */
        const val MAX_PAYLOAD_SIZE = 0x3FFF // 16383
    }
}

// =============================================================================
// ShadowsocksAEADReader (Decrypt)
// =============================================================================

/**
 * Decrypts Shadowsocks AEAD chunk format.
 *
 * State machine: `.waitingSalt` -> `.readingLength` -> `.readingPayload`
 */
class ShadowsocksAEADReader(
    private val cipher: ShadowsocksCipher,
    private val masterKey: ByteArray
) {
    private var subkey: ByteArray? = null
    private var nonce = ShadowsocksNonce(cipher.nonceSize)
    private var state = if (cipher == ShadowsocksCipher.NONE) State.READING_LENGTH else State.WAITING_SALT
    private var buffer = ByteArrayOutputStream()
    private var bufferBytes = byteArrayOf()
    private var bufferOffset = 0
    private var pendingPayloadLength = 0

    private enum class State {
        WAITING_SALT,
        READING_LENGTH,
        READING_PAYLOAD
    }

    /** Compaction threshold — avoid O(n) shifts until dead space is significant. */
    private companion object {
        const val COMPACT_THRESHOLD = 4096
    }

    init {
        if (cipher == ShadowsocksCipher.NONE) {
            subkey = byteArrayOf()
        }
    }

    /** Feeds ciphertext and returns any available decrypted plaintext. */
    fun open(ciphertext: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return ciphertext

        // Append to buffer
        val newBuf = ByteArray(bufferBytes.size - bufferOffset + ciphertext.size)
        System.arraycopy(bufferBytes, bufferOffset, newBuf, 0, bufferBytes.size - bufferOffset)
        System.arraycopy(ciphertext, 0, newBuf, bufferBytes.size - bufferOffset, ciphertext.size)
        bufferBytes = newBuf
        bufferOffset = 0

        val output = ByteArrayOutputStream()

        while (true) {
            val remaining = bufferBytes.size - bufferOffset
            when (state) {
                State.WAITING_SALT -> {
                    if (remaining < cipher.saltSize) break
                    val salt = bufferBytes.copyOfRange(bufferOffset, bufferOffset + cipher.saltSize)
                    bufferOffset += cipher.saltSize
                    subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey, salt, cipher.keySize)
                    state = State.READING_LENGTH
                    continue
                }

                State.READING_LENGTH -> {
                    val needed = 2 + cipher.tagSize
                    if (remaining < needed) break
                    val encryptedLength = bufferBytes.copyOfRange(bufferOffset, bufferOffset + needed)
                    bufferOffset += needed
                    val lengthData = ShadowsocksAEADCrypto.open(cipher, subkey!!, nonce.next(), encryptedLength)
                    require(lengthData.size == 2) { "Invalid length data" }
                    pendingPayloadLength =
                        ((lengthData[0].toInt() and 0xFF) shl 8) or (lengthData[1].toInt() and 0xFF)
                    state = State.READING_PAYLOAD
                    continue
                }

                State.READING_PAYLOAD -> {
                    val needed = pendingPayloadLength + cipher.tagSize
                    if (remaining < needed) break
                    val encryptedPayload = bufferBytes.copyOfRange(bufferOffset, bufferOffset + needed)
                    bufferOffset += needed
                    val payload = ShadowsocksAEADCrypto.open(cipher, subkey!!, nonce.next(), encryptedPayload)
                    output.write(payload)
                    state = State.READING_LENGTH
                    continue
                }
            }
            break
        }

        // Compact buffer
        if (bufferOffset > COMPACT_THRESHOLD) {
            bufferBytes = bufferBytes.copyOfRange(bufferOffset, bufferBytes.size)
            bufferOffset = 0
        } else if (bufferOffset > 0 && bufferOffset == bufferBytes.size) {
            bufferBytes = byteArrayOf()
            bufferOffset = 0
        }

        return output.toByteArray()
    }
}

// =============================================================================
// UDP Crypto
// =============================================================================

/**
 * Per-packet encryption/decryption for legacy Shadowsocks UDP.
 */
object ShadowsocksUDPCrypto {

    /** Encrypts a UDP packet: random salt + single AEAD seal (no chunking). */
    fun encrypt(cipher: ShadowsocksCipher, masterKey: ByteArray, payload: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return payload

        val salt = ShadowsocksAEADCrypto.generateRandomSalt(cipher.saltSize)
        val subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey, salt, cipher.keySize)

        // Single AEAD seal with all-zero nonce
        val nonce = ByteArray(cipher.nonceSize)
        val encrypted = ShadowsocksAEADCrypto.seal(cipher, subkey, nonce, payload)

        return salt + encrypted
    }

    /** Decrypts a UDP packet: extract salt, derive subkey, AEAD open. */
    fun decrypt(cipher: ShadowsocksCipher, masterKey: ByteArray, data: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return data

        require(data.size > cipher.saltSize + cipher.tagSize) { "Data too short" }

        val salt = data.copyOf(cipher.saltSize)
        val ciphertext = data.copyOfRange(cipher.saltSize, data.size)
        val subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey, salt, cipher.keySize)

        val nonce = ByteArray(cipher.nonceSize)
        return ShadowsocksAEADCrypto.open(cipher, subkey, nonce, ciphertext)
    }
}

// =============================================================================
// Errors
// =============================================================================

sealed class ShadowsocksError(message: String) : Exception(message) {
    class InvalidMethod(method: String) : ShadowsocksError("Unsupported Shadowsocks method: $method")
    class DecryptionFailed : ShadowsocksError("Shadowsocks AEAD decryption failed")
    class InvalidAddress : ShadowsocksError("Invalid Shadowsocks address header")
    class BadTimestamp : ShadowsocksError("Shadowsocks 2022 bad timestamp")
    class BadRequestSalt : ShadowsocksError("Shadowsocks 2022 bad request salt")
    class BadHeaderType : ShadowsocksError("Shadowsocks 2022 bad header type")
    class InvalidPSK : ShadowsocksError("Invalid Shadowsocks 2022 PSK")
}
