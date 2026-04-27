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

enum class ShadowsocksCipher(
    val keySize: Int,
    val isSS2022: Boolean = false
) {
    AES_128_GCM(16),
    AES_256_GCM(32),
    CHACHA20_POLY1305(32),
    NONE(0),
    BLAKE3_AES_128_GCM(16, true),
    BLAKE3_AES_256_GCM(32, true),
    BLAKE3_CHACHA20_POLY1305(32, true);

    val saltSize: Int get() = keySize
    val tagSize: Int get() = if (this == NONE) 0 else 16
    val nonceSize: Int get() = if (this == NONE) 0 else 12

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

object ShadowsocksKeyDerivation {

    /** EVP_BytesToKey (MD5-based) master-key derivation from a password. */
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

    /** HKDF-SHA1 subkey derivation with info = "ss-subkey". */
    fun deriveSubkey(masterKey: ByteArray, salt: ByteArray, keySize: Int): ByteArray {
        val info = "ss-subkey".toByteArray(Charsets.UTF_8)
        return hkdfSha1(masterKey, salt, info, keySize)
    }

    /**
     * Decodes a base64-encoded SS 2022 PSK. Colon-separated multi-PSK returns
     * only the last entry (the client PSK).
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

    /** Decodes every colon-separated base64-encoded PSK for multi-user mode. */
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

    /** First 16 bytes of BLAKE3(data). Used for the identity-header pskHash. */
    fun blake3Hash16(data: ByteArray): ByteArray {
        val hash = NativeBridge.nativeBlake3Hash(data)
        return hash.copyOf(16)
    }

    /** BLAKE3 DeriveKey: context "shadowsocks 2022 identity subkey", input = psk + salt. */
    fun deriveIdentitySubkey(psk: ByteArray, salt: ByteArray, keySize: Int): ByteArray {
        val input = psk + salt
        return NativeBridge.nativeBlake3DeriveKey(
            "shadowsocks 2022 identity subkey", input, keySize
        )
    }

    /** BLAKE3 DeriveKey: context "shadowsocks 2022 session subkey", input = psk + salt. */
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

    private fun hkdfSha1(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int
    ): ByteArray {
        val hmacAlgo = "HmacSHA1"
        val hashLen = 20

        val extractMac = Mac.getInstance(hmacAlgo)
        extractMac.init(SecretKeySpec(salt, hmacAlgo))
        val prk = extractMac.doFinal(ikm)

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

/**
 * Incrementing AEAD nonce. Initialized to all 0xFF so the first [next] returns all zeros;
 * increments little-endian on each call.
 */
class ShadowsocksNonce(size: Int) {
    private val bytes = ByteArray(size) { 0xFF.toByte() }

    fun next(): ByteArray {
        for (i in bytes.indices) {
            bytes[i]++
            if (bytes[i] != 0.toByte()) break
        }
        return bytes.copyOf()
    }
}

object ShadowsocksAEADCrypto {

    private val random = SecureRandom()

    // Per-thread Cipher cache: Cipher is not thread-safe, so each thread keeps its own
    // instance to avoid Cipher.getInstance() per operation.
    private val tlAesGcm = ThreadLocal<Cipher>()
    private val tlChaCha = ThreadLocal<Cipher>()

    private fun aesGcmCipher(): Cipher {
        return tlAesGcm.get() ?: Cipher.getInstance("AES/GCM/NoPadding").also { tlAesGcm.set(it) }
    }

    private fun chaCha20Cipher(): Cipher {
        return tlChaCha.get() ?: Cipher.getInstance("ChaCha20/Poly1305/NoPadding").also { tlChaCha.set(it) }
    }

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

    private fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val c = aesGcmCipher()
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return c.doFinal(plaintext)
    }

    private fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val c = aesGcmCipher()
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return c.doFinal(ciphertext)
    }

    private fun chaCha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val c = chaCha20Cipher()
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        return c.doFinal(plaintext)
    }

    private fun chaCha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val c = chaCha20Cipher()
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        return c.doFinal(ciphertext)
    }
}

/** Single-block AES-ECB used for SS 2022 identity headers. */
object AesEcb {
    private val tlCipher = ThreadLocal<Cipher>()

    private fun cipher(): Cipher {
        return tlCipher.get() ?: Cipher.getInstance("AES/ECB/NoPadding").also { tlCipher.set(it) }
    }

    fun encrypt(key: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16)
        val c = cipher()
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block)
    }

    fun decrypt(key: ByteArray, block: ByteArray): ByteArray {
        require(block.size == 16)
        val c = cipher()
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block)
    }
}

/**
 * Encrypts data into Shadowsocks AEAD chunks.
 *
 * Chunk: `[Encrypted 2-byte length + 16-byte tag] [Encrypted payload + 16-byte tag]`.
 * Max payload per chunk is 0x3FFF (16,383 bytes). The salt is prepended on the first output.
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

    /** Prepends salt on first call; subsequent calls emit chunks only. */
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

            val lengthBytes = byteArrayOf((chunkSize shr 8).toByte(), (chunkSize and 0xFF).toByte())
            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, nonce.next(), lengthBytes))

            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, nonce.next(), chunk))

            offset += chunkSize
        }

        return output.toByteArray()
    }

    companion object {
        const val MAX_PAYLOAD_SIZE = 0x3FFF // 16383
    }
}

/**
 * Decrypts Shadowsocks AEAD chunks. State machine:
 * `WAITING_SALT` → `READING_LENGTH` ⇄ `READING_PAYLOAD`.
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

    /** Defer compaction until dead space is significant to avoid O(n) shifts on each read. */
    private companion object {
        const val COMPACT_THRESHOLD = 4096
    }

    init {
        if (cipher == ShadowsocksCipher.NONE) {
            subkey = byteArrayOf()
        }
    }

    fun open(ciphertext: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return ciphertext

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

/** Per-packet AEAD for legacy Shadowsocks UDP. */
object ShadowsocksUDPCrypto {

    /** UDP encrypt: random salt + single AEAD seal with all-zero nonce, no chunking. */
    fun encrypt(cipher: ShadowsocksCipher, masterKey: ByteArray, payload: ByteArray): ByteArray {
        if (cipher == ShadowsocksCipher.NONE) return payload

        val salt = ShadowsocksAEADCrypto.generateRandomSalt(cipher.saltSize)
        val subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey, salt, cipher.keySize)

        val nonce = ByteArray(cipher.nonceSize)
        val encrypted = ShadowsocksAEADCrypto.seal(cipher, subkey, nonce, payload)

        return salt + encrypted
    }

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

sealed class ShadowsocksError(message: String) : Exception(message) {
    class InvalidMethod(method: String) : ShadowsocksError("Unsupported Shadowsocks method: $method")
    class DecryptionFailed : ShadowsocksError("Shadowsocks AEAD decryption failed")
    class InvalidAddress : ShadowsocksError("Invalid Shadowsocks address header")
    class BadTimestamp : ShadowsocksError("Shadowsocks 2022 bad timestamp")
    class BadRequestSalt : ShadowsocksError("Shadowsocks 2022 bad request salt")
    class BadHeaderType : ShadowsocksError("Shadowsocks 2022 bad header type")
    class InvalidPSK : ShadowsocksError("Invalid Shadowsocks 2022 PSK")
}
