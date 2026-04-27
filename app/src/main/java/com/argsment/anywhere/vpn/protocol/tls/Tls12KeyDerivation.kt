package com.argsment.anywhere.vpn.protocol.tls

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * TLS 1.2 key material derived from the master secret. The master secret itself
 * is held by the caller because it is reused for Finished computation.
 */
data class Tls12Keys(
    val clientMACKey: ByteArray,
    val serverMACKey: ByteArray,
    val clientKey: ByteArray,
    val serverKey: ByteArray,
    val clientIV: ByteArray,
    val serverIV: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Tls12Keys) return false
        return clientKey.contentEquals(other.clientKey) &&
                serverKey.contentEquals(other.serverKey) &&
                clientIV.contentEquals(other.clientIV) &&
                serverIV.contentEquals(other.serverIV) &&
                clientMACKey.contentEquals(other.clientMACKey) &&
                serverMACKey.contentEquals(other.serverMACKey)
    }

    override fun hashCode(): Int {
        var result = clientKey.contentHashCode()
        result = 31 * result + serverKey.contentHashCode()
        return result
    }
}

/**
 * TLS 1.2 key derivation (RFC 5246 + RFC 7627).
 */
object Tls12KeyDerivation {

    // -- PRF (Pseudo-Random Function, RFC 5246 §5) --

    /**
     * TLS PRF: P_hash(secret, label || seed) truncated to [length] bytes.
     *
     * @param useSHA384 Use HMAC-SHA384 instead of HMAC-SHA256.
     */
    fun prf(
        secret: ByteArray,
        label: String,
        seed: ByteArray,
        length: Int,
        useSHA384: Boolean = false
    ): ByteArray {
        val labelBytes = label.toByteArray(Charsets.UTF_8)
        val labelAndSeed = ByteArray(labelBytes.size + seed.size)
        System.arraycopy(labelBytes, 0, labelAndSeed, 0, labelBytes.size)
        System.arraycopy(seed, 0, labelAndSeed, labelBytes.size, seed.size)
        return pHash(secret, labelAndSeed, length, useSHA384)
    }

    private fun pHash(
        secret: ByteArray,
        seed: ByteArray,
        length: Int,
        useSHA384: Boolean
    ): ByteArray {
        val algo = if (useSHA384) "HmacSHA384" else "HmacSHA256"
        val mac = Mac.getInstance(algo)
        val keySpec = SecretKeySpec(secret, algo)

        val result = ByteArray(length)
        var filled = 0
        var a = seed  // A(0) = seed

        while (filled < length) {
            mac.init(keySpec)
            a = mac.doFinal(a)  // A(i) = HMAC(secret, A(i-1))

            mac.init(keySpec)
            mac.update(a)
            mac.update(seed)
            val block = mac.doFinal()  // P_hash = HMAC(secret, A(i) || seed)

            val toCopy = minOf(block.size, length - filled)
            System.arraycopy(block, 0, result, filled, toCopy)
            filled += toCopy
        }

        return result
    }

    // -- Master Secret --

    /**
     * Standard master secret (RFC 5246 §8.1):
     * `master_secret = PRF(pre_master_secret, "master secret",
     *                      ClientHello.random + ServerHello.random)[0..47]`
     */
    fun masterSecret(
        preMasterSecret: ByteArray,
        clientRandom: ByteArray,
        serverRandom: ByteArray,
        useSHA384: Boolean = false
    ): ByteArray {
        val seed = ByteArray(clientRandom.size + serverRandom.size)
        System.arraycopy(clientRandom, 0, seed, 0, clientRandom.size)
        System.arraycopy(serverRandom, 0, seed, clientRandom.size, serverRandom.size)
        return prf(preMasterSecret, "master secret", seed, 48, useSHA384)
    }

    /**
     * Extended master secret (RFC 7627):
     * `master_secret = PRF(pre_master_secret, "extended master secret",
     *                      Hash(handshake_messages))[0..47]`
     */
    fun extendedMasterSecret(
        preMasterSecret: ByteArray,
        sessionHash: ByteArray,
        useSHA384: Boolean = false
    ): ByteArray {
        return prf(preMasterSecret, "extended master secret", sessionHash, 48, useSHA384)
    }

    // -- Key Expansion --

    /**
     * Derives encryption keys from the master secret (RFC 5246 §6.3):
     * `key_block = PRF(master_secret, "key expansion",
     *                  server_random + client_random)`
     *
     * The key block is partitioned into:
     * `client_write_MAC_key + server_write_MAC_key + client_write_key + server_write_key
     *  + client_write_IV + server_write_IV`
     */
    fun keysFromMasterSecret(
        masterSecret: ByteArray,
        clientRandom: ByteArray,
        serverRandom: ByteArray,
        cipherSuite: Int
    ): Tls12Keys {
        val macLen = TlsCipherSuite.macLength(cipherSuite)
        val keyLen = TlsCipherSuite.keyLength(cipherSuite)
        val ivLen = TlsCipherSuite.ivLength(cipherSuite)
        val useSHA384 = TlsCipherSuite.usesSHA384(cipherSuite)

        // Seed order is server_random + client_random (reversed from master secret derivation).
        val seed = ByteArray(serverRandom.size + clientRandom.size)
        System.arraycopy(serverRandom, 0, seed, 0, serverRandom.size)
        System.arraycopy(clientRandom, 0, seed, serverRandom.size, clientRandom.size)

        val totalLen = 2 * macLen + 2 * keyLen + 2 * ivLen
        val keyBlock = prf(masterSecret, "key expansion", seed, totalLen, useSHA384)

        var offset = 0
        val clientMACKey = keyBlock.copyOfRange(offset, offset + macLen); offset += macLen
        val serverMACKey = keyBlock.copyOfRange(offset, offset + macLen); offset += macLen
        val clientKey = keyBlock.copyOfRange(offset, offset + keyLen); offset += keyLen
        val serverKey = keyBlock.copyOfRange(offset, offset + keyLen); offset += keyLen
        val clientIV = keyBlock.copyOfRange(offset, offset + ivLen); offset += ivLen
        val serverIV = keyBlock.copyOfRange(offset, offset + ivLen)

        return Tls12Keys(
            clientMACKey = clientMACKey,
            serverMACKey = serverMACKey,
            clientKey = clientKey,
            serverKey = serverKey,
            clientIV = clientIV,
            serverIV = serverIV
        )
    }

    // -- Finished Verify Data --

    /**
     * Computes the 12-byte `verify_data` for the Finished message (RFC 5246 §7.4.9):
     * `verify_data = PRF(master_secret, label, Hash(handshake_messages))[0..11]`
     *
     * @param label `"client finished"` or `"server finished"`.
     */
    fun computeFinishedVerifyData(
        masterSecret: ByteArray,
        label: String,
        handshakeHash: ByteArray,
        useSHA384: Boolean = false
    ): ByteArray {
        return prf(masterSecret, label, handshakeHash, 12, useSHA384)
    }

    fun transcriptHash(messages: ByteArray, useSHA384: Boolean = false): ByteArray {
        val algo = if (useSHA384) "SHA-384" else "SHA-256"
        return MessageDigest.getInstance(algo).digest(messages)
    }

    /**
     * Record MAC for CBC cipher suites:
     * MAC = HMAC(macKey, seqNum(8) || contentType(1) || version(2) || length(2) || payload)
     */
    fun tls10MAC(
        macKey: ByteArray,
        seqNum: Long,
        contentType: Byte,
        protocolVersion: Int,
        payload: ByteArray,
        useSHA384: Boolean = false,
        useSHA256: Boolean = false
    ): ByteArray {
        val algo = when {
            useSHA384 -> "HmacSHA384"
            useSHA256 -> "HmacSHA256"
            else -> "HmacSHA1"
        }
        val mac = Mac.getInstance(algo)
        mac.init(SecretKeySpec(macKey, algo))

        // Sequence number (8 bytes, big-endian)
        for (i in 7 downTo 0) {
            mac.update(((seqNum shr (i * 8)) and 0xFF).toByte())
        }
        // Content type
        mac.update(contentType)
        // Protocol version
        mac.update(((protocolVersion shr 8) and 0xFF).toByte())
        mac.update((protocolVersion and 0xFF).toByte())
        // Payload length
        mac.update(((payload.size shr 8) and 0xFF).toByte())
        mac.update((payload.size and 0xFF).toByte())
        // Payload
        mac.update(payload)

        return mac.doFinal()
    }
}
