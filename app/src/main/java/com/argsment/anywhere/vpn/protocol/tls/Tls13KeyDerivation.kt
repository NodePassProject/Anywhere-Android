package com.argsment.anywhere.vpn.protocol.tls

import com.argsment.anywhere.vpn.NativeBridge

/**
 * TLS 1.3 cipher suite constants.
 */
object TlsCipherSuite {
    const val TLS_AES_128_GCM_SHA256: Int = 0x1301
    const val TLS_AES_256_GCM_SHA384: Int = 0x1302
    const val TLS_CHACHA20_POLY1305_SHA256: Int = 0x1303
}

/**
 * TLS 1.3 handshake traffic keys.
 */
data class TlsHandshakeKeys(
    val clientKey: ByteArray,
    val clientIV: ByteArray,
    val serverKey: ByteArray,
    val serverIV: ByteArray,
    val clientTrafficSecret: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TlsHandshakeKeys) return false
        return clientKey.contentEquals(other.clientKey) &&
                clientIV.contentEquals(other.clientIV) &&
                serverKey.contentEquals(other.serverKey) &&
                serverIV.contentEquals(other.serverIV) &&
                clientTrafficSecret.contentEquals(other.clientTrafficSecret)
    }

    override fun hashCode(): Int {
        var result = clientKey.contentHashCode()
        result = 31 * result + clientIV.contentHashCode()
        result = 31 * result + serverKey.contentHashCode()
        result = 31 * result + serverIV.contentHashCode()
        result = 31 * result + clientTrafficSecret.contentHashCode()
        return result
    }
}

/**
 * TLS 1.3 application traffic keys.
 */
data class TlsApplicationKeys(
    val clientKey: ByteArray,
    val clientIV: ByteArray,
    val serverKey: ByteArray,
    val serverIV: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TlsApplicationKeys) return false
        return clientKey.contentEquals(other.clientKey) &&
                clientIV.contentEquals(other.clientIV) &&
                serverKey.contentEquals(other.serverKey) &&
                serverIV.contentEquals(other.serverIV)
    }

    override fun hashCode(): Int {
        var result = clientKey.contentHashCode()
        result = 31 * result + clientIV.contentHashCode()
        result = 31 * result + serverKey.contentHashCode()
        result = 31 * result + serverIV.contentHashCode()
        return result
    }
}

/**
 * TLS 1.3 key derivation utilities.
 *
 * Delegates all cryptographic operations to [NativeBridge] JNI functions
 * which use OpenSSL/BoringSSL for HKDF-Expand-Label and transcript hashing.
 *
 * Supports both AES-128-GCM-SHA256 (0x1301) and AES-256-GCM-SHA384 (0x1302).
 */
class Tls13KeyDerivation(
    val cipherSuite: Int = TlsCipherSuite.TLS_AES_128_GCM_SHA256
) {
    /** Hash output length based on cipher suite. */
    val hashLength: Int
        get() = if (cipherSuite == TlsCipherSuite.TLS_AES_256_GCM_SHA384) 48 else 32

    /** Encryption key length based on cipher suite. */
    val keyLength: Int
        get() = when (cipherSuite) {
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256 -> 32
            else -> 16
        }

    /**
     * Derive TLS 1.3 handshake keys from shared secret and transcript.
     *
     * @param sharedSecret The X25519 shared secret (32 bytes).
     * @param transcript The concatenated ClientHello + ServerHello handshake messages.
     * @return A pair of (handshakeSecret, TlsHandshakeKeys).
     */
    fun deriveHandshakeKeys(
        sharedSecret: ByteArray,
        transcript: ByteArray
    ): Pair<ByteArray, TlsHandshakeKeys> {
        val result = NativeBridge.nativeTls13DeriveHandshakeKeys(
            cipherSuite, sharedSecret, transcript
        ) ?: throw IllegalStateException("Failed to derive TLS 1.3 handshake keys")

        // Result layout: hsSecret(hashLength) + clientKey(keyLength) + clientIV(12) +
        //                serverKey(keyLength) + serverIV(12) + clientTrafficSecret(hashLength)
        var offset = 0

        val hsSecret = result.copyOfRange(offset, offset + hashLength)
        offset += hashLength

        val clientKey = result.copyOfRange(offset, offset + keyLength)
        offset += keyLength

        val clientIV = result.copyOfRange(offset, offset + 12)
        offset += 12

        val serverKey = result.copyOfRange(offset, offset + keyLength)
        offset += keyLength

        val serverIV = result.copyOfRange(offset, offset + 12)
        offset += 12

        val clientTrafficSecret = result.copyOfRange(offset, offset + hashLength)

        val keys = TlsHandshakeKeys(
            clientKey = clientKey,
            clientIV = clientIV,
            serverKey = serverKey,
            serverIV = serverIV,
            clientTrafficSecret = clientTrafficSecret
        )
        return Pair(hsSecret, keys)
    }

    /**
     * Derive application keys from the full transcript (including server Finished).
     *
     * @param handshakeSecret The handshake secret from [deriveHandshakeKeys].
     * @param fullTranscript The full handshake transcript including all messages through Finished.
     * @return The application traffic keys.
     */
    fun deriveApplicationKeys(
        handshakeSecret: ByteArray,
        fullTranscript: ByteArray
    ): TlsApplicationKeys {
        val result = NativeBridge.nativeTls13DeriveApplicationKeys(
            cipherSuite, handshakeSecret, fullTranscript
        ) ?: throw IllegalStateException("Failed to derive TLS 1.3 application keys")

        // Result layout: clientKey(keyLength) + clientIV(12) + serverKey(keyLength) + serverIV(12)
        var offset = 0

        val clientKey = result.copyOfRange(offset, offset + keyLength)
        offset += keyLength

        val clientIV = result.copyOfRange(offset, offset + 12)
        offset += 12

        val serverKey = result.copyOfRange(offset, offset + keyLength)
        offset += keyLength

        val serverIV = result.copyOfRange(offset, offset + 12)

        return TlsApplicationKeys(
            clientKey = clientKey,
            clientIV = clientIV,
            serverKey = serverKey,
            serverIV = serverIV
        )
    }

    /**
     * Compute Client Finished verify data.
     *
     * @param clientTrafficSecret The client handshake traffic secret.
     * @param transcript The handshake transcript up to and including server Finished.
     * @return The verify data (32 or 48 bytes depending on cipher suite).
     */
    fun computeFinishedVerifyData(
        clientTrafficSecret: ByteArray,
        transcript: ByteArray
    ): ByteArray {
        return NativeBridge.nativeTls13ComputeFinished(
            cipherSuite, clientTrafficSecret, transcript
        ) ?: throw IllegalStateException("Failed to compute TLS 1.3 finished verify data")
    }

    /**
     * Compute transcript hash.
     *
     * @param messages The concatenated handshake messages to hash.
     * @return The hash (32 or 48 bytes depending on cipher suite).
     */
    fun transcriptHash(messages: ByteArray): ByteArray {
        return NativeBridge.nativeTls13TranscriptHash(
            cipherSuite, messages
        ) ?: throw IllegalStateException("Failed to compute TLS 1.3 transcript hash")
    }
}
