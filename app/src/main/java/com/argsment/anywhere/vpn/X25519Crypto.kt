package com.argsment.anywhere.vpn

import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.SecureRandom

/**
 * X25519 Diffie-Hellman key exchange (RFC 7748).
 *
 * Delegates the curve arithmetic to BouncyCastle (`org.bouncycastle.math.ec.rfc7748.X25519`)
 * which is constant-time and well-tested.
 */
internal object X25519Crypto {

    private val random = SecureRandom()

    /**
     * Generate an X25519 key pair.
     * @return 64 bytes: privateKey(32) + publicKey(32). The private key is
     * already clamped per RFC 7748 §5.
     */
    fun generateKeyPair(): ByteArray {
        val privateKey = ByteArray(X25519.SCALAR_SIZE)
        // BC's generatePrivateKey draws from the supplied SecureRandom and
        // applies RFC 7748 clamping internally.
        X25519.generatePrivateKey(random, privateKey)

        val publicKey = ByteArray(X25519.POINT_SIZE)
        X25519.scalarMultBase(privateKey, 0, publicKey, 0)

        val result = ByteArray(64)
        System.arraycopy(privateKey, 0, result, 0, 32)
        System.arraycopy(publicKey, 0, result, 32, 32)
        return result
    }

    /**
     * Compute X25519 shared secret.
     * @param privateKey 32-byte private key.
     * @param peerPublicKey 32-byte peer public key.
     * @return 32-byte shared secret.
     * @throws IllegalArgumentException if either key is not 32 bytes.
     * @throws RuntimeException if the result is the all-zero point (low-order peer key).
     */
    fun keyAgreement(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(privateKey.size == X25519.SCALAR_SIZE) { "privateKey must be exactly 32 bytes" }
        require(peerPublicKey.size == X25519.POINT_SIZE) { "peerPublicKey must be exactly 32 bytes" }

        val shared = ByteArray(X25519.POINT_SIZE)
        X25519.scalarMult(privateKey, 0, peerPublicKey, 0, shared, 0)

        // Reject all-zero output (low-order point).
        var acc: Byte = 0
        for (b in shared) acc = (acc.toInt() or b.toInt()).toByte()
        if (acc.toInt() == 0) {
            throw RuntimeException("X25519 key agreement failed (low-order point)")
        }
        return shared
    }
}
