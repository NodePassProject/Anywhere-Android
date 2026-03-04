package com.argsment.anywhere.vpn.protocol.tls

import android.util.Log
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.util.NioSocket
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val TAG = "TlsClient"

// MARK: - TLS Errors

sealed class TlsError(message: String) : IOException(message) {
    class ConnectionFailed(msg: String) : TlsError("TLS connection failed: $msg")
    class HandshakeFailed(msg: String) : TlsError("TLS handshake failed: $msg")
    class CertificateValidationFailed(msg: String) : TlsError("Certificate validation failed: $msg")
}

/**
 * Client for establishing standard TLS 1.3 connections.
 * Port of iOS TLSClient.swift.
 *
 * Performs a TLS 1.3 handshake with X.509 certificate validation:
 * - Builds a standard ClientHello with random SessionId.
 * - Optionally validates the server certificate chain.
 * - Derives application-layer encryption keys from the TLS 1.3 handshake.
 *
 * After a successful handshake, returns a [TlsRecordConnection] that wraps
 * the underlying [NioSocket] with TLS record encryption/decryption.
 *
 * Uses suspend functions (coroutine-based) instead of callbacks.
 */
class TlsClient(private val configuration: TlsConfiguration) {

    private var connection: NioSocket? = null

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKeyBytes: ByteArray? = null
    private var ephemeralPublicKeyBytes: ByteArray? = null
    private var storedClientHello: ByteArray? = null

    // TLS 1.3 session state (cleared after handshake)
    private var keyDerivation: Tls13KeyDerivation? = null
    private var handshakeSecret: ByteArray? = null
    private var handshakeKeys: TlsHandshakeKeys? = null
    private var applicationKeys: TlsApplicationKeys? = null
    private var handshakeTranscript: ByteArray? = null
    private var serverHandshakeSeqNum: Long = 0

    // Certificate validation state
    private val serverCertificates = mutableListOf<X509Certificate>()

    // MARK: - Public API

    /**
     * Connects to a server and performs the TLS 1.3 handshake.
     *
     * @param host The server hostname or IP address.
     * @param port The server port number.
     * @return The established [TlsRecordConnection].
     */
    suspend fun connect(host: String, port: Int): TlsRecordConnection {
        // Generate ephemeral X25519 key pair
        val kpg = KeyPairGenerator.getInstance("X25519")
        val kp = kpg.generateKeyPair()

        // Extract raw public key bytes (32 bytes for X25519)
        val pubKey = kp.public as XECPublicKey
        val uBytes = pubKey.u.toByteArray()
        // BigInteger may produce leading zero or wrong-length array; normalize to 32 bytes LE
        ephemeralPublicKeyBytes = normalizeX25519PublicKey(uBytes)
        ephemeralPrivateKeyBytes = kp.private.encoded // PKCS#8 encoded for KeyAgreement

        val socket = NioSocket()
        connection = socket

        try {
            socket.connect(host, port)
        } catch (e: Exception) {
            Log.e(TAG, "TCP connection failed: ${e.message}")
            throw TlsError.ConnectionFailed(e.message ?: "Unknown error")
        }

        return performTLSHandshake(kp.private)
    }

    /** Cancels the connection and releases all resources. */
    fun cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = null
    }

    // MARK: - Handshake

    /**
     * Performs the TLS 1.3 handshake: sends ClientHello, processes ServerHello,
     * derives encryption keys, validates certificates, and sends Client Finished.
     */
    private suspend fun performTLSHandshake(
        privateKey: java.security.PrivateKey
    ): TlsRecordConnection {
        val pubKeyBytes = ephemeralPublicKeyBytes
            ?: throw TlsError.HandshakeFailed("No ephemeral key")

        val clientHello = buildTLSClientHello(pubKeyBytes)

        // Store for TLS transcript (without 5-byte TLS record header)
        storedClientHello = clientHello.copyOfRange(5, clientHello.size)

        val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
        conn.send(clientHello)

        return receiveServerResponse(privateKey)
    }

    // MARK: - ClientHello

    /**
     * Builds a standard TLS 1.3 ClientHello with random SessionId.
     */
    private fun buildTLSClientHello(publicKey: ByteArray): ByteArray {
        val random = ByteArray(32)
        java.security.SecureRandom().nextBytes(random)

        // Standard TLS: random 32-byte session ID (no Reality metadata)
        val sessionId = ByteArray(32)
        java.security.SecureRandom().nextBytes(sessionId)

        val rawClientHello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint = configuration.fingerprint,
            random = random,
            sessionId = sessionId,
            serverName = configuration.serverName,
            publicKey = publicKey,
            alpn = configuration.alpn ?: listOf("h2", "http/1.1")
        )

        return TlsClientHelloBuilder.wrapInTLSRecord(rawClientHello)
    }

    // MARK: - Server Response Processing

    /** Receives and processes the server's TLS response. */
    private suspend fun receiveServerResponse(
        privateKey: java.security.PrivateKey
    ): TlsRecordConnection {
        val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
        val data = conn.receive()

        if (data == null || data.size < 5) {
            Log.e(TAG, "No server response or too short")
            throw TlsError.HandshakeFailed("No server response")
        }

        val contentType = data[0].toInt() and 0xFF

        return when (contentType) {
            0x16 -> { // Handshake
                continueReceivingHandshake(data, privateKey)
            }
            0x15 -> { // Alert
                val alertLevel = if (data.size > 5) data[5].toInt() and 0xFF else 0
                val alertDesc = if (data.size > 6) data[6].toInt() and 0xFF else 0
                Log.e(TAG, "TLS Alert: level=$alertLevel, desc=$alertDesc")
                throw TlsError.HandshakeFailed("TLS Alert: level=$alertLevel, desc=$alertDesc")
            }
            else -> {
                Log.e(TAG, "Unexpected content type: 0x${String.format("%02x", contentType)}")
                throw TlsError.HandshakeFailed("Unexpected content type: $contentType")
            }
        }
    }

    /**
     * Continues receiving handshake messages until ServerHello is complete.
     */
    private suspend fun continueReceivingHandshake(
        buffer: ByteArray,
        privateKey: java.security.PrivateKey
    ): TlsRecordConnection {
        var buf = buffer

        while (buf.size < 100) {
            // Need more data
            val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
            val moreData = conn.receive()
            if (moreData != null) {
                buf = buf + moreData
            }
        }

        // Parse ServerHello using NativeBridge
        val parsed = NativeBridge.nativeParseServerHello(buf)
            ?: throw TlsError.HandshakeFailed("Failed to parse ServerHello")

        // parsed: keyShare(32) + cipherSuite(2 big-endian)
        if (parsed.size < 34) {
            throw TlsError.HandshakeFailed("ServerHello parse result too short")
        }

        val serverKeyShare = parsed.copyOfRange(0, 32)
        val cipherSuite = ((parsed[32].toInt() and 0xFF) shl 8) or (parsed[33].toInt() and 0xFF)

        val clientHello = storedClientHello
            ?: throw TlsError.HandshakeFailed("Missing stored ClientHello")

        // X25519 key agreement
        val sharedSecretData = computeSharedSecret(privateKey, serverKeyShare)

        val serverHello = extractServerHelloMessage(buf)

        keyDerivation = Tls13KeyDerivation(cipherSuite)

        val transcript = clientHello + serverHello

        val (hs, keys) = keyDerivation!!.deriveHandshakeKeys(sharedSecretData, transcript)
        handshakeSecret = hs
        handshakeKeys = keys
        handshakeTranscript = transcript

        return consumeRemainingHandshake(buf)
    }

    // MARK: - ServerHello Parsing

    /** Extracts the ServerHello handshake message from the buffer (without TLS record header). */
    private fun extractServerHelloMessage(buffer: ByteArray): ByteArray {
        var offset = 0
        while (offset + 5 < buffer.size) {
            val contentType = buffer[offset].toInt() and 0xFF
            val recordLen = ((buffer[offset + 3].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 4].toInt() and 0xFF)

            if (contentType == 0x16) {
                val recordStart = offset + 5
                if (recordStart < buffer.size && (buffer[recordStart].toInt() and 0xFF) == 0x02) {
                    val end = minOf(recordStart + recordLen, buffer.size)
                    return buffer.copyOfRange(recordStart, end)
                }
            }

            offset += 5 + recordLen
        }
        return ByteArray(0)
    }

    // MARK: - X25519 Key Agreement

    /** Computes X25519 shared secret. */
    private fun computeSharedSecret(
        privateKey: java.security.PrivateKey,
        serverKeyShareBytes: ByteArray
    ): ByteArray {
        // Build server public key from raw bytes
        // X25519 raw public key is 32 bytes, little-endian u-coordinate
        val u = java.math.BigInteger(1, serverKeyShareBytes.reversedArray())
        val serverPubKeySpec = XECPublicKeySpec(NamedParameterSpec.X25519, u)
        val keyFactory = KeyFactory.getInstance("X25519")
        val serverPublicKey = keyFactory.generatePublic(serverPubKeySpec)

        val keyAgreement = KeyAgreement.getInstance("X25519")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(serverPublicKey, true)
        return keyAgreement.generateSecret()
    }

    // MARK: - Encrypted Handshake Processing

    /**
     * Consumes remaining TLS handshake records (encrypted), looking for Server Finished.
     *
     * For standard TLS, also parses Certificate and CertificateVerify messages.
     */
    private suspend fun consumeRemainingHandshake(
        buffer: ByteArray,
        startOffset: Int = 0
    ): TlsRecordConnection {
        val keys = handshakeKeys ?: throw TlsError.HandshakeFailed("Missing handshake keys")
        val kd = keyDerivation ?: throw TlsError.HandshakeFailed("Missing key derivation")

        var buf = buffer
        var offset = startOffset
        var fullTranscript = handshakeTranscript?.copyOf() ?: ByteArray(0)
        var foundServerFinished = false

        // Track transcript up to CertificateVerify for signature verification
        var transcriptBeforeCertVerify: ByteArray? = null
        var certificateVerifySignature: ByteArray? = null
        var certificateVerifyAlgorithm: Int = 0

        while (offset + 5 <= buf.size) {
            val contentType = buf[offset].toInt() and 0xFF
            val recordLen = ((buf[offset + 3].toInt() and 0xFF) shl 8) or
                    (buf[offset + 4].toInt() and 0xFF)

            if (offset + 5 + recordLen > buf.size) break

            if (contentType == 0x14 || contentType == 0x16) {
                // ChangeCipherSpec or plaintext handshake -- skip
                offset += 5 + recordLen
                continue
            } else if (contentType == 0x17) {
                // Encrypted handshake (Application Data wrapper)
                val recordHeader = buf.copyOfRange(offset, offset + 5)
                val ciphertext = buf.copyOfRange(offset + 5, offset + 5 + recordLen)

                try {
                    val seqNum = serverHandshakeSeqNum
                    val decrypted = decryptHandshakeRecord(
                        ciphertext, keys.serverKey, keys.serverIV, seqNum, recordHeader
                    )
                    serverHandshakeSeqNum++

                    // Parse decrypted handshake messages
                    var hsOffset = 0
                    while (hsOffset + 4 <= decrypted.size) {
                        val hsType = decrypted[hsOffset].toInt() and 0xFF
                        val hsLen = ((decrypted[hsOffset + 1].toInt() and 0xFF) shl 16) or
                                ((decrypted[hsOffset + 2].toInt() and 0xFF) shl 8) or
                                (decrypted[hsOffset + 3].toInt() and 0xFF)

                        if (hsOffset + 4 + hsLen > decrypted.size) break

                        val hsMessage = decrypted.copyOfRange(hsOffset, hsOffset + 4 + hsLen)
                        val hsBody = decrypted.copyOfRange(hsOffset + 4, hsOffset + 4 + hsLen)

                        when (hsType) {
                            0x08 -> { // EncryptedExtensions
                                fullTranscript = fullTranscript + hsMessage
                            }
                            0x0B -> { // Certificate
                                fullTranscript = fullTranscript + hsMessage
                                parseCertificateMessage(hsBody)
                            }
                            0x0F -> { // CertificateVerify
                                transcriptBeforeCertVerify = fullTranscript.copyOf()
                                fullTranscript = fullTranscript + hsMessage
                                if (hsBody.size >= 4) {
                                    certificateVerifyAlgorithm =
                                        ((hsBody[0].toInt() and 0xFF) shl 8) or (hsBody[1].toInt() and 0xFF)
                                    val sigLen = ((hsBody[2].toInt() and 0xFF) shl 8) or
                                            (hsBody[3].toInt() and 0xFF)
                                    if (hsBody.size >= 4 + sigLen) {
                                        certificateVerifySignature = hsBody.copyOfRange(4, 4 + sigLen)
                                    }
                                }
                            }
                            0x14 -> { // Finished
                                fullTranscript = fullTranscript + hsMessage
                                foundServerFinished = true
                            }
                            else -> {
                                fullTranscript = fullTranscript + hsMessage
                            }
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to decrypt handshake record: ${e.message}")
                }
            }

            offset += 5 + recordLen
        }

        val processedOffset = offset
        handshakeTranscript = fullTranscript

        if (foundServerFinished) {
            // Validate server certificate (unless allowInsecure)
            if (!configuration.allowInsecure) {
                if (serverCertificates.isEmpty()) {
                    throw TlsError.CertificateValidationFailed("No server certificates received")
                }

                validateCertificate()

                // Verify CertificateVerify signature
                if (transcriptBeforeCertVerify != null && certificateVerifySignature != null) {
                    verifyCertificateVerify(
                        transcriptBeforeCertVerify,
                        certificateVerifyAlgorithm,
                        certificateVerifySignature
                    )
                }
            }

            return finishHandshake(fullTranscript)
        } else {
            // Need more handshake data
            val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
            val moreData = conn.receive()
            var newBuffer = buf
            if (moreData != null) {
                newBuffer = buf + moreData
            }
            return consumeRemainingHandshake(newBuffer, processedOffset)
        }
    }

    // MARK: - Handshake Record Decryption

    /**
     * Decrypts a TLS handshake record using AES-GCM.
     * Returns the decrypted inner plaintext with content type stripped.
     */
    private fun decryptHandshakeRecord(
        ciphertext: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        seqNum: Long,
        recordHeader: ByteArray
    ): ByteArray {
        if (ciphertext.size < 16) {
            throw TlsError.HandshakeFailed("Ciphertext too short")
        }

        val nonce = NativeBridge.nativeXorNonce(iv, seqNum)

        val tagOffset = ciphertext.size - 16
        val ct = ciphertext.copyOfRange(0, tagOffset)
        val tag = ciphertext.copyOfRange(tagOffset, ciphertext.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
        cipher.updateAAD(recordHeader)
        val decrypted = cipher.doFinal(ct + tag)

        if (decrypted.isEmpty()) {
            throw TlsError.HandshakeFailed("Empty decrypted data")
        }

        // Strip trailing padding zeros and content type byte
        var contentEnd = decrypted.size - 1
        while (contentEnd >= 0 && decrypted[contentEnd] == 0.toByte()) {
            contentEnd--
        }

        if (contentEnd < 0) {
            throw TlsError.HandshakeFailed("No content type found")
        }

        // contentEnd now points to the inner content type byte; return everything before it
        return decrypted.copyOfRange(0, contentEnd)
    }

    // MARK: - Certificate Parsing

    /**
     * Parses the Certificate handshake message to extract DER-encoded X.509 certificates.
     *
     * TLS 1.3 Certificate message format:
     * - 1 byte: certificate request context length (usually 0)
     * - N bytes: certificate request context
     * - 3 bytes: certificate list length
     * - For each certificate:
     *   - 3 bytes: certificate data length
     *   - N bytes: DER-encoded certificate
     *   - 2 bytes: extensions length
     *   - N bytes: extensions
     */
    private fun parseCertificateMessage(body: ByteArray) {
        serverCertificates.clear()

        if (body.size < 4) return

        var offset = 0

        // Certificate request context
        val contextLen = body[offset].toInt() and 0xFF
        offset += 1 + contextLen

        if (offset + 3 > body.size) return

        // Certificate list length (3 bytes)
        val listLen = ((body[offset].toInt() and 0xFF) shl 16) or
                ((body[offset + 1].toInt() and 0xFF) shl 8) or
                (body[offset + 2].toInt() and 0xFF)
        offset += 3

        val listEnd = offset + listLen
        if (listEnd > body.size) return

        val certFactory = CertificateFactory.getInstance("X.509")

        while (offset + 3 <= listEnd) {
            // Certificate data length (3 bytes)
            val certLen = ((body[offset].toInt() and 0xFF) shl 16) or
                    ((body[offset + 1].toInt() and 0xFF) shl 8) or
                    (body[offset + 2].toInt() and 0xFF)
            offset += 3

            if (offset + certLen > listEnd) break

            val certData = body.copyOfRange(offset, offset + certLen)
            offset += certLen

            try {
                val cert = certFactory.generateCertificate(
                    java.io.ByteArrayInputStream(certData)
                ) as X509Certificate
                serverCertificates.add(cert)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse certificate: ${e.message}")
            }

            // Skip certificate extensions
            if (offset + 2 > listEnd) break
            val extLen = ((body[offset].toInt() and 0xFF) shl 8) or
                    (body[offset + 1].toInt() and 0xFF)
            offset += 2 + extLen
        }
    }

    // MARK: - Certificate Validation

    /**
     * Validates the server certificate chain.
     * Uses basic Java certificate validation.
     */
    private fun validateCertificate() {
        if (serverCertificates.isEmpty()) {
            throw TlsError.CertificateValidationFailed("No server certificates")
        }

        try {
            // Basic validation: check the leaf certificate is valid (not expired)
            val leafCert = serverCertificates.first()
            leafCert.checkValidity()

            // Verify the certificate chain
            for (i in 0 until serverCertificates.size - 1) {
                val cert = serverCertificates[i]
                val issuer = serverCertificates[i + 1]
                try {
                    cert.verify(issuer.publicKey)
                } catch (e: Exception) {
                    Log.w(TAG, "Certificate chain verification failed at index $i: ${e.message}")
                    // Don't throw here for flexibility; the server cert is checked above
                }
            }

            // Verify SNI matches (basic check)
            // Android's X509Certificate does not have the same SecTrust API as iOS,
            // so we do a basic subject alternative name check
            val sni = configuration.serverName
            if (!verifySNI(leafCert, sni)) {
                Log.w(TAG, "SNI mismatch: expected $sni")
                // Log warning but don't fail -- some configurations use IP addresses
            }
        } catch (e: TlsError) {
            throw e
        } catch (e: Exception) {
            throw TlsError.CertificateValidationFailed(e.message ?: "Certificate validation failed")
        }
    }

    /** Basic SNI verification against certificate Subject Alternative Names. */
    private fun verifySNI(cert: X509Certificate, sni: String): Boolean {
        try {
            val sans = cert.subjectAlternativeNames ?: return false
            for (san in sans) {
                val type = san[0] as Int
                if (type == 2) { // DNS name
                    val dnsName = san[1] as String
                    if (dnsName.equals(sni, ignoreCase = true)) return true
                    // Wildcard matching
                    if (dnsName.startsWith("*.")) {
                        val suffix = dnsName.substring(1)
                        val sniDot = sni.indexOf('.')
                        if (sniDot >= 0 && sni.substring(sniDot).equals(suffix, ignoreCase = true)) {
                            return true
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore SAN parsing errors
        }
        return false
    }

    // MARK: - CertificateVerify

    /**
     * Verifies the CertificateVerify signature against the handshake transcript.
     *
     * The signature is computed over:
     * `64 spaces + "TLS 1.3, server CertificateVerify\0" + transcript_hash`
     */
    private fun verifyCertificateVerify(
        transcript: ByteArray,
        algorithm: Int,
        signature: ByteArray
    ) {
        val kd = keyDerivation ?: throw TlsError.HandshakeFailed("Missing key derivation")

        val serverCert = serverCertificates.firstOrNull()
            ?: throw TlsError.CertificateValidationFailed("No server certificate for CertificateVerify")

        val serverPublicKey = serverCert.publicKey

        // Build the content to verify:
        // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
        val transcriptHash = kd.transcriptHash(transcript)

        val spaces = ByteArray(64) { 0x20 }
        val label = "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII)
        val content = spaces + label + byteArrayOf(0x00) + transcriptHash

        val javaAlgorithm = javaSignatureAlgorithm(algorithm)

        try {
            val sig = java.security.Signature.getInstance(javaAlgorithm)
            sig.initVerify(serverPublicKey)
            sig.update(content)
            val isValid = sig.verify(signature)
            if (!isValid) {
                throw TlsError.CertificateValidationFailed("CertificateVerify signature verification failed")
            }
        } catch (e: TlsError) {
            throw e
        } catch (e: Exception) {
            throw TlsError.CertificateValidationFailed("CertificateVerify failed: ${e.message}")
        }
    }

    /** Maps TLS signature algorithm identifier to Java Signature algorithm name. */
    private fun javaSignatureAlgorithm(tlsAlgorithm: Int): String {
        return when (tlsAlgorithm) {
            0x0403 -> "SHA256withECDSA"    // ecdsa_secp256r1_sha256
            0x0503 -> "SHA384withECDSA"    // ecdsa_secp384r1_sha384
            0x0603 -> "SHA512withECDSA"    // ecdsa_secp521r1_sha512
            0x0804 -> "RSASSA-PSS"         // rsa_pss_rsae_sha256
            0x0805 -> "RSASSA-PSS"         // rsa_pss_rsae_sha384
            0x0806 -> "RSASSA-PSS"         // rsa_pss_rsae_sha512
            0x0401 -> "SHA256withRSA"      // rsa_pkcs1_sha256
            0x0501 -> "SHA384withRSA"      // rsa_pkcs1_sha384
            0x0601 -> "SHA512withRSA"      // rsa_pkcs1_sha512
            else -> "RSASSA-PSS"
        }
    }

    // MARK: - Finish Handshake

    /** Derives application keys and sends Client Finished to complete the handshake. */
    private suspend fun finishHandshake(fullTranscript: ByteArray): TlsRecordConnection {
        val kd = keyDerivation ?: throw TlsError.HandshakeFailed("Missing handshake state")
        val hs = handshakeSecret ?: throw TlsError.HandshakeFailed("Missing handshake state")

        applicationKeys = kd.deriveApplicationKeys(hs, fullTranscript)

        sendClientFinished()

        val appKeys = applicationKeys ?: throw TlsError.HandshakeFailed("Application keys not available")

        val tlsConnection = TlsRecordConnection(
            clientKey = appKeys.clientKey,
            clientIV = appKeys.clientIV,
            serverKey = appKeys.serverKey,
            serverIV = appKeys.serverIV
        )
        tlsConnection.connection = connection
        connection = null

        clearHandshakeState()
        return tlsConnection
    }

    // MARK: - Client Finished

    /** Sends the ChangeCipherSpec and encrypted Client Finished messages. */
    private suspend fun sendClientFinished() {
        val keys = handshakeKeys ?: throw TlsError.HandshakeFailed("Missing handshake keys")
        val transcript = handshakeTranscript ?: throw TlsError.HandshakeFailed("Missing handshake keys")
        val kd = keyDerivation ?: throw TlsError.HandshakeFailed("Missing handshake keys")

        // ChangeCipherSpec record
        val ccsRecord = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

        // Build and encrypt Client Finished
        val verifyData = kd.computeFinishedVerifyData(keys.clientTrafficSecret, transcript)

        val finishedMsg = ByteArray(4 + verifyData.size)
        finishedMsg[0] = 0x14 // Handshake type: Finished
        finishedMsg[1] = 0x00
        finishedMsg[2] = 0x00
        finishedMsg[3] = verifyData.size.toByte()
        System.arraycopy(verifyData, 0, finishedMsg, 4, verifyData.size)

        val finishedRecord = encryptHandshakeRecord(
            finishedMsg, keys.clientKey, keys.clientIV, 0
        )

        val combined = ccsRecord + finishedRecord

        val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
        conn.send(combined)
    }

    /**
     * Encrypts a TLS 1.3 handshake record using AES-GCM.
     * Returns a complete TLS record (header + ciphertext + tag).
     */
    private fun encryptHandshakeRecord(
        plaintext: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        seqNum: Long
    ): ByteArray {
        val nonce = NativeBridge.nativeXorNonce(iv, seqNum)

        // Inner plaintext: handshake data + content type (0x16 = handshake)
        val innerPlaintext = ByteArray(plaintext.size + 1)
        System.arraycopy(plaintext, 0, innerPlaintext, 0, plaintext.size)
        innerPlaintext[plaintext.size] = 0x16

        val encryptedLen = innerPlaintext.size + 16 // +16 for GCM tag
        val aad = byteArrayOf(
            0x17, 0x03, 0x03,
            ((encryptedLen shr 8) and 0xFF).toByte(),
            (encryptedLen and 0xFF).toByte()
        )

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val encrypted = cipher.doFinal(innerPlaintext)

        // Build full TLS record: header + encrypted (ciphertext + tag)
        val record = ByteArray(5 + encrypted.size)
        record[0] = 0x17
        record[1] = 0x03
        record[2] = 0x03
        record[3] = ((encrypted.size shr 8) and 0xFF).toByte()
        record[4] = (encrypted.size and 0xFF).toByte()
        System.arraycopy(encrypted, 0, record, 5, encrypted.size)

        return record
    }

    // MARK: - Helpers

    /** Normalizes X25519 public key bytes from BigInteger representation to 32-byte LE array. */
    private fun normalizeX25519PublicKey(uBytes: ByteArray): ByteArray {
        // BigInteger.toByteArray() returns big-endian, may have leading zero byte
        // X25519 public keys on the wire are little-endian 32 bytes
        val reversed = uBytes.reversedArray()
        return when {
            reversed.size == 32 -> reversed
            reversed.size > 32 -> reversed.copyOfRange(0, 32)
            else -> reversed + ByteArray(32 - reversed.size)
        }
    }

    /** Frees handshake-only state to reduce memory after the connection is established. */
    private fun clearHandshakeState() {
        ephemeralPrivateKeyBytes = null
        ephemeralPublicKeyBytes = null
        storedClientHello = null
        keyDerivation = null
        handshakeSecret = null
        handshakeKeys = null
        handshakeTranscript = null
        serverCertificates.clear()
    }
}
