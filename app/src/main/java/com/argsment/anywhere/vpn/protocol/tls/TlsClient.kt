package com.argsment.anywhere.vpn.protocol.tls

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.util.NioSocket
import java.io.IOException
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val logger = AnywhereLogger("TLS")

// -- TLS Errors --

sealed class TlsError(message: String) : IOException(message) {
    class ConnectionFailed(msg: String) : TlsError("TLS connection failed: $msg")
    class HandshakeFailed(msg: String) : TlsError("TLS handshake failed: $msg")
    class CertificateValidationFailed(msg: String) : TlsError("Certificate validation failed: $msg")
}

/**
 * Client for establishing standard TLS 1.3 connections.
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

    companion object {
        /**
         * Legacy pass-through to [CertificatePolicy.trustedFingerprints]. Kept for
         * source compatibility with earlier code paths that set the list directly.
         */
        var trustedFingerprints: List<String>
            get() = CertificatePolicy.trustedFingerprints
            set(value) = CertificatePolicy.setTrustedFingerprints(value)
    }

    private var connection: Transport? = null

    // Ephemeral X25519 key pair (cleared after handshake)
    private var ephemeralPrivateKeyBytes: ByteArray? = null
    private var ephemeralPublicKeyBytes: ByteArray? = null
    private var storedClientHello: ByteArray? = null
    private var clientRandom: ByteArray? = null

    // TLS 1.3 session state (cleared after handshake)
    private var keyDerivation: Tls13KeyDerivation? = null
    private var handshakeSecret: ByteArray? = null
    private var handshakeKeys: TlsHandshakeKeys? = null
    private var applicationKeys: TlsApplicationKeys? = null
    private var handshakeTranscript: ByteArray? = null
    private var serverHandshakeSeqNum: Long = 0

    // TLS 1.2 session state (cleared after handshake)
    private var serverRandom: ByteArray? = null
    private var tls12CipherSuite: Int = 0
    private var negotiatedVersion: Int = 0x0303
    private var useExtendedMasterSecret: Boolean = false
    private var tls12Transcript: ByteArray? = null

    // Certificate validation state
    private val serverCertificates = mutableListOf<X509Certificate>()

    // -- Public API --

    /**
     * Connects to a server and performs the TLS 1.3 handshake.
     *
     * @param host The server hostname or IP address.
     * @param port The server port number.
     * @return The established [TlsRecordConnection].
     */
    suspend fun connect(host: String, port: Int): TlsRecordConnection {
        // Generate ephemeral X25519 key pair via native bridge (works on all Android versions)
        val keyPair = NativeBridge.nativeX25519GenerateKeyPair()
        ephemeralPrivateKeyBytes = keyPair.copyOfRange(0, 32)
        ephemeralPublicKeyBytes = keyPair.copyOfRange(32, 64)

        // Build the ClientHello up front so it can ride along with the TCP
        // handshake — mirroring iOS, where `NWTransport.connect(initialData:)`
        // queues the ClientHello as the TFO payload. The kernel will flush it
        // the instant the SYN-ACK arrives, saving one scheduling hop compared
        // to a separate `send` after `finishConnect`.
        val clientHello = buildTLSClientHello(
            ephemeralPublicKeyBytes ?: throw TlsError.HandshakeFailed("No ephemeral key")
        )
        storedClientHello = clientHello.copyOfRange(5, clientHello.size)

        val socket = NioSocket()
        connection = socket

        try {
            socket.connect(host, port, initialData = clientHello)
        } catch (e: Exception) {
            logger.error("TCP connection failed: ${e.message}")
            throw TlsError.ConnectionFailed(e.message ?: "Unknown error")
        }

        return receiveServerResponse()
    }

    /**
     * Performs the TLS 1.3 handshake over an existing transport (for proxy chaining).
     * The transport is already connected to the server — no TCP connect needed.
     */
    suspend fun connect(transport: Transport): TlsRecordConnection {
        val keyPair = NativeBridge.nativeX25519GenerateKeyPair()
        ephemeralPrivateKeyBytes = keyPair.copyOfRange(0, 32)
        ephemeralPublicKeyBytes = keyPair.copyOfRange(32, 64)

        connection = transport
        return performTLSHandshake()
    }

    /** Cancels the connection and releases all resources. */
    fun cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = null
    }

    // -- Handshake --

    /**
     * Performs the TLS 1.3 handshake: sends ClientHello, processes ServerHello,
     * derives encryption keys, validates certificates, and sends Client Finished.
     */
    private suspend fun performTLSHandshake(): TlsRecordConnection {
        val pubKeyBytes = ephemeralPublicKeyBytes
            ?: throw TlsError.HandshakeFailed("No ephemeral key")

        val clientHello = buildTLSClientHello(pubKeyBytes)

        // Store for TLS transcript (without 5-byte TLS record header)
        storedClientHello = clientHello.copyOfRange(5, clientHello.size)

        val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
        conn.send(clientHello)

        return receiveServerResponse()
    }

    // -- ClientHello --

    /**
     * Builds a standard TLS 1.3 ClientHello with random SessionId.
     */
    private fun buildTLSClientHello(publicKey: ByteArray): ByteArray {
        val random = ByteArray(32)
        java.security.SecureRandom().nextBytes(random)
        clientRandom = random

        // Standard TLS: random 32-byte session ID (no Reality metadata)
        val sessionId = ByteArray(32)
        java.security.SecureRandom().nextBytes(sessionId)

        val rawClientHello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint = configuration.fingerprint,
            random = random,
            sessionId = sessionId,
            serverName = configuration.serverName,
            publicKey = publicKey,
            alpn = configuration.alpn ?: listOf("h2", "http/1.1"),
            omitPQKeyShares = true  // Omit PQ key shares for standard TLS to reduce ClientHello size (matching iOS)
        )

        return TlsClientHelloBuilder.wrapInTLSRecord(rawClientHello)
    }

    // -- Server Response Processing --

    /**
     * Receives and processes the server's TLS response.
     *
     * Buffers partial reads until at least one complete TLS record header (5 bytes)
     * is available. The server may deliver data in small chunks, especially when
     * the connection is tunneled through a proxy chain (matching iOS).
     */
    private suspend fun receiveServerResponse(
        existingBuffer: ByteArray = ByteArray(0)
    ): TlsRecordConnection {
        // Already have enough data to inspect the record header
        if (existingBuffer.size >= 5) {
            val contentType = existingBuffer[0].toInt() and 0xFF
            return when (contentType) {
                0x16 -> continueReceivingHandshake(existingBuffer)
                0x15 -> {
                    val alertLevel = if (existingBuffer.size > 5) existingBuffer[5].toInt() and 0xFF else 0
                    val alertDesc = if (existingBuffer.size > 6) existingBuffer[6].toInt() and 0xFF else 0
                    logger.error("TLS Alert: level=$alertLevel, desc=$alertDesc")
                    throw TlsError.HandshakeFailed("TLS Alert: level=$alertLevel, desc=$alertDesc")
                }
                else -> {
                    logger.error("Unexpected content type: 0x${String.format("%02x", contentType)}")
                    throw TlsError.HandshakeFailed("Unexpected content type: $contentType")
                }
            }
        }

        val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
        val data = conn.receive()

        if (data == null || data.isEmpty()) {
            logger.error("No server response (connection closed)")
            throw TlsError.HandshakeFailed("No server response")
        }

        // Buffer partial data and recurse until we have at least 5 bytes
        return receiveServerResponse(existingBuffer + data)
    }

    /**
     * Continues receiving handshake messages until ServerHello is complete.
     */
    private suspend fun continueReceivingHandshake(
        buffer: ByteArray
    ): TlsRecordConnection {
        var buf = buffer

        // Keep reading until we have a complete TLS record containing ServerHello
        while (!bufferContainsCompleteServerHello(buf)) {
            val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
            val moreData = conn.receive()
                ?: throw TlsError.HandshakeFailed("Connection closed during handshake")
            buf = buf + moreData
        }

        // Try TLS 1.3 parsing first (looks for key_share extension)
        val parsed = com.argsment.anywhere.vpn.util.PacketUtil.parseServerHello(buf)

        if (parsed != null && parsed.size >= 34) {
            // TLS 1.3 path
            negotiatedVersion = 0x0304
            enforceVersionConstraints()

            val serverKeyShare = parsed.copyOfRange(0, 32)
            val cipherSuite = ((parsed[32].toInt() and 0xFF) shl 8) or (parsed[33].toInt() and 0xFF)

            val clientHello = storedClientHello
                ?: throw TlsError.HandshakeFailed("Missing stored ClientHello")

            val privateKey = ephemeralPrivateKeyBytes
                ?: throw TlsError.HandshakeFailed("No ephemeral key")
            val sharedSecretData = NativeBridge.nativeX25519KeyAgreement(privateKey, serverKeyShare)

            val serverHello = extractServerHelloMessage(buf)
            checkHelloRetryRequest(serverHello)

            keyDerivation = Tls13KeyDerivation(cipherSuite)

            val transcript = clientHello + serverHello

            val (hs, keys) = keyDerivation!!.deriveHandshakeKeys(sharedSecretData, transcript)
            handshakeSecret = hs
            handshakeKeys = keys
            handshakeTranscript = transcript

            return consumeRemainingHandshake(buf)
        }

        // TLS 1.2 fallback: no key_share means server chose TLS 1.2
        return handleTls12Handshake(buf)
    }

    // -- ServerHello Parsing --

    /** HelloRetryRequest special random value (RFC 8446 §4.1.3). */
    private val HELLO_RETRY_REQUEST_RANDOM = byteArrayOf(
        0xCF.toByte(), 0x21.toByte(), 0xAD.toByte(), 0x74.toByte(),
        0xE5.toByte(), 0x9A.toByte(), 0x61.toByte(), 0x11.toByte(),
        0xBE.toByte(), 0x1D.toByte(), 0x8C.toByte(), 0x02.toByte(),
        0x1E.toByte(), 0x65.toByte(), 0xB8.toByte(), 0x91.toByte(),
        0xC2.toByte(), 0xA2.toByte(), 0x11.toByte(), 0x16.toByte(),
        0x7A.toByte(), 0xBB.toByte(), 0x8C.toByte(), 0x5E.toByte(),
        0x07.toByte(), 0x9E.toByte(), 0x09.toByte(), 0xE2.toByte(),
        0xC8.toByte(), 0xA8.toByte(), 0x33.toByte(), 0x9C.toByte()
    )

    /** Checks whether the buffer contains at least one complete TLS record with a ServerHello. */
    private fun bufferContainsCompleteServerHello(buffer: ByteArray): Boolean {
        var offset = 0
        while (offset + 5 <= buffer.size) {
            val contentType = buffer[offset].toInt() and 0xFF
            val recordLen = ((buffer[offset + 3].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 4].toInt() and 0xFF)
            if (offset + 5 + recordLen > buffer.size) return false
            if (contentType == 0x16) {
                // Check if this record contains a ServerHello
                val hsStart = offset + 5
                if (hsStart < buffer.size && (buffer[hsStart].toInt() and 0xFF) == 0x02) {
                    return true
                }
            }
            offset += 5 + recordLen
        }
        return false
    }

    /** Detects HelloRetryRequest by checking the server random. */
    private fun checkHelloRetryRequest(serverHello: ByteArray) {
        // ServerHello: type(1) + length(3) + version(2) + random(32)
        if (serverHello.size >= 38) {
            val serverRandom = serverHello.copyOfRange(6, 38)
            if (serverRandom.contentEquals(HELLO_RETRY_REQUEST_RANDOM)) {
                throw TlsError.HandshakeFailed("HelloRetryRequest not supported")
            }
        }
    }

    /** Extracts the ServerHello handshake message from the buffer (without TLS record header). */
    private fun extractServerHelloMessage(buffer: ByteArray): ByteArray {
        var offset = 0
        while (offset + 5 <= buffer.size) {
            val contentType = buffer[offset].toInt() and 0xFF
            val recordLen = ((buffer[offset + 3].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 4].toInt() and 0xFF)

            if (offset + 5 + recordLen > buffer.size) break

            if (contentType == 0x16) {
                // Parse individual handshake messages within this record
                val recordStart = offset + 5
                val recordEnd = recordStart + recordLen
                var hsOffset = recordStart
                while (hsOffset + 4 <= recordEnd) {
                    val hsType = buffer[hsOffset].toInt() and 0xFF
                    val hsLen = ((buffer[hsOffset + 1].toInt() and 0xFF) shl 16) or
                            ((buffer[hsOffset + 2].toInt() and 0xFF) shl 8) or
                            (buffer[hsOffset + 3].toInt() and 0xFF)
                    if (hsOffset + 4 + hsLen > recordEnd) break
                    if (hsType == 0x02) { // ServerHello
                        return buffer.copyOfRange(hsOffset, hsOffset + 4 + hsLen)
                    }
                    hsOffset += 4 + hsLen
                }
            }

            offset += 5 + recordLen
        }
        return ByteArray(0)
    }

    // -- Encrypted Handshake Processing --

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
                            0x19 -> { // CompressedCertificate (RFC 8879)
                                fullTranscript = fullTranscript + hsMessage
                                val decompressed = decompressCertificate(hsBody)
                                if (decompressed != null) {
                                    parseCertificateMessage(decompressed)
                                } else {
                                    logger.warning("Failed to decompress CompressedCertificate")
                                }
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
                                // Verify Server Finished verify data (matching iOS)
                                val transcriptBeforeFinished = fullTranscript
                                fullTranscript = fullTranscript + hsMessage
                                val expectedVerifyData = kd.computeFinishedVerifyData(
                                    keys.serverTrafficSecret, transcriptBeforeFinished
                                )
                                // Constant-time comparison to prevent timing side-channel
                                // attacks on the server Finished verify_data (matches iOS).
                                if (!constantTimeEqual(hsBody, expectedVerifyData)) {
                                    throw TlsError.HandshakeFailed("Server Finished verify data mismatch")
                                }
                                foundServerFinished = true
                            }
                            else -> {
                                fullTranscript = fullTranscript + hsMessage
                            }
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch (e: Exception) {
                    logger.error("Failed to decrypt handshake record: ${e.message}")
                }
            }

            offset += 5 + recordLen

            // Stop processing once Server Finished is found — any subsequent
            // records (e.g. NewSessionTicket) are encrypted with application keys
            // and must be handled by TlsRecordConnection, not the handshake loop.
            if (foundServerFinished) break
        }

        val processedOffset = offset
        handshakeTranscript = fullTranscript

        if (foundServerFinished) {
            // Validate server certificate (unless allowInsecure)
            if (!configuration.allowInsecure && !CertificatePolicy.allowInsecure) {
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

            val tlsConn = finishHandshake(fullTranscript)
            // Pass any remaining buffer data (e.g., NewSessionTicket) to the
            // TlsRecordConnection so it isn't lost (matching iOS prependToReceiveBuffer)
            if (processedOffset < buf.size) {
                val remaining = buf.copyOfRange(processedOffset, buf.size)
                tlsConn.prependToReceiveBuffer(remaining)
            }
            return tlsConn
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

    // -- Handshake Record Decryption --

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

        val nonce = com.argsment.anywhere.vpn.util.PacketUtil.xorNonce(iv, seqNum)

        val isChaCha = keyDerivation?.cipherSuite == TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
        val cipherTransform = if (isChaCha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
        val cipherAlgo = if (isChaCha) "ChaCha20" else "AES"
        val cipher = Cipher.getInstance(cipherTransform)
        val keySpec = SecretKeySpec(key, cipherAlgo)
        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec)
        cipher.updateAAD(recordHeader)
        val decrypted = cipher.doFinal(ciphertext)

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

    // -- Certificate Parsing --

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
                logger.warning("Failed to parse certificate: ${e.message}")
            }

            // Skip certificate extensions
            if (offset + 2 > listEnd) break
            val extLen = ((body[offset].toInt() and 0xFF) shl 8) or
                    (body[offset + 1].toInt() and 0xFF)
            offset += 2 + extLen
        }
    }

    // -- CompressedCertificate (RFC 8879) --

    /**
     * Decompresses a CompressedCertificate message body.
     *
     * RFC 8879 layout: algorithm (2) + uncompressed_length (3) + compressed_length (3) + data
     * Supports zlib (0x0001) and brotli (0x0002, if available).
     */
    private fun decompressCertificate(body: ByteArray): ByteArray? {
        if (body.size < 8) return null

        val algorithm = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        val uncompressedLength = ((body[2].toInt() and 0xFF) shl 16) or
                ((body[3].toInt() and 0xFF) shl 8) or (body[4].toInt() and 0xFF)
        val compressedLength = ((body[5].toInt() and 0xFF) shl 16) or
                ((body[6].toInt() and 0xFF) shl 8) or (body[7].toInt() and 0xFF)

        if (8 + compressedLength > body.size) return null
        if (uncompressedLength <= 0 || uncompressedLength > (1 shl 24)) return null

        val compressed = body.copyOfRange(8, 8 + compressedLength)

        return when (algorithm) {
            0x0001 -> { // zlib
                try {
                    val inflater = java.util.zip.Inflater()
                    inflater.setInput(compressed)
                    val output = ByteArray(uncompressedLength)
                    val decodedSize = inflater.inflate(output)
                    inflater.end()
                    if (decodedSize > 0) output.copyOfRange(0, decodedSize) else null
                } catch (e: Exception) {
                    logger.warning("zlib decompression failed: ${e.message}")
                    null
                }
            }
            0x0002 -> { // brotli (RFC 8879)
                try {
                    val brotliInput = org.brotli.dec.BrotliInputStream(compressed.inputStream())
                    val output = ByteArray(uncompressedLength)
                    var totalRead = 0
                    while (totalRead < uncompressedLength) {
                        val n = brotliInput.read(output, totalRead, uncompressedLength - totalRead)
                        if (n <= 0) break
                        totalRead += n
                    }
                    brotliInput.close()
                    if (totalRead > 0) output.copyOfRange(0, totalRead) else null
                } catch (e: Exception) {
                    logger.warning("Brotli decompression failed: ${e.message}")
                    null
                }
            }
            else -> {
                logger.warning("Unknown certificate compression algorithm: 0x${String.format("%04x", algorithm)}")
                null
            }
        }
    }

    // -- Certificate Validation --

    /**
     * Validates the server certificate.
     *
     * First tries standard system trust evaluation. If that fails, checks
     * whether the leaf certificate's SHA-256 fingerprint is in the user's
     * trusted certificate list. Chain trust validation is best-effort
     * (logged, not fatal) because the CertificateVerify signature already
     * proves the server holds the private key for the leaf certificate.
     */
    private fun validateCertificate() {
        if (serverCertificates.isEmpty()) {
            throw TlsError.CertificateValidationFailed("No server certificates")
        }

        // Check leaf certificate validity (not expired)
        val leafCert = serverCertificates.first()
        leafCert.checkValidity()

        // Best-effort chain trust validation via Android TrustManagerFactory.
        // Non-fatal: CertificateVerify provides the key-ownership proof.
        try {
            val tmf = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
            )
            tmf.init(null as java.security.KeyStore?)

            val x509tm = tmf.trustManagers
                .filterIsInstance<javax.net.ssl.X509TrustManager>()
                .firstOrNull()

            if (x509tm != null) {
                val authType = when (leafCert.publicKey.algorithm) {
                    "EC" -> "ECDHE_ECDSA"
                    else -> "ECDHE_RSA"
                }
                x509tm.checkServerTrusted(serverCertificates.toTypedArray(), authType)
            }
        } catch (e: Exception) {
            logger.warning("Chain trust validation failed: ${e.message}")
            // System trust failed — check user-trusted certificate fingerprints (matching iOS)
            if (!isUserTrusted(leafCert)) {
                throw TlsError.CertificateValidationFailed(
                    "Certificate not trusted by system or user: ${e.message}"
                )
            }
        }
    }

    /**
     * Checks whether the certificate's SHA-256 fingerprint is in the user's trusted list.
     *
     * Uses [constantTimeEqual] for the per-entry comparison to avoid leaking information
     * about how many leading bytes of a candidate fingerprint match. This matches iOS's
     * `constantTimeEqual()` helper in `TLSClient.swift`.
     */
    private fun isUserTrusted(certificate: X509Certificate): Boolean {
        val trusted = trustedFingerprints
        if (trusted.isEmpty()) return false
        val candidate = MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
            .toByteArray(Charsets.US_ASCII)

        // Walk every entry — do NOT short-circuit on first match.
        var matched = false
        for (entry in trusted) {
            val entryBytes = entry.toByteArray(Charsets.US_ASCII)
            if (constantTimeEqual(candidate, entryBytes)) {
                matched = true
            }
        }
        return matched
    }

    /**
     * Constant-time byte-array comparison. Returns true iff [a] and [b] have the same
     * length and identical contents. The comparison time depends only on the length of
     * the longer input, not on where (or whether) the inputs first differ.
     *
     * Mirrors iOS `constantTimeEqual` in `TLSClient.swift`.
     */
    private fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or ((a[i].toInt() xor b[i].toInt()) and 0xFF)
        }
        return diff == 0
    }

    /**
     * Validates the negotiated TLS version against the [TlsConfiguration.minVersion] and
     * [TlsConfiguration.maxVersion] constraints. A null bound means "no constraint".
     *
     * Throws [TlsError.HandshakeFailed] if the negotiated version is outside the allowed
     * range. Mirrors iOS version-pinning behavior.
     */
    private fun enforceVersionConstraints() {
        val negotiated = when (negotiatedVersion) {
            0x0303 -> com.argsment.anywhere.data.model.TlsVersion.TLS12
            0x0304 -> com.argsment.anywhere.data.model.TlsVersion.TLS13
            else -> null
        }
        if (negotiated == null) {
            // Unknown version: only fail if either constraint is set.
            if (configuration.minVersion != null || configuration.maxVersion != null) {
                throw TlsError.HandshakeFailed(
                    "Negotiated TLS version 0x${"%04x".format(negotiatedVersion)} is not allowed"
                )
            }
            return
        }
        configuration.minVersion?.let { min ->
            if (negotiated.value < min.value) {
                throw TlsError.HandshakeFailed(
                    "Negotiated TLS version ${negotiated.displayName} is below minimum ${min.displayName}"
                )
            }
        }
        configuration.maxVersion?.let { max ->
            if (negotiated.value > max.value) {
                throw TlsError.HandshakeFailed(
                    "Negotiated TLS version ${negotiated.displayName} exceeds maximum ${max.displayName}"
                )
            }
        }
    }

    // -- CertificateVerify --

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

        try {
            // Android's Conscrypt uses "SHA256withRSA/PSS" naming convention
            // (not the generic "RSASSA-PSS" which requires explicit PSSParameterSpec)
            val sig = java.security.Signature.getInstance(javaSignatureAlgorithm(algorithm))
            sig.initVerify(serverPublicKey)
            sig.update(content)
            val isValid = sig.verify(signature)
            if (!isValid) {
                if (configuration.allowInsecure || CertificatePolicy.allowInsecure) return
                throw TlsError.CertificateValidationFailed("CertificateVerify signature verification failed")
            }
        } catch (e: TlsError) {
            throw e
        } catch (e: Exception) {
            if (configuration.allowInsecure || CertificatePolicy.allowInsecure) return
            throw TlsError.CertificateValidationFailed("CertificateVerify failed: ${e.message}")
        }
    }

    /** Maps TLS signature algorithm identifier to Java Signature algorithm name.
     *  Uses Android Conscrypt naming: "SHA256withRSA/PSS" (not generic "RSASSA-PSS").
     *  Mirrors iOS `secKeyAlgorithm()`. */
    private fun javaSignatureAlgorithm(tlsAlgorithm: Int): String {
        return when (tlsAlgorithm) {
            // ECDSA
            0x0403 -> "SHA256withECDSA"    // ecdsa_secp256r1_sha256
            0x0503 -> "SHA384withECDSA"    // ecdsa_secp384r1_sha384
            0x0603 -> "SHA512withECDSA"    // ecdsa_secp521r1_sha512
            // RSA-PSS
            0x0804 -> "SHA256withRSA/PSS"  // rsa_pss_rsae_sha256
            0x0805 -> "SHA384withRSA/PSS"  // rsa_pss_rsae_sha384
            0x0806 -> "SHA512withRSA/PSS"  // rsa_pss_rsae_sha512
            // RSA-PKCS1
            0x0401 -> "SHA256withRSA"      // rsa_pkcs1_sha256
            0x0501 -> "SHA384withRSA"      // rsa_pkcs1_sha384
            0x0601 -> "SHA512withRSA"      // rsa_pkcs1_sha512
            0x0201 -> "SHA1withRSA"        // rsa_pkcs1_sha1 (legacy, RFC 8446 §B.3.1.3)
            // EdDSA
            0x0807 -> "Ed25519"            // ed25519 (Android API 33+)
            else -> "SHA256withRSA"
        }
    }

    // -- Finish Handshake --

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
            serverIV = appKeys.serverIV,
            cipherSuite = keyDerivation?.cipherSuite ?: TlsCipherSuite.TLS_AES_128_GCM_SHA256
        )
        tlsConnection.connection = connection
        connection = null

        clearHandshakeState()
        return tlsConnection
    }

    // -- Client Finished --

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
        val nonce = com.argsment.anywhere.vpn.util.PacketUtil.xorNonce(iv, seqNum)

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

        val isChaCha = keyDerivation?.cipherSuite == TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
        val cipherTransform = if (isChaCha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
        val cipherAlgo = if (isChaCha) "ChaCha20" else "AES"
        val cipher = Cipher.getInstance(cipherTransform)
        val keySpec = SecretKeySpec(key, cipherAlgo)
        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec)
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

    // ========= TLS 1.2 Handshake =========

    /**
     * Handles the TLS 1.2 handshake. Server has responded with TLS 1.2 ServerHello.
     * Collects plaintext Certificate, ServerKeyExchange, ServerHelloDone, then
     * sends ClientKeyExchange + ChangeCipherSpec + Finished.
     */
    private suspend fun handleTls12Handshake(buffer: ByteArray): TlsRecordConnection {
        val clientHello = storedClientHello
            ?: throw TlsError.HandshakeFailed("Missing stored ClientHello")

        // Parse ServerHello to extract cipher suite, server random, EMS
        val serverHello = extractServerHelloMessage(buffer)
        if (serverHello.isEmpty()) {
            throw TlsError.HandshakeFailed("Failed to extract TLS 1.2 ServerHello")
        }
        parseTls12ServerHello(serverHello)

        // Enforce version constraints now that the negotiated version is known
        // (parseTls12ServerHello may upgrade to 0x0304 via the supported_versions extension).
        enforceVersionConstraints()

        // Start transcript
        tls12Transcript = clientHello + serverHello

        // Collect remaining plaintext handshake messages
        var buf = buffer
        var offset = 0
        var serverKeyExchangeBody: ByteArray? = null
        var foundServerHelloDone = false

        while (!foundServerHelloDone) {
            while (offset + 5 <= buf.size) {
                val contentType = buf[offset].toInt() and 0xFF
                val recordLen = ((buf[offset + 3].toInt() and 0xFF) shl 8) or
                        (buf[offset + 4].toInt() and 0xFF)
                if (offset + 5 + recordLen > buf.size) break

                if (contentType == 0x16) {
                    // Plaintext handshake record — may contain multiple messages
                    val recordData = buf.copyOfRange(offset + 5, offset + 5 + recordLen)
                    var hsOffset = 0
                    while (hsOffset + 4 <= recordData.size) {
                        val hsType = recordData[hsOffset].toInt() and 0xFF
                        val hsLen = ((recordData[hsOffset + 1].toInt() and 0xFF) shl 16) or
                                ((recordData[hsOffset + 2].toInt() and 0xFF) shl 8) or
                                (recordData[hsOffset + 3].toInt() and 0xFF)
                        if (hsOffset + 4 + hsLen > recordData.size) break

                        val hsMessage = recordData.copyOfRange(hsOffset, hsOffset + 4 + hsLen)
                        val hsBody = recordData.copyOfRange(hsOffset + 4, hsOffset + 4 + hsLen)

                        when (hsType) {
                            0x02 -> {} // ServerHello (already parsed above)
                            0x0B -> { // Certificate
                                tls12Transcript = tls12Transcript!! + hsMessage
                                parseTls12CertificateMessage(hsBody)
                            }
                            0x0C -> { // ServerKeyExchange
                                tls12Transcript = tls12Transcript!! + hsMessage
                                serverKeyExchangeBody = hsBody
                            }
                            0x0E -> { // ServerHelloDone
                                tls12Transcript = tls12Transcript!! + hsMessage
                                foundServerHelloDone = true
                            }
                            else -> {
                                tls12Transcript = tls12Transcript!! + hsMessage
                            }
                        }
                        hsOffset += 4 + hsLen
                    }
                }
                offset += 5 + recordLen
            }

            if (!foundServerHelloDone) {
                val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
                val moreData = conn.receive() ?: throw TlsError.HandshakeFailed("Connection closed during handshake")
                buf = buf + moreData
            }
        }

        val skipValidation = configuration.allowInsecure || CertificatePolicy.allowInsecure

        // Validate certificate
        if (!skipValidation && serverCertificates.isNotEmpty()) {
            validateCertificate()
        }

        // Verify ServerKeyExchange signature
        if (!skipValidation && serverKeyExchangeBody != null) {
            verifyTls12ServerKeyExchange(serverKeyExchangeBody)
        }

        // Perform key exchange: ECDHE if ServerKeyExchange present, RSA otherwise
        val (preMasterSecret, ckeBody) = if (serverKeyExchangeBody != null) {
            processECDHEServerKeyExchange(serverKeyExchangeBody)
        } else if (!TlsCipherSuite.isECDHE(tls12CipherSuite)) {
            processRSAKeyExchange()
        } else {
            throw TlsError.HandshakeFailed("Missing ServerKeyExchange for ECDHE cipher suite")
        }

        // Build ClientKeyExchange handshake message
        val ckeMessage = ByteArray(4 + ckeBody.size)
        ckeMessage[0] = 0x10 // ClientKeyExchange
        ckeMessage[1] = ((ckeBody.size shr 16) and 0xFF).toByte()
        ckeMessage[2] = ((ckeBody.size shr 8) and 0xFF).toByte()
        ckeMessage[3] = (ckeBody.size and 0xFF).toByte()
        System.arraycopy(ckeBody, 0, ckeMessage, 4, ckeBody.size)
        tls12Transcript = tls12Transcript!! + ckeMessage

        // Derive master secret
        val cRandom = clientRandom ?: throw TlsError.HandshakeFailed("Missing client random")
        val sRandom = serverRandom ?: throw TlsError.HandshakeFailed("Missing server random")
        val useSHA384 = TlsCipherSuite.usesSHA384(tls12CipherSuite)

        val masterSecret = if (useExtendedMasterSecret) {
            val sessionHash = Tls12KeyDerivation.transcriptHash(tls12Transcript!!, useSHA384)
            Tls12KeyDerivation.extendedMasterSecret(preMasterSecret, sessionHash, useSHA384)
        } else {
            Tls12KeyDerivation.masterSecret(preMasterSecret, cRandom, sRandom, useSHA384)
        }

        // Expand keys
        val keys = Tls12KeyDerivation.keysFromMasterSecret(masterSecret, cRandom, sRandom, tls12CipherSuite)

        // Send ClientKeyExchange + ChangeCipherSpec + Finished
        return sendTls12ClientKeyExchangeAndFinished(buf, offset, ckeMessage, keys, masterSecret)
    }

    /** Parses TLS 1.2 ServerHello to extract cipher suite, random, and EMS. */
    private fun parseTls12ServerHello(serverHelloMsg: ByteArray) {
        // ServerHello message: type(1) + length(3) + version(2) + random(32) + ...
        if (serverHelloMsg.size < 39) {
            throw TlsError.HandshakeFailed("ServerHello too short")
        }
        var offset = 4 // Skip type(1) + length(3)

        // Version
        negotiatedVersion = ((serverHelloMsg[offset].toInt() and 0xFF) shl 8) or
                (serverHelloMsg[offset + 1].toInt() and 0xFF)
        offset += 2

        // Server random
        serverRandom = serverHelloMsg.copyOfRange(offset, offset + 32)
        offset += 32

        // Session ID
        val sessionIdLen = serverHelloMsg[offset].toInt() and 0xFF
        offset += 1 + sessionIdLen

        if (offset + 3 > serverHelloMsg.size) return

        // Cipher suite
        tls12CipherSuite = ((serverHelloMsg[offset].toInt() and 0xFF) shl 8) or
                (serverHelloMsg[offset + 1].toInt() and 0xFF)
        offset += 2

        // Compression method
        offset += 1

        // Extensions
        if (offset + 2 <= serverHelloMsg.size) {
            val extLen = ((serverHelloMsg[offset].toInt() and 0xFF) shl 8) or
                    (serverHelloMsg[offset + 1].toInt() and 0xFF)
            offset += 2
            val extEnd = minOf(offset + extLen, serverHelloMsg.size)

            while (offset + 4 <= extEnd) {
                val extType = ((serverHelloMsg[offset].toInt() and 0xFF) shl 8) or
                        (serverHelloMsg[offset + 1].toInt() and 0xFF)
                val extDataLen = ((serverHelloMsg[offset + 2].toInt() and 0xFF) shl 8) or
                        (serverHelloMsg[offset + 3].toInt() and 0xFF)
                offset += 4

                when (extType) {
                    0x0017 -> useExtendedMasterSecret = true  // Extended Master Secret
                    0x002B -> { // supported_versions: if server responds 0x0304, it's TLS 1.3
                        if (extDataLen >= 2) {
                            val ver = ((serverHelloMsg[offset].toInt() and 0xFF) shl 8) or
                                    (serverHelloMsg[offset + 1].toInt() and 0xFF)
                            negotiatedVersion = ver
                        }
                    }
                }
                offset += extDataLen
            }
        }

    }

    /** Parses TLS 1.2 Certificate message (plaintext, without context length). */
    private fun parseTls12CertificateMessage(body: ByteArray) {
        serverCertificates.clear()
        if (body.size < 3) return

        val listLen = ((body[0].toInt() and 0xFF) shl 16) or
                ((body[1].toInt() and 0xFF) shl 8) or
                (body[2].toInt() and 0xFF)
        var offset = 3
        val listEnd = minOf(offset + listLen, body.size)
        val certFactory = CertificateFactory.getInstance("X.509")

        while (offset + 3 <= listEnd) {
            val certLen = ((body[offset].toInt() and 0xFF) shl 16) or
                    ((body[offset + 1].toInt() and 0xFF) shl 8) or
                    (body[offset + 2].toInt() and 0xFF)
            offset += 3
            if (offset + certLen > listEnd) break

            try {
                val cert = certFactory.generateCertificate(
                    java.io.ByteArrayInputStream(body.copyOfRange(offset, offset + certLen))
                ) as X509Certificate
                serverCertificates.add(cert)
            } catch (e: Exception) {
                logger.warning("Failed to parse TLS 1.2 certificate: ${e.message}")
            }
            offset += certLen
        }
    }

    /** Processes ServerKeyExchange for ECDHE: extracts curve, public key, computes shared secret. */
    private fun processECDHEServerKeyExchange(body: ByteArray): Pair<ByteArray, ByteArray> {
        if (body.size < 4) throw TlsError.HandshakeFailed("ServerKeyExchange too short")

        val curveType = body[0].toInt() and 0xFF
        if (curveType != 0x03) throw TlsError.HandshakeFailed("Unsupported curve type: $curveType")

        val namedCurve = ((body[1].toInt() and 0xFF) shl 8) or (body[2].toInt() and 0xFF)
        val pubKeyLen = body[3].toInt() and 0xFF
        if (body.size < 4 + pubKeyLen) throw TlsError.HandshakeFailed("ServerKeyExchange truncated")

        val serverPubKey = body.copyOfRange(4, 4 + pubKeyLen)

        return when (namedCurve) {
            0x001D -> { // X25519
                val privateKey = ephemeralPrivateKeyBytes
                    ?: throw TlsError.HandshakeFailed("No ephemeral key")
                val sharedSecret = NativeBridge.nativeX25519KeyAgreement(privateKey, serverPubKey)
                val cke = ByteArray(1 + 32)
                cke[0] = 32
                System.arraycopy(ephemeralPublicKeyBytes!!, 0, cke, 1, 32)
                Pair(sharedSecret, cke)
            }
            0x0017 -> { // P-256
                val kpg = java.security.KeyPairGenerator.getInstance("EC")
                kpg.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
                val kp = kpg.generateKeyPair()
                val ecPub = kp.public as java.security.interfaces.ECPublicKey
                val ecPriv = kp.private

                // Derive shared secret via ECDH
                val ka = javax.crypto.KeyAgreement.getInstance("ECDH")
                ka.init(ecPriv)
                val serverKeyFactory = java.security.KeyFactory.getInstance("EC")
                val pubKeyPoint = java.security.spec.ECPoint(
                    java.math.BigInteger(1, serverPubKey.copyOfRange(1, 33)),
                    java.math.BigInteger(1, serverPubKey.copyOfRange(33, 65))
                )
                val pubKeySpec = java.security.spec.ECPublicKeySpec(pubKeyPoint, ecPub.params)
                ka.doPhase(serverKeyFactory.generatePublic(pubKeySpec), true)
                val sharedSecret = ka.generateSecret()

                // Build ClientKeyExchange: length(1) + uncompressed point (65 bytes)
                val w = ecPub.w
                val x = w.affineX.toByteArray().let { b ->
                    when { b.size == 32 -> b; b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
                        else -> ByteArray(32 - b.size) + b }
                }
                val y = w.affineY.toByteArray().let { b ->
                    when { b.size == 32 -> b; b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
                        else -> ByteArray(32 - b.size) + b }
                }
                val clientPubKey = byteArrayOf(0x04) + x + y
                val cke = ByteArray(1 + clientPubKey.size)
                cke[0] = clientPubKey.size.toByte()
                System.arraycopy(clientPubKey, 0, cke, 1, clientPubKey.size)
                Pair(sharedSecret, cke)
            }
            0x0018 -> { // P-384 (secp384r1) — matching iOS
                val kpg = java.security.KeyPairGenerator.getInstance("EC")
                kpg.initialize(java.security.spec.ECGenParameterSpec("secp384r1"))
                val kp = kpg.generateKeyPair()
                val ecPub = kp.public as java.security.interfaces.ECPublicKey
                val ecPriv = kp.private

                val ka = javax.crypto.KeyAgreement.getInstance("ECDH")
                ka.init(ecPriv)
                val serverKeyFactory = java.security.KeyFactory.getInstance("EC")
                val pubKeyPoint = java.security.spec.ECPoint(
                    java.math.BigInteger(1, serverPubKey.copyOfRange(1, 49)),
                    java.math.BigInteger(1, serverPubKey.copyOfRange(49, 97))
                )
                val pubKeySpec = java.security.spec.ECPublicKeySpec(pubKeyPoint, ecPub.params)
                ka.doPhase(serverKeyFactory.generatePublic(pubKeySpec), true)
                val sharedSecret = ka.generateSecret()

                // Build ClientKeyExchange: length(1) + uncompressed point (97 bytes for P-384)
                val w = ecPub.w
                val x = w.affineX.toByteArray().let { b ->
                    when { b.size == 48 -> b; b.size > 48 -> b.copyOfRange(b.size - 48, b.size)
                        else -> ByteArray(48 - b.size) + b }
                }
                val y = w.affineY.toByteArray().let { b ->
                    when { b.size == 48 -> b; b.size > 48 -> b.copyOfRange(b.size - 48, b.size)
                        else -> ByteArray(48 - b.size) + b }
                }
                val clientPubKey = byteArrayOf(0x04) + x + y
                val cke = ByteArray(1 + clientPubKey.size)
                cke[0] = clientPubKey.size.toByte()
                System.arraycopy(clientPubKey, 0, cke, 1, clientPubKey.size)
                Pair(sharedSecret, cke)
            }
            else -> throw TlsError.HandshakeFailed("Unsupported ECDHE curve: 0x${"%04x".format(namedCurve)}")
        }
    }

    /** Processes RSA ServerKeyExchange (static RSA key exchange, no ServerKeyExchange). */
    private fun processRSAKeyExchange(): Pair<ByteArray, ByteArray> {
        val serverCert = serverCertificates.firstOrNull()
            ?: throw TlsError.HandshakeFailed("No server certificate for RSA key exchange")

        // Generate 48-byte pre-master secret: version(2) + random(46)
        val preMasterSecret = ByteArray(48)
        java.security.SecureRandom().nextBytes(preMasterSecret)
        preMasterSecret[0] = 0x03
        preMasterSecret[1] = 0x03

        // Encrypt with server's RSA public key (PKCS#1 v1.5)
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, serverCert.publicKey)
        val encrypted = cipher.doFinal(preMasterSecret)

        // ClientKeyExchange: length(2) + encrypted pre-master secret
        val cke = ByteArray(2 + encrypted.size)
        cke[0] = ((encrypted.size shr 8) and 0xFF).toByte()
        cke[1] = (encrypted.size and 0xFF).toByte()
        System.arraycopy(encrypted, 0, cke, 2, encrypted.size)

        return Pair(preMasterSecret, cke)
    }

    /** Verifies ServerKeyExchange signature using server certificate. */
    private fun verifyTls12ServerKeyExchange(body: ByteArray) {
        val serverCert = serverCertificates.firstOrNull() ?: return
        if (body.size < 4) return

        val pubKeyLen = body[3].toInt() and 0xFF
        val paramsEnd = 4 + pubKeyLen
        if (body.size < paramsEnd + 4) return

        val sigAlgorithm = ((body[paramsEnd].toInt() and 0xFF) shl 8) or
                (body[paramsEnd + 1].toInt() and 0xFF)
        val sigLen = ((body[paramsEnd + 2].toInt() and 0xFF) shl 8) or
                (body[paramsEnd + 3].toInt() and 0xFF)
        if (body.size < paramsEnd + 4 + sigLen) return

        val signature = body.copyOfRange(paramsEnd + 4, paramsEnd + 4 + sigLen)

        val cRandom = clientRandom ?: return
        val sRandom = serverRandom ?: return

        val content = cRandom + sRandom + body.copyOfRange(0, paramsEnd)

        try {
            val sig = java.security.Signature.getInstance(javaSignatureAlgorithm(sigAlgorithm))
            sig.initVerify(serverCert.publicKey)
            sig.update(content)
            if (!sig.verify(signature)) {
                if (configuration.allowInsecure || CertificatePolicy.allowInsecure) return
                throw TlsError.CertificateValidationFailed("ServerKeyExchange signature verification failed")
            }
        } catch (e: TlsError) {
            throw e
        } catch (e: Exception) {
            if (configuration.allowInsecure || CertificatePolicy.allowInsecure) return
            throw TlsError.CertificateValidationFailed("ServerKeyExchange signature verification error: ${e.message}")
        }
    }

    /** Sends ClientKeyExchange + ChangeCipherSpec + Finished, then receives server CCS + Finished. */
    private suspend fun sendTls12ClientKeyExchangeAndFinished(
        buffer: ByteArray,
        processedOffset: Int,
        ckeMessage: ByteArray,
        keys: Tls12Keys,
        masterSecret: ByteArray
    ): TlsRecordConnection {
        val conn = connection ?: throw TlsError.ConnectionFailed("Connection cancelled")
        val useSHA384 = TlsCipherSuite.usesSHA384(tls12CipherSuite)
        val versionHi = ((negotiatedVersion shr 8) and 0xFF).toByte()
        val versionLo = (negotiatedVersion and 0xFF).toByte()

        // Build ClientKeyExchange TLS record
        val ckeRecord = ByteArray(5 + ckeMessage.size)
        ckeRecord[0] = 0x16; ckeRecord[1] = versionHi; ckeRecord[2] = versionLo
        ckeRecord[3] = ((ckeMessage.size shr 8) and 0xFF).toByte()
        ckeRecord[4] = (ckeMessage.size and 0xFF).toByte()
        System.arraycopy(ckeMessage, 0, ckeRecord, 5, ckeMessage.size)

        // ChangeCipherSpec record
        val ccsRecord = byteArrayOf(0x14, versionHi, versionLo, 0x00, 0x01, 0x01)

        // Compute client Finished verify data
        val transcriptHash = Tls12KeyDerivation.transcriptHash(tls12Transcript!!, useSHA384)
        val clientVerifyData = Tls12KeyDerivation.computeFinishedVerifyData(
            masterSecret, "client finished", transcriptHash, useSHA384
        )

        // Build Finished handshake message
        val finishedMsg = ByteArray(4 + clientVerifyData.size)
        finishedMsg[0] = 0x14 // Finished
        finishedMsg[1] = 0x00; finishedMsg[2] = 0x00
        finishedMsg[3] = clientVerifyData.size.toByte()
        System.arraycopy(clientVerifyData, 0, finishedMsg, 4, clientVerifyData.size)

        // Encrypt Finished with client write keys (seqNum = 0 — first record after CCS)
        val encryptedFinished = encryptTls12HandshakeRecord(
            finishedMsg, 0x16, 0, keys, negotiatedVersion
        )

        // Send all three: CKE + CCS + encrypted Finished
        conn.send(ckeRecord + ccsRecord + encryptedFinished)

        // Receive server's ChangeCipherSpec + encrypted Finished
        var buf = if (processedOffset < buffer.size) {
            buffer.copyOfRange(processedOffset, buffer.size)
        } else {
            ByteArray(0)
        }

        // Wait for server CCS + Finished
        while (buf.size < 12) {
            val moreData = conn.receive() ?: throw TlsError.HandshakeFailed("Connection closed waiting for server Finished")
            buf = buf + moreData
        }

        // Skip server ChangeCipherSpec and find encrypted Finished
        var off = 0
        var foundCCS = false
        while (off + 5 <= buf.size) {
            val ct = buf[off].toInt() and 0xFF
            val rl = ((buf[off + 3].toInt() and 0xFF) shl 8) or (buf[off + 4].toInt() and 0xFF)
            if (off + 5 + rl > buf.size) {
                val moreData = conn.receive() ?: throw TlsError.HandshakeFailed("Connection closed")
                buf = buf + moreData
                continue
            }
            if (ct == 0x14) { // ChangeCipherSpec
                foundCCS = true
                off += 5 + rl
                continue
            }
            if (ct == 0x16 && !foundCCS) {
                // Plaintext handshake record BEFORE CCS (e.g. NewSessionTicket).
                // Must be added to the transcript — the server includes it when
                // computing its Finished verify_data.
                val recordBody = buf.copyOfRange(off + 5, off + 5 + rl)
                tls12Transcript = tls12Transcript!! + recordBody
                off += 5 + rl
                continue
            }
            if (ct == 0x16 && foundCCS) { // Encrypted handshake (Finished)
                val encFinished = buf.copyOfRange(off + 5, off + 5 + rl)
                val header = buf.copyOfRange(off, off + 5)
                val decrypted = decryptTls12HandshakeRecord(
                    encFinished, header[0], 0, keys, negotiatedVersion
                )
                // Verify server Finished
                tls12Transcript = tls12Transcript!! + finishedMsg
                val serverTranscriptHash = Tls12KeyDerivation.transcriptHash(tls12Transcript!!, useSHA384)
                val expectedServerVerify = Tls12KeyDerivation.computeFinishedVerifyData(
                    masterSecret, "server finished", serverTranscriptHash, useSHA384
                )
                if (decrypted.size >= 4) {
                    val serverVerify = decrypted.copyOfRange(4, decrypted.size)
                    // Constant-time comparison to prevent timing side-channel attacks
                    // on the server Finished verify_data (matches iOS).
                    if (!constantTimeEqual(serverVerify, expectedServerVerify)) {
                        throw TlsError.HandshakeFailed("TLS 1.2 Server Finished verify data mismatch")
                    }
                }
                off += 5 + rl
                break
            }
            off += 5 + rl
        }

        // Build TLS 1.2 record connection (seqNums start at 1 after Finished)
        val tlsConnection = TlsRecordConnection(
            tls12ClientKey = keys.clientKey,
            clientIV = keys.clientIV,
            serverKey = keys.serverKey,
            serverIV = keys.serverIV,
            clientMACKey = keys.clientMACKey,
            serverMACKey = keys.serverMACKey,
            cipherSuite = tls12CipherSuite,
            protocolVersion = negotiatedVersion,
            initialClientSeqNum = 1,
            initialServerSeqNum = 1
        )
        tlsConnection.connection = connection
        connection = null

        // Pass remaining buffer data
        if (off < buf.size) {
            tlsConnection.prependToReceiveBuffer(buf.copyOfRange(off, buf.size))
        }

        clearHandshakeState()
        return tlsConnection
    }

    /** Encrypts a TLS 1.2 handshake record for sending Client Finished. */
    private fun encryptTls12HandshakeRecord(
        plaintext: ByteArray, contentType: Byte, seqNum: Long,
        keys: Tls12Keys, version: Int
    ): ByteArray {
        val versionHi = ((version shr 8) and 0xFF).toByte()
        val versionLo = (version and 0xFF).toByte()
        val isAEAD = TlsCipherSuite.isAEAD(tls12CipherSuite)
        val isChaCha = TlsCipherSuite.isChaCha20(tls12CipherSuite)

        if (isAEAD) {
            val nonce: ByteArray
            val explicitNonce: ByteArray
            if (isChaCha) {
                nonce = xorNonce(keys.clientIV, seqNum)
                explicitNonce = ByteArray(0)
            } else {
                val seqBytes = seqToBytes(seqNum)
                nonce = keys.clientIV + seqBytes
                explicitNonce = seqBytes
            }

            val aad = ByteArray(13)
            val seqBytes = seqToBytes(seqNum)
            System.arraycopy(seqBytes, 0, aad, 0, 8)
            aad[8] = contentType; aad[9] = versionHi; aad[10] = versionLo
            aad[11] = ((plaintext.size shr 8) and 0xFF).toByte()
            aad[12] = (plaintext.size and 0xFF).toByte()

            val cipherAlgo = if (isChaCha) "ChaCha20" else "AES"
            val cipherTransform = if (isChaCha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
            val cipher = Cipher.getInstance(cipherTransform)
            val keySpec = SecretKeySpec(keys.clientKey, cipherAlgo)
            val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec)
            cipher.updateAAD(aad)
            val encrypted = cipher.doFinal(plaintext)

            val recordPayloadLen = explicitNonce.size + encrypted.size
            val record = ByteArray(5 + recordPayloadLen)
            record[0] = contentType; record[1] = versionHi; record[2] = versionLo
            record[3] = ((recordPayloadLen shr 8) and 0xFF).toByte()
            record[4] = (recordPayloadLen and 0xFF).toByte()
            if (explicitNonce.isNotEmpty()) {
                System.arraycopy(explicitNonce, 0, record, 5, explicitNonce.size)
            }
            System.arraycopy(encrypted, 0, record, 5 + explicitNonce.size, encrypted.size)
            return record
        } else {
            // CBC mode
            val useSHA384 = TlsCipherSuite.usesSHA384(tls12CipherSuite)
            val useSHA256 = TlsCipherSuite.cbcUsesSHA256(tls12CipherSuite)
            val mac = Tls12KeyDerivation.tls10MAC(
                keys.clientMACKey, seqNum, contentType, version, plaintext, useSHA384, useSHA256
            )

            val data = plaintext + mac
            val blockSize = 16
            val paddingLen = blockSize - (data.size % blockSize)
            val paddingByte = (paddingLen - 1).toByte()
            val padded = data + ByteArray(paddingLen) { paddingByte }

            val iv = ByteArray(blockSize)
            java.security.SecureRandom().nextBytes(iv)

            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys.clientKey, "AES"), IvParameterSpec(iv))
            val encrypted = cipher.doFinal(padded)

            val recordPayloadLen = blockSize + encrypted.size
            val record = ByteArray(5 + recordPayloadLen)
            record[0] = contentType; record[1] = versionHi; record[2] = versionLo
            record[3] = ((recordPayloadLen shr 8) and 0xFF).toByte()
            record[4] = (recordPayloadLen and 0xFF).toByte()
            System.arraycopy(iv, 0, record, 5, blockSize)
            System.arraycopy(encrypted, 0, record, 5 + blockSize, encrypted.size)
            return record
        }
    }

    /** Decrypts a TLS 1.2 encrypted handshake record (server Finished). */
    private fun decryptTls12HandshakeRecord(
        ciphertext: ByteArray, contentType: Byte, seqNum: Long,
        keys: Tls12Keys, version: Int
    ): ByteArray {
        val isAEAD = TlsCipherSuite.isAEAD(tls12CipherSuite)
        val isChaCha = TlsCipherSuite.isChaCha20(tls12CipherSuite)

        if (isAEAD) {
            val explicitNonceLen = if (isChaCha) 0 else 8
            if (ciphertext.size < explicitNonceLen + 16) {
                throw TlsError.HandshakeFailed("Ciphertext too short")
            }
            val explicitNonce = if (isChaCha) ByteArray(0) else ciphertext.copyOfRange(0, explicitNonceLen)
            val payload = ciphertext.copyOfRange(explicitNonceLen, ciphertext.size)

            val nonce = if (isChaCha) {
                xorNonce(keys.serverIV, seqNum)
            } else {
                keys.serverIV + explicitNonce
            }

            val plaintextLen = payload.size - 16
            val aad = ByteArray(13)
            val seqBytes = seqToBytes(seqNum)
            System.arraycopy(seqBytes, 0, aad, 0, 8)
            aad[8] = contentType
            aad[9] = ((version shr 8) and 0xFF).toByte()
            aad[10] = (version and 0xFF).toByte()
            aad[11] = ((plaintextLen shr 8) and 0xFF).toByte()
            aad[12] = (plaintextLen and 0xFF).toByte()

            val cipherAlgo = if (isChaCha) "ChaCha20" else "AES"
            val cipherTransform = if (isChaCha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
            val cipher = Cipher.getInstance(cipherTransform)
            val keySpec = SecretKeySpec(keys.serverKey, cipherAlgo)
            val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec)
            cipher.updateAAD(aad)
            return cipher.doFinal(payload)
        } else {
            // CBC decryption with MAC verification (matching iOS)
            val blockSize = 16
            if (ciphertext.size < blockSize * 2) throw TlsError.HandshakeFailed("Ciphertext too short for CBC")

            val iv = ciphertext.copyOfRange(0, blockSize)
            val encrypted = ciphertext.copyOfRange(blockSize, ciphertext.size)

            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keys.serverKey, "AES"), IvParameterSpec(iv))
            var decrypted = cipher.doFinal(encrypted)

            // Validate and strip padding (constant-time to mitigate Lucky13).
            // We always run the validation loop with a clamped index range so the
            // execution time does not leak whether `paddingLen` was out of bounds.
            val paddingByte = decrypted.last().toInt() and 0xFF
            val paddingLen = paddingByte + 1
            var paddingGood = 0
            if (paddingLen > decrypted.size) {
                paddingGood = 1
            } else {
                for (i in (decrypted.size - paddingLen) until decrypted.size) {
                    paddingGood = paddingGood or (decrypted[i].toInt() and 0xFF xor paddingByte)
                }
            }
            if (paddingGood != 0) throw TlsError.HandshakeFailed("Invalid CBC padding")
            decrypted = decrypted.copyOfRange(0, decrypted.size - paddingLen)

            // Strip and verify MAC
            val macSize = TlsCipherSuite.macLength(tls12CipherSuite)
            if (decrypted.size < macSize) throw TlsError.HandshakeFailed("Decrypted data too short for MAC")
            val payload = decrypted.copyOfRange(0, decrypted.size - macSize)
            val receivedMAC = decrypted.copyOfRange(decrypted.size - macSize, decrypted.size)

            val useSHA384 = TlsCipherSuite.usesSHA384(tls12CipherSuite)
            val useSHA256 = TlsCipherSuite.cbcUsesSHA256(tls12CipherSuite)
            val expectedMAC = Tls12KeyDerivation.tls10MAC(
                keys.serverMACKey, seqNum, contentType, version, payload, useSHA384, useSHA256
            )
            // Constant-time MAC comparison to prevent timing side-channel attacks.
            if (receivedMAC.size != expectedMAC.size ||
                !constantTimeEqual(receivedMAC, expectedMAC)) {
                throw TlsError.HandshakeFailed("Handshake record MAC verification failed")
            }
            return payload
        }
    }

    /** XOR sequence number into the last 8 bytes of an IV. */
    private fun xorNonce(iv: ByteArray, seqNum: Long): ByteArray {
        val nonce = iv.copyOf()
        val base = nonce.size - 8
        for (i in 0 until 8) {
            nonce[base + i] = (nonce[base + i].toInt() xor ((seqNum shr ((7 - i) * 8)) and 0xFF).toInt()).toByte()
        }
        return nonce
    }

    /** Convert sequence number to 8-byte big-endian array. */
    private fun seqToBytes(seqNum: Long): ByteArray {
        val bytes = ByteArray(8)
        for (i in 0 until 8) { bytes[i] = ((seqNum shr ((7 - i) * 8)) and 0xFF).toByte() }
        return bytes
    }

    // -- Helpers --

    /** Frees handshake-only state to reduce memory after the connection is established. */
    private fun clearHandshakeState() {
        ephemeralPrivateKeyBytes = null
        ephemeralPublicKeyBytes = null
        storedClientHello = null
        clientRandom = null
        keyDerivation = null
        handshakeSecret = null
        handshakeKeys = null
        handshakeTranscript = null
        serverRandom = null
        tls12Transcript = null
        serverCertificates.clear()
    }
}
