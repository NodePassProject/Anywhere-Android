package com.argsment.anywhere.vpn.protocol.reality

import android.util.Log
import com.argsment.anywhere.data.model.RealityConfiguration
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.protocol.tls.Tls13KeyDerivation
import com.argsment.anywhere.vpn.protocol.tls.TlsApplicationKeys
import com.argsment.anywhere.vpn.protocol.tls.TlsClientHelloBuilder
import com.argsment.anywhere.vpn.protocol.tls.TlsHandshakeKeys
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.vless.RealityError
import com.argsment.anywhere.vpn.util.NioSocket
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val TAG = "RealityClient"

/**
 * Client for establishing authenticated Reality connections over TLS 1.3.
 *
 * Performs a TLS 1.3 handshake with Reality-specific extensions:
 * - Embeds authentication metadata in the ClientHello SessionId (AES-GCM encrypted).
 * - Uses X25519 ECDH with the server's public key for mutual authentication.
 * - Derives application-layer encryption keys from the TLS 1.3 handshake transcript.
 *
 * After a successful handshake, returns a [TlsRecordConnection] that wraps
 * the underlying [NioSocket] with TLS record encryption/decryption.
 *
 * Port of iOS RealityClient.swift (653 lines).
 */
class RealityClient(
    private val configuration: RealityConfiguration
) {
    private var connection: NioSocket? = null

    // Ephemeral key pair (cleared after handshake)
    private var ephemeralPrivateKey: java.security.PrivateKey? = null
    private var ephemeralPublicKeyBytes: ByteArray? = null
    private var authKey: ByteArray? = null
    private var storedClientHello: ByteArray? = null

    // TLS 1.3 session state (cleared after handshake)
    private var keyDerivation: Tls13KeyDerivation? = null
    private var handshakeSecret: ByteArray? = null
    private var handshakeKeys: TlsHandshakeKeys? = null
    private var applicationKeys: TlsApplicationKeys? = null
    private var handshakeTranscript: ByteArray? = null
    private var serverHandshakeSeqNum: Long = 0

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Connects to a Reality server and performs the TLS handshake.
     *
     * @param host The server hostname or IP address.
     * @param port The server port number.
     * @return The established [TlsRecordConnection].
     */
    suspend fun connect(host: String, port: Int): TlsRecordConnection {
        // Generate ephemeral X25519 key pair
        val kpg = KeyPairGenerator.getInstance("X25519")
        val keyPair = kpg.generateKeyPair()
        ephemeralPrivateKey = keyPair.private
        // Extract raw 32-byte public key
        ephemeralPublicKeyBytes = extractX25519PublicKeyBytes(keyPair.public)

        val socket = NioSocket()
        connection = socket

        try {
            socket.connect(host, port)
        } catch (e: Exception) {
            Log.e(TAG, "[Reality] TCP connection failed: ${e.message}")
            throw RealityError.HandshakeFailed("TCP connection failed: ${e.message}")
        }

        return performRealityHandshake()
    }

    /**
     * Cancels the connection and releases all resources.
     */
    fun cancel() {
        clearHandshakeState()
        connection?.forceCancel()
        connection = null
    }

    // =========================================================================
    // Handshake
    // =========================================================================

    /**
     * Performs the Reality TLS handshake: sends ClientHello, processes ServerHello,
     * derives encryption keys, and sends Client Finished.
     */
    private suspend fun performRealityHandshake(): TlsRecordConnection {
        val privateKey = ephemeralPrivateKey
            ?: throw RealityError.HandshakeFailed("No ephemeral key")

        val clientHello = buildRealityClientHello(privateKey)

        // Store for TLS transcript (without 5-byte TLS record header)
        storedClientHello = clientHello.copyOfRange(5, clientHello.size)

        val conn = connection
            ?: throw RealityError.HandshakeFailed("Connection cancelled")

        conn.send(clientHello)

        return receiveServerResponse()
    }

    // =========================================================================
    // ClientHello
    // =========================================================================

    /**
     * Builds a TLS ClientHello with Reality authentication metadata.
     *
     * Embeds version, timestamp, and shortId in the SessionId field,
     * encrypted with AES-GCM using a key derived from ECDH with the server.
     *
     * @param privateKey The ephemeral X25519 private key for this connection.
     * @return A complete TLS record containing the ClientHello.
     */
    private fun buildRealityClientHello(privateKey: java.security.PrivateKey): ByteArray {
        val random = ByteArray(32)
        SecureRandom().nextBytes(random)

        // Build SessionId with Reality metadata in first 16 bytes
        val sessionId = ByteArray(32)
        sessionId[0] = 26  // Xray-core version 26.1.18
        sessionId[1] = 1
        sessionId[2] = 18
        sessionId[3] = 0

        val timestamp = (System.currentTimeMillis() / 1000).toInt()
        sessionId[4] = ((timestamp shr 24) and 0xFF).toByte()
        sessionId[5] = ((timestamp shr 16) and 0xFF).toByte()
        sessionId[6] = ((timestamp shr 8) and 0xFF).toByte()
        sessionId[7] = (timestamp and 0xFF).toByte()

        val shortIdLen = minOf(configuration.shortId.size, 8)
        for (i in 0 until shortIdLen) {
            sessionId[8 + i] = configuration.shortId[i]
        }

        // ECDH with server's public key to derive auth key
        val serverPubKey = buildX25519PublicKey(configuration.publicKey)
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privateKey)
        ka.doPhase(serverPubKey, true)
        val sharedSecretBytes = ka.generateSecret()

        val salt = random.copyOfRange(0, 20)
        val info = "REALITY".toByteArray(Charsets.UTF_8)
        authKey = deriveKeyHKDF(sharedSecretBytes, salt, info, 32)

        val currentAuthKey = authKey
            ?: throw RealityError.HandshakeFailed("Failed to derive auth key")

        val pubKeyBytes = ephemeralPublicKeyBytes
            ?: throw RealityError.HandshakeFailed("No public key bytes")

        // Build ClientHello with zero SessionId for AAD (matching Xray-core)
        val zeroSessionId = ByteArray(32)
        val rawClientHelloForAAD = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint = configuration.fingerprint,
            random = random,
            sessionId = zeroSessionId,
            serverName = configuration.serverName,
            publicKey = pubKeyBytes
        )

        // Encrypt first 16 bytes of SessionId using AES-GCM
        val nonce = random.copyOfRange(20, 32)
        val plaintext = sessionId.copyOfRange(0, 16)

        val encryptedSessionId = encryptAESGCM(
            plaintext = plaintext,
            key = currentAuthKey,
            nonce = nonce,
            aad = rawClientHelloForAAD
        )

        // Build final ClientHello with encrypted sessionId
        val finalClientHello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint = configuration.fingerprint,
            random = random,
            sessionId = encryptedSessionId,
            serverName = configuration.serverName,
            publicKey = pubKeyBytes
        )

        return TlsClientHelloBuilder.wrapInTLSRecord(finalClientHello)
    }

    // =========================================================================
    // Server Response Processing
    // =========================================================================

    /**
     * Receives and processes the server's TLS response.
     */
    private suspend fun receiveServerResponse(): TlsRecordConnection {
        val conn = connection
            ?: throw RealityError.HandshakeFailed("Connection cancelled")

        val data = conn.receive()
            ?: throw RealityError.HandshakeFailed("No server response")

        if (data.size < 5) {
            throw RealityError.HandshakeFailed("Server response too short")
        }

        val contentType = data[0].toInt() and 0xFF

        return when (contentType) {
            0x16 -> { // Handshake
                continueReceivingHandshake(data)
            }
            0x15 -> { // Alert
                val alertLevel = if (data.size > 5) data[5].toInt() and 0xFF else 0
                val alertDesc = if (data.size > 6) data[6].toInt() and 0xFF else 0
                Log.e(TAG, "[Reality] TLS Alert: level=$alertLevel, desc=$alertDesc")
                throw RealityError.HandshakeFailed("TLS Alert: level=$alertLevel, desc=$alertDesc")
            }
            else -> {
                Log.e(TAG, "[Reality] Unexpected content type: 0x${String.format("%02x", contentType)}")
                throw RealityError.HandshakeFailed("Unexpected content type: $contentType")
            }
        }
    }

    /**
     * Continues receiving handshake messages until ServerHello is complete.
     */
    private suspend fun continueReceivingHandshake(buffer: ByteArray): TlsRecordConnection {
        var buf = buffer

        while (buf.size < 100) {
            val conn = connection
                ?: throw RealityError.HandshakeFailed("Connection cancelled")
            val moreData = conn.receive()
            if (moreData != null) {
                buf = buf + moreData
            }
        }

        if (!verifyServerResponse(buf)) {
            Log.e(TAG, "[Reality] Server verification failed")
            throw RealityError.HandshakeFailed("Server verification failed")
        }

        val parsed = parseServerHello(buf)
            ?: throw RealityError.HandshakeFailed("Failed to parse ServerHello")

        val serverKeyShare = parsed.first
        val cipherSuite = parsed.second

        val privateKey = ephemeralPrivateKey
            ?: throw RealityError.HandshakeFailed("No ephemeral key")
        val clientHello = storedClientHello
            ?: throw RealityError.HandshakeFailed("No stored ClientHello")

        // Perform ECDH with server's ephemeral key
        val serverEphPubKey = buildX25519PublicKey(serverKeyShare)
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privateKey)
        ka.doPhase(serverEphPubKey, true)
        val sharedSecretData = ka.generateSecret()

        val serverHello = extractServerHelloMessage(buf)

        keyDerivation = Tls13KeyDerivation(cipherSuite)

        val transcript = clientHello + serverHello

        val (hs, keys) = keyDerivation!!.deriveHandshakeKeys(sharedSecretData, transcript)
        handshakeSecret = hs
        handshakeKeys = keys
        handshakeTranscript = transcript

        return consumeRemainingHandshake(buf, 0)
    }

    // =========================================================================
    // ServerHello Parsing
    // =========================================================================

    /**
     * Extracts the ServerHello handshake message from the buffer (without TLS record header).
     */
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
        return byteArrayOf()
    }

    /**
     * Parses the ServerHello to extract the server's X25519 key share and cipher suite.
     * First tries the native C parser, then falls back to the Kotlin parser.
     *
     * @param data The raw TLS data containing the ServerHello record.
     * @return A pair of (keyShare, cipherSuite) or null if parsing fails.
     */
    private fun parseServerHello(data: ByteArray): Pair<ByteArray, Int>? {
        // Try native parser first
        val nativeResult = NativeBridge.nativeParseServerHello(data)
        if (nativeResult != null && nativeResult.size == 34) {
            val keyShare = nativeResult.copyOfRange(0, 32)
            val cipherSuite = ((nativeResult[32].toInt() and 0xFF) shl 8) or
                    (nativeResult[33].toInt() and 0xFF)
            return Pair(keyShare, cipherSuite)
        }

        // Fallback to Kotlin parser
        return parseServerHelloKotlin(data)
    }

    /**
     * Kotlin fallback for ServerHello parsing.
     */
    private fun parseServerHelloKotlin(data: ByteArray): Pair<ByteArray, Int>? {
        var offset = 0

        while (offset + 5 < data.size) {
            val contentType = data[offset].toInt() and 0xFF
            if (contentType != 0x16) break

            val recordLen = ((data[offset + 3].toInt() and 0xFF) shl 8) or
                    (data[offset + 4].toInt() and 0xFF)
            offset += 5

            if (offset + recordLen > data.size) break
            if ((data[offset].toInt() and 0xFF) != 0x02) {
                offset += recordLen
                continue
            }

            // ServerHello found
            var shOffset = offset + 1 + 3 + 2 + 32 // type + length(3) + version(2) + random(32)
            if (shOffset >= data.size) return null

            val sessionIdLen = data[shOffset].toInt() and 0xFF
            shOffset += 1 + sessionIdLen

            if (shOffset + 2 > data.size) return null
            val cipherSuite = ((data[shOffset].toInt() and 0xFF) shl 8) or
                    (data[shOffset + 1].toInt() and 0xFF)

            shOffset += 3 // cipher suite (2) + compression method (1)
            if (shOffset + 2 > data.size) return null

            val extLen = ((data[shOffset].toInt() and 0xFF) shl 8) or
                    (data[shOffset + 1].toInt() and 0xFF)
            shOffset += 2

            val extEnd = shOffset + extLen
            if (extEnd > data.size) return null

            while (shOffset + 4 <= extEnd) {
                val extType = ((data[shOffset].toInt() and 0xFF) shl 8) or
                        (data[shOffset + 1].toInt() and 0xFF)
                val extDataLen = ((data[shOffset + 2].toInt() and 0xFF) shl 8) or
                        (data[shOffset + 3].toInt() and 0xFF)
                shOffset += 4

                if (extType == 0x0033) { // key_share
                    if (shOffset + 4 > data.size) return null
                    val group = ((data[shOffset].toInt() and 0xFF) shl 8) or
                            (data[shOffset + 1].toInt() and 0xFF)
                    val keyLen = ((data[shOffset + 2].toInt() and 0xFF) shl 8) or
                            (data[shOffset + 3].toInt() and 0xFF)
                    shOffset += 4

                    if (group == 0x001d && keyLen == 32) {
                        if (shOffset + 32 > data.size) return null
                        return Pair(
                            data.copyOfRange(shOffset, shOffset + 32),
                            cipherSuite
                        )
                    }
                }

                shOffset += extDataLen
            }

            break
        }

        return null
    }

    // =========================================================================
    // Encrypted Handshake Processing
    // =========================================================================

    /**
     * Consumes remaining TLS handshake records (encrypted), looking for Server Finished.
     *
     * Once Server Finished is found, derives application keys and sends Client Finished.
     */
    private suspend fun consumeRemainingHandshake(
        buffer: ByteArray,
        startOffset: Int
    ): TlsRecordConnection {
        val keys = handshakeKeys
            ?: throw RealityError.HandshakeFailed("Missing handshake keys")
        val kd = keyDerivation
            ?: throw RealityError.HandshakeFailed("Missing key derivation")

        var offset = startOffset
        var fullTranscript = handshakeTranscript ?: byteArrayOf()
        var foundServerFinished = false

        while (offset + 5 <= buffer.size) {
            val contentType = buffer[offset].toInt() and 0xFF
            val recordLen = ((buffer[offset + 3].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 4].toInt() and 0xFF)

            if (offset + 5 + recordLen > buffer.size) break

            if (contentType == 0x14 || contentType == 0x16) {
                // ChangeCipherSpec or plaintext handshake - skip
                offset += 5 + recordLen
                continue
            } else if (contentType == 0x17) {
                // Encrypted handshake (Application Data wrapper)
                val recordHeader = buffer.copyOfRange(offset, offset + 5)
                val ciphertext = buffer.copyOfRange(offset + 5, offset + 5 + recordLen)

                try {
                    val seqNum = serverHandshakeSeqNum
                    val decrypted = decryptHandshakeRecord(
                        ciphertext = ciphertext,
                        key = keys.serverKey,
                        iv = keys.serverIV,
                        seqNum = seqNum,
                        recordHeader = recordHeader
                    )
                    serverHandshakeSeqNum++

                    // Add decrypted handshake messages to transcript
                    var hsOffset = 0
                    while (hsOffset + 4 <= decrypted.size) {
                        val hsType = decrypted[hsOffset].toInt() and 0xFF
                        val hsLen = ((decrypted[hsOffset + 1].toInt() and 0xFF) shl 16) or
                                ((decrypted[hsOffset + 2].toInt() and 0xFF) shl 8) or
                                (decrypted[hsOffset + 3].toInt() and 0xFF)

                        if (hsOffset + 4 + hsLen > decrypted.size) break

                        val hsMessage = decrypted.copyOfRange(hsOffset, hsOffset + 4 + hsLen)
                        fullTranscript = fullTranscript + hsMessage

                        if (hsType == 0x14) { // Finished
                            foundServerFinished = true
                        }

                        hsOffset += 4 + hsLen
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "[Reality] Failed to decrypt handshake record: ${e.message}")
                }
            }

            offset += 5 + recordLen
        }

        val processedOffset = offset
        handshakeTranscript = fullTranscript

        if (foundServerFinished) {
            applicationKeys = kd.deriveApplicationKeys(handshakeSecret!!, fullTranscript)

            sendClientFinished()

            val appKeys = applicationKeys
                ?: throw RealityError.HandshakeFailed("Application keys not available")

            val realityConnection = TlsRecordConnection(
                clientKey = appKeys.clientKey,
                clientIV = appKeys.clientIV,
                serverKey = appKeys.serverKey,
                serverIV = appKeys.serverIV
            )
            realityConnection.connection = connection
            connection = null

            clearHandshakeState()
            return realityConnection
        } else {
            // Need more handshake data
            val conn = connection
                ?: throw RealityError.HandshakeFailed("Connection cancelled")

            val moreData = conn.receive()
            var newBuffer = buffer
            if (moreData != null) {
                newBuffer = buffer + moreData
            }

            return consumeRemainingHandshake(newBuffer, processedOffset)
        }
    }

    // =========================================================================
    // Client Finished
    // =========================================================================

    /**
     * Sends the ChangeCipherSpec and encrypted Client Finished messages.
     */
    private suspend fun sendClientFinished() {
        val keys = handshakeKeys
            ?: throw RealityError.HandshakeFailed("Missing handshake keys")
        val transcript = handshakeTranscript
            ?: throw RealityError.HandshakeFailed("Missing transcript")
        val kd = keyDerivation
            ?: throw RealityError.HandshakeFailed("Missing key derivation")

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
            plaintext = finishedMsg,
            key = keys.clientKey,
            iv = keys.clientIV,
            seqNum = 0
        )

        val fullMessage = ccsRecord + finishedRecord

        val conn = connection
            ?: throw RealityError.HandshakeFailed("Connection cancelled")
        conn.send(fullMessage)
    }

    // =========================================================================
    // Verification
    // =========================================================================

    /**
     * Verifies the server response contains a valid ServerHello.
     */
    private fun verifyServerResponse(data: ByteArray): Boolean {
        if (authKey == null) return false

        var offset = 0
        while (offset + 5 < data.size) {
            val contentType = data[offset].toInt() and 0xFF
            if (contentType != 0x16) break

            val recordLen = ((data[offset + 3].toInt() and 0xFF) shl 8) or
                    (data[offset + 4].toInt() and 0xFF)
            offset += 5

            if (offset + recordLen > data.size) break

            if ((data[offset].toInt() and 0xFF) == 0x02) { // ServerHello
                return true
            }

            offset += recordLen
        }

        return false
    }

    // =========================================================================
    // Crypto Helpers
    // =========================================================================

    /**
     * Encrypts plaintext with AES-GCM.
     * Returns ciphertext + tag (32 bytes for 16 bytes plaintext).
     */
    private fun encryptAESGCM(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(key, "AES")
        val parameterSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec)
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
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
        val nonce = buildNonce(iv, seqNum)

        // Inner plaintext: data + content type 0x16 (handshake)
        val innerPlaintext = plaintext + byteArrayOf(0x16)

        val encryptedLen = innerPlaintext.size + 16
        val aad = byteArrayOf(
            0x17, 0x03, 0x03,
            (encryptedLen shr 8).toByte(),
            (encryptedLen and 0xFF).toByte()
        )

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(key, "AES")
        val parameterSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec)
        cipher.updateAAD(aad)
        val ciphertextAndTag = cipher.doFinal(innerPlaintext)

        return aad + ciphertextAndTag
    }

    /**
     * Decrypts a TLS 1.3 handshake record using AES-GCM.
     * Returns the decrypted handshake messages (stripped of inner content type and padding).
     */
    private fun decryptHandshakeRecord(
        ciphertext: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        seqNum: Long,
        recordHeader: ByteArray
    ): ByteArray {
        if (ciphertext.size < 16) {
            throw RealityError.HandshakeFailed("Ciphertext too short")
        }

        val nonce = buildNonce(iv, seqNum)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = SecretKeySpec(key, "AES")
        val parameterSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec)
        cipher.updateAAD(recordHeader)
        val decrypted = cipher.doFinal(ciphertext)

        if (decrypted.isEmpty()) {
            throw RealityError.HandshakeFailed("Empty decrypted data")
        }

        // Strip inner content type and padding (TLS 1.3: trailing content type + zero padding)
        var endIndex = decrypted.size - 1
        while (endIndex >= 0 && decrypted[endIndex].toInt() == 0) {
            endIndex--
        }

        if (endIndex < 0) {
            throw RealityError.HandshakeFailed("No content type found")
        }

        // endIndex points to the inner content type byte
        // Return everything before it
        return if (endIndex > 0) {
            decrypted.copyOfRange(0, endIndex)
        } else {
            byteArrayOf()
        }
    }

    /**
     * Builds a TLS 1.3 nonce by XORing the IV with the sequence number.
     */
    private fun buildNonce(iv: ByteArray, seqNum: Long): ByteArray {
        val nonce = iv.copyOf()
        val base = nonce.size - 8
        for (i in 0 until 8) {
            nonce[base + i] = (nonce[base + i].toInt() xor
                    ((seqNum shr ((7 - i) * 8)) and 0xFF).toInt()).toByte()
        }
        return nonce
    }

    /**
     * Derives a symmetric key from a shared secret using HKDF (via javax.crypto).
     */
    private fun deriveKeyHKDF(
        sharedSecret: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int
    ): ByteArray {
        // HKDF-Extract
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        val saltKey = SecretKeySpec(
            if (salt.isEmpty()) ByteArray(32) else salt,
            "HmacSHA256"
        )
        mac.init(saltKey)
        val prk = mac.doFinal(sharedSecret)

        // HKDF-Expand
        val result = ByteArray(outputLength)
        var offset = 0
        var counter: Byte = 1
        var previousBlock = byteArrayOf()

        while (offset < outputLength) {
            val expandMac = javax.crypto.Mac.getInstance("HmacSHA256")
            expandMac.init(SecretKeySpec(prk, "HmacSHA256"))
            expandMac.update(previousBlock)
            expandMac.update(info)
            expandMac.update(byteArrayOf(counter))
            previousBlock = expandMac.doFinal()

            val toCopy = minOf(previousBlock.size, outputLength - offset)
            System.arraycopy(previousBlock, 0, result, offset, toCopy)
            offset += toCopy
            counter++
        }

        return result
    }

    // =========================================================================
    // X25519 Key Helpers
    // =========================================================================

    /**
     * Extracts the raw 32-byte X25519 public key from a Java PublicKey.
     * The encoded form is X.509 SubjectPublicKeyInfo; the raw key is the last 32 bytes.
     */
    private fun extractX25519PublicKeyBytes(publicKey: java.security.PublicKey): ByteArray {
        val encoded = publicKey.encoded
        // X.509 encoding for X25519 is 44 bytes: 12-byte header + 32-byte key
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    /**
     * Builds a Java PublicKey from raw 32-byte X25519 key material.
     */
    private fun buildX25519PublicKey(rawBytes: ByteArray): java.security.PublicKey {
        // X.509 SubjectPublicKeyInfo header for X25519
        val header = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00
        )
        val encoded = header + rawBytes
        val keySpec = java.security.spec.X509EncodedKeySpec(encoded)
        val kf = KeyFactory.getInstance("X25519")
        return kf.generatePublic(keySpec)
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    /**
     * Frees handshake-only state to reduce memory after the connection is established.
     */
    private fun clearHandshakeState() {
        ephemeralPrivateKey = null
        ephemeralPublicKeyBytes = null
        authKey = null
        storedClientHello = null
        keyDerivation = null
        handshakeSecret = null
        handshakeKeys = null
        handshakeTranscript = null
    }
}
