package com.argsment.anywhere.vpn.protocol.shadowsocks

import android.util.Log
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

private const val TAG = "SS2022"

private const val HEADER_TYPE_CLIENT: Byte = 0
private const val HEADER_TYPE_SERVER: Byte = 1
private const val MAX_PADDING_LENGTH = 900
private const val MAX_TIMESTAMP_DIFF = 30L
private const val TAG_SIZE = 16

// =============================================================================
// Shadowsocks2022Connection (TCP)
// =============================================================================

/**
 * Wraps a transport with Shadowsocks 2022 AEAD encryption.
 *
 * Request format: salt + [identity headers] + seal(fixedHeader) + seal(variableHeader+payload) [+ AEAD chunks]
 * Response format: salt + seal(fixedHeader) + seal(data) [+ AEAD chunks]
 */
class Shadowsocks2022Connection(
    private val transport: Transport,
    private val cipher: ShadowsocksCipher,
    private val pskList: List<ByteArray>,
    private var addressHeader: ByteArray?
) : VlessConnection() {

    private val random = SecureRandom()
    private val psk = pskList.last()
    private val pskHashes: List<ByteArray> = (1 until pskList.size).map {
        ShadowsocksKeyDerivation.blake3Hash16(pskList[it])
    }

    // Write state
    private var requestSalt: ByteArray? = null
    private var writeNonce = ShadowsocksNonce(cipher.nonceSize)
    private var writeSubkey: ByteArray? = null
    private var handshakeSent = false

    // Read state
    private var readNonce = ShadowsocksNonce(cipher.nonceSize)
    private var readSubkey: ByteArray? = null
    private var readBuffer = byteArrayOf()
    private var readBufferOffset = 0
    private var responseHeaderParsed = false
    private var pendingVarHeaderLen: Int? = null
    private var pendingPayloadLength: Int? = null

    /** Compact threshold — avoid O(n) shifts until dead space is significant (matching iOS). */
    private companion object {
        const val COMPACT_THRESHOLD = 4096
    }

    private val sendLock = Any()

    init {
        responseHeaderReceived = true
    }

    override val isConnected: Boolean get() = true

    override suspend fun sendRaw(data: ByteArray) {
        val needsHandshake: Boolean
        val header: ByteArray?
        synchronized(sendLock) {
            needsHandshake = !handshakeSent
            header = addressHeader
            if (needsHandshake) {
                handshakeSent = true
                addressHeader = null
            }
        }

        if (needsHandshake) {
            val output = buildRequest(data, header!!)
            transport.send(output)
        } else {
            val encrypted = sealChunks(data)
            transport.send(encrypted)
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        try {
            val needsHandshake: Boolean
            val header: ByteArray?
            synchronized(sendLock) {
                needsHandshake = !handshakeSent
                header = addressHeader
                if (needsHandshake) {
                    handshakeSent = true
                    addressHeader = null
                }
            }

            if (needsHandshake) {
                val output = buildRequest(data, header!!)
                transport.sendAsync(output)
            } else {
                val encrypted = sealChunks(data)
                transport.sendAsync(encrypted)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        while (true) {
            val data = transport.receive() ?: return null
            if (data.isEmpty()) return null
            val plaintext = processReceived(data)
            if (plaintext.isNotEmpty()) return plaintext
        }
    }

    override fun cancel() {
        transport.forceCancel()
    }

    // -- Request Construction --

    private fun buildRequest(payload: ByteArray, addressHeader: ByteArray): ByteArray {
        val keySize = cipher.keySize

        // Generate random salt
        val salt = ShadowsocksAEADCrypto.generateRandomSalt(keySize)
        requestSalt = salt

        // Derive session key via BLAKE3
        val sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk, salt, keySize)
        writeSubkey = sessionKey

        val output = ByteArrayOutputStream()
        output.write(salt)

        // Write extended identity headers for multi-user mode
        if (pskList.size >= 2) {
            writeIdentityHeaders(output, salt)
        }

        // Fixed header: type(1) + timestamp(8) + variableHeaderLen(2) = 11 bytes
        val paddingLen = if (payload.size < MAX_PADDING_LENGTH) random.nextInt(MAX_PADDING_LENGTH) + 1 else 0
        val variableHeaderLen = addressHeader.size + 2 + paddingLen + payload.size

        val fixedHeader = ByteArrayOutputStream(11)
        fixedHeader.write(HEADER_TYPE_CLIENT.toInt())
        val timestamp = System.currentTimeMillis() / 1000
        fixedHeader.write(timestamp.toBigEndianBytes())
        fixedHeader.write(variableHeaderLen.toUShortBigEndian())

        // Seal fixed header
        val sealedFixed = ShadowsocksAEADCrypto.seal(cipher, sessionKey, writeNonce.next(), fixedHeader.toByteArray())
        output.write(sealedFixed)

        // Variable header: address + paddingLen(2) + padding + payload
        val variableHeader = ByteArrayOutputStream(variableHeaderLen)
        variableHeader.write(addressHeader)
        variableHeader.write(paddingLen.toUShortBigEndian())
        if (paddingLen > 0) {
            variableHeader.write(ByteArray(paddingLen))
        }
        variableHeader.write(payload)

        // Seal variable header
        val sealedVariable = ShadowsocksAEADCrypto.seal(cipher, sessionKey, writeNonce.next(), variableHeader.toByteArray())
        output.write(sealedVariable)

        return output.toByteArray()
    }

    private fun writeIdentityHeaders(output: ByteArrayOutputStream, salt: ByteArray) {
        val keySize = cipher.keySize
        for (i in 0 until pskList.size - 1) {
            val identitySubkey = ShadowsocksKeyDerivation.deriveIdentitySubkey(pskList[i], salt, keySize)
            val pskHash = pskHashes[i]
            output.write(AesEcb.encrypt(identitySubkey, pskHash))
        }
    }

    /** Encrypts data into standard AEAD chunks (for subsequent sends after handshake). */
    private fun sealChunks(plaintext: ByteArray): ByteArray {
        val subkey = writeSubkey ?: throw ShadowsocksError.DecryptionFailed()
        val maxPayload = ShadowsocksAEADWriter.MAX_PAYLOAD_SIZE
        val output = ByteArrayOutputStream()
        var offset = 0

        while (offset < plaintext.size) {
            val remaining = plaintext.size - offset
            val chunkSize = minOf(remaining, maxPayload)
            val chunk = plaintext.copyOfRange(offset, offset + chunkSize)

            // Encrypted 2-byte length
            val lengthBytes = byteArrayOf((chunkSize shr 8).toByte(), (chunkSize and 0xFF).toByte())
            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, writeNonce.next(), lengthBytes))

            // Encrypted payload
            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, writeNonce.next(), chunk))

            offset += chunkSize
        }

        return output.toByteArray()
    }

    // -- Response Parsing --

    /** Number of unprocessed bytes in the read buffer. */
    private var _readBufferEnd = 0
    private fun readBufferAvailable(): Int = _readBufferEnd - readBufferOffset

    private fun processReceived(data: ByteArray): ByteArray {
        // Append incoming data
        val activeLen = readBufferAvailable()
        val needed = activeLen + data.size
        if (readBufferOffset + activeLen + data.size > readBuffer.size) {
            // Compact or grow
            if (readBuffer.size >= needed && readBufferOffset > 0) {
                System.arraycopy(readBuffer, readBufferOffset, readBuffer, 0, activeLen)
            } else {
                val newBuf = ByteArray(maxOf(readBuffer.size * 2, needed))
                System.arraycopy(readBuffer, readBufferOffset, newBuf, 0, activeLen)
                readBuffer = newBuf
            }
            readBufferOffset = 0
            _readBufferEnd = activeLen
        }
        System.arraycopy(data, 0, readBuffer, _readBufferEnd, data.size)
        _readBufferEnd += data.size

        val output = ByteArrayOutputStream()

        // Try to finish parsing the variable header if waiting
        pendingVarHeaderLen?.let { varLen ->
            val parsed = parseVariableHeader(varLen) ?: return byteArrayOf()
            output.write(parsed)
        }

        if (!responseHeaderParsed) {
            val parsed = parseResponseHeader() ?: return byteArrayOf()
            output.write(parsed)
        }

        if (responseHeaderParsed) {
            output.write(decryptChunks())
        }

        // Compact buffer when dead space exceeds threshold (matching iOS)
        if (readBufferOffset > COMPACT_THRESHOLD) {
            val remaining = readBufferAvailable()
            if (remaining > 0) {
                System.arraycopy(readBuffer, readBufferOffset, readBuffer, 0, remaining)
            }
            readBufferOffset = 0
            _readBufferEnd = remaining
        } else if (readBufferOffset > 0 && readBufferAvailable() == 0) {
            readBufferOffset = 0
            _readBufferEnd = 0
        }

        return output.toByteArray()
    }

    private fun parseResponseHeader(): ByteArray? {
        val keySize = cipher.keySize

        // Need: salt(keySize) + sealed fixed header(1+8+keySize+2 + tagSize)
        val fixedHeaderPlainLen = 1 + 8 + keySize + 2
        val minNeeded = keySize + fixedHeaderPlainLen + TAG_SIZE
        if (readBufferAvailable() < minNeeded) return null

        val salt = readBuffer.copyOfRange(readBufferOffset, readBufferOffset + keySize)

        // Derive read session key
        val sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk, salt, keySize)
        readSubkey = sessionKey

        // Read and decrypt fixed header chunk
        val fixedChunkLen = fixedHeaderPlainLen + TAG_SIZE
        val fixedChunk = readBuffer.copyOfRange(readBufferOffset + keySize, readBufferOffset + keySize + fixedChunkLen)
        readBufferOffset += keySize + fixedChunkLen

        val fixedHeader = ShadowsocksAEADCrypto.open(cipher, sessionKey, readNonce.next(), fixedChunk)
        require(fixedHeader.size == fixedHeaderPlainLen)

        var offset = 0
        val headerType = fixedHeader[offset]
        offset++
        if (headerType != HEADER_TYPE_SERVER) throw ShadowsocksError.BadHeaderType()

        // Validate timestamp
        val epoch = fixedHeader.readLongBE(offset)
        offset += 8
        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - epoch) > MAX_TIMESTAMP_DIFF) throw ShadowsocksError.BadTimestamp()

        // Validate request salt
        val responseSalt = fixedHeader.copyOfRange(offset, offset + keySize)
        offset += keySize
        requestSalt?.let {
            if (!responseSalt.contentEquals(it)) throw ShadowsocksError.BadRequestSalt()
        }

        // Read variable length
        val varLen = ((fixedHeader[offset].toInt() and 0xFF) shl 8) or (fixedHeader[offset + 1].toInt() and 0xFF)

        return parseVariableHeader(varLen) ?: byteArrayOf()
    }

    private fun parseVariableHeader(varLen: Int): ByteArray? {
        val varChunkLen = varLen + TAG_SIZE
        if (readBufferAvailable() < varChunkLen) {
            pendingVarHeaderLen = varLen
            return null
        }

        val varChunk = readBuffer.copyOfRange(readBufferOffset, readBufferOffset + varChunkLen)
        readBufferOffset += varChunkLen

        val subkey = readSubkey ?: throw ShadowsocksError.DecryptionFailed()
        val varData = ShadowsocksAEADCrypto.open(cipher, subkey, readNonce.next(), varChunk)

        pendingVarHeaderLen = null
        responseHeaderParsed = true
        return varData
    }

    private fun decryptChunks(): ByteArray {
        val subkey = readSubkey ?: return byteArrayOf()
        val output = ByteArrayOutputStream()

        while (true) {
            val remaining = readBufferAvailable()
            val payloadLen: Int

            val pending = pendingPayloadLength
            if (pending != null) {
                payloadLen = pending
            } else {
                val lenNeeded = 2 + TAG_SIZE
                if (remaining < lenNeeded) break

                val encLen = readBuffer.copyOfRange(readBufferOffset, readBufferOffset + lenNeeded)
                val lenData = ShadowsocksAEADCrypto.open(cipher, subkey, readNonce.next(), encLen)
                require(lenData.size == 2)
                readBufferOffset += lenNeeded

                payloadLen = ((lenData[0].toInt() and 0xFF) shl 8) or (lenData[1].toInt() and 0xFF)
            }

            val payloadNeeded = payloadLen + TAG_SIZE
            if (readBufferAvailable() < payloadNeeded) {
                pendingPayloadLength = payloadLen
                break
            }

            pendingPayloadLength = null

            val encPayload = readBuffer.copyOfRange(readBufferOffset, readBufferOffset + payloadNeeded)
            readBufferOffset += payloadNeeded

            output.write(ShadowsocksAEADCrypto.open(cipher, subkey, readNonce.next(), encPayload))
        }

        return output.toByteArray()
    }
}

// =============================================================================
// Shadowsocks2022AESUDPConnection
// =============================================================================

/**
 * Wraps a transport with Shadowsocks 2022 per-packet UDP encryption (AES variant).
 *
 * Packet format (outgoing):
 *   AES-ECB(sessionID(8) + packetID(8)) + AEAD(type + timestamp + paddingLen + padding + address + payload)
 *   AEAD nonce = packetHeader[4:16]
 */
class Shadowsocks2022AESUDPConnection(
    private val transport: Transport,
    private val cipher: ShadowsocksCipher,
    private val pskList: List<ByteArray>,
    private val dstHost: String,
    private val dstPort: Int
) : VlessConnection() {

    private val random = SecureRandom()
    private val psk = pskList.last()
    private val pskHashes: List<ByteArray> = (1 until pskList.size).map {
        ShadowsocksKeyDerivation.blake3Hash16(pskList[it])
    }
    private val headerEncryptPSK = pskList.first()

    // Session state
    private val sessionID: Long
    private var packetID: Long = 0
    private val sessionCipher: ByteArray

    // Remote session tracking
    private var remoteSessionID: Long = 0
    private var remoteSessionCipher: ByteArray? = null

    init {
        responseHeaderReceived = true
        sessionID = random.nextLong()
        val sidBytes = sessionID.toBigEndianBytes()
        sessionCipher = ShadowsocksKeyDerivation.deriveSessionKey(psk, sidBytes, cipher.keySize)
    }

    override val isConnected: Boolean get() = true

    override suspend fun sendRaw(data: ByteArray) {
        transport.send(encryptPacket(data))
    }

    override fun sendRawAsync(data: ByteArray) {
        try {
            transport.sendAsync(encryptPacket(data))
        } catch (e: Exception) {
            Log.e(TAG, "UDP send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = transport.receive() ?: return null
        if (data.isEmpty()) return null
        return decryptPacket(data)
    }

    override fun cancel() {
        transport.forceCancel()
    }

    private fun encryptPacket(payload: ByteArray): ByteArray {
        packetID++
        // Build packet header: sessionID(8) + packetID(8) = 16 bytes
        val header = sessionID.toBigEndianBytes() + packetID.toBigEndianBytes()

        // Build identity headers for multi-user mode
        val identityData = ByteArrayOutputStream()
        if (pskHashes.isNotEmpty()) {
            for (i in pskHashes.indices) {
                val pskHash = pskHashes[i]
                val xored = ByteArray(16) { j -> (pskHash[j].toInt() xor header[j].toInt()).toByte() }
                identityData.write(AesEcb.encrypt(pskList[i], xored))
            }
        }

        // Build body: type(1) + timestamp(8) + paddingLen(2) + padding + address + payload
        val addressHeader = ShadowsocksProtocol.buildAddressHeader(dstHost, dstPort)
        val paddingLen = if (dstPort == 53 && payload.size < MAX_PADDING_LENGTH)
            random.nextInt(MAX_PADDING_LENGTH - payload.size) + 1 else 0

        val body = ByteArrayOutputStream()
        body.write(HEADER_TYPE_CLIENT.toInt())
        body.write((System.currentTimeMillis() / 1000).toBigEndianBytes())
        body.write(paddingLen.toUShortBigEndian())
        if (paddingLen > 0) body.write(ByteArray(paddingLen))
        body.write(addressHeader)
        body.write(payload)

        // AEAD seal body: nonce = header[4:16]
        val nonce = header.copyOfRange(4, 16)
        val sealedBody = ShadowsocksAEADCrypto.seal(cipher, sessionCipher, nonce, body.toByteArray())

        // AES-ECB encrypt the 16-byte header
        val encryptedHeader = AesEcb.encrypt(headerEncryptPSK, header)

        return encryptedHeader + identityData.toByteArray() + sealedBody
    }

    private fun decryptPacket(data: ByteArray): ByteArray {
        require(data.size >= 16 + TAG_SIZE)

        // AES-ECB decrypt header using last PSK
        val header = AesEcb.decrypt(psk, data.copyOf(16))

        val remoteSession = header.readLongBE(0)

        // Get or derive remote session cipher
        val remoteCipherKey: ByteArray
        val cachedCipher = remoteSessionCipher
        if (remoteSession == remoteSessionID && cachedCipher != null) {
            remoteCipherKey = cachedCipher
        } else {
            val rsData = remoteSession.toBigEndianBytes()
            remoteCipherKey = ShadowsocksKeyDerivation.deriveSessionKey(psk, rsData, cipher.keySize)
            remoteSessionID = remoteSession
            remoteSessionCipher = remoteCipherKey
        }

        // AEAD open body: nonce = header[4:16]
        val nonce = header.copyOfRange(4, 16)
        val sealedBody = data.copyOfRange(16, data.size)
        val body = ShadowsocksAEADCrypto.open(cipher, remoteCipherKey, nonce, sealedBody)

        // Parse body: type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + address + payload
        require(body.size >= 1 + 8 + 8 + 2)

        var offset = 0
        val headerType = body[offset]; offset++
        if (headerType != HEADER_TYPE_SERVER) throw ShadowsocksError.BadHeaderType()

        val epoch = body.readLongBE(offset); offset += 8
        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - epoch) > MAX_TIMESTAMP_DIFF) throw ShadowsocksError.BadTimestamp()

        val clientSid = body.readLongBE(offset); offset += 8
        if (clientSid != sessionID) throw ShadowsocksError.DecryptionFailed()

        // Padding
        require(body.size - offset >= 2)
        val paddingLen = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
        offset += 2 + paddingLen

        // Skip address header
        val parsed = ShadowsocksProtocol.decodeUDPPacket(body.copyOfRange(offset, body.size))
            ?: throw ShadowsocksError.InvalidAddress()
        return parsed.payload
    }
}

// =============================================================================
// Shadowsocks2022ChaChaUDPConnection
// =============================================================================

/**
 * Wraps a transport with Shadowsocks 2022 per-packet UDP encryption (ChaCha20 variant).
 *
 * Uses XChaCha20-Poly1305 with 24-byte nonce.
 * Packet format: nonce(24) + XChaCha20-Poly1305(sessionID + packetID + type + timestamp + padding + address + payload)
 */
class Shadowsocks2022ChaChaUDPConnection(
    private val transport: Transport,
    private val psk: ByteArray,
    private val dstHost: String,
    private val dstPort: Int
) : VlessConnection() {

    private val random = SecureRandom()
    private val sessionID: Long = random.nextLong()
    private var packetID: Long = 0

    init {
        responseHeaderReceived = true
    }

    override val isConnected: Boolean get() = true

    override suspend fun sendRaw(data: ByteArray) {
        transport.send(encryptPacket(data))
    }

    override fun sendRawAsync(data: ByteArray) {
        try {
            transport.sendAsync(encryptPacket(data))
        } catch (e: Exception) {
            Log.e(TAG, "ChaCha UDP send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = transport.receive() ?: return null
        if (data.isEmpty()) return null
        return decryptPacket(data)
    }

    override fun cancel() {
        transport.forceCancel()
    }

    private fun encryptPacket(payload: ByteArray): ByteArray {
        // Generate 24-byte nonce
        val nonce = ByteArray(24)
        random.nextBytes(nonce)

        val addressHeader = ShadowsocksProtocol.buildAddressHeader(dstHost, dstPort)
        val paddingLen = if (dstPort == 53 && payload.size < MAX_PADDING_LENGTH)
            random.nextInt(MAX_PADDING_LENGTH - payload.size) + 1 else 0

        packetID++
        val body = ByteArrayOutputStream()
        body.write(sessionID.toBigEndianBytes())
        body.write(packetID.toBigEndianBytes())
        body.write(HEADER_TYPE_CLIENT.toInt())
        body.write((System.currentTimeMillis() / 1000).toBigEndianBytes())
        body.write(paddingLen.toUShortBigEndian())
        if (paddingLen > 0) body.write(ByteArray(paddingLen))
        body.write(addressHeader)
        body.write(payload)

        val sealed = XChaCha20Poly1305.seal(psk, nonce, body.toByteArray())
        return nonce + sealed
    }

    private fun decryptPacket(data: ByteArray): ByteArray {
        require(data.size >= 24 + TAG_SIZE)

        val nonce = data.copyOf(24)
        val ciphertext = data.copyOfRange(24, data.size)
        val body = XChaCha20Poly1305.open(psk, nonce, ciphertext)

        // Parse: sessionID(8) + packetID(8) + type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + address + payload
        require(body.size >= 8 + 8 + 1 + 8 + 8 + 2)

        var offset = 16 // skip sessionID + packetID

        val headerType = body[offset]; offset++
        if (headerType != HEADER_TYPE_SERVER) throw ShadowsocksError.BadHeaderType()

        val epoch = body.readLongBE(offset); offset += 8
        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - epoch) > MAX_TIMESTAMP_DIFF) throw ShadowsocksError.BadTimestamp()

        val clientSid = body.readLongBE(offset); offset += 8
        if (clientSid != sessionID) throw ShadowsocksError.DecryptionFailed()

        // Padding
        require(body.size - offset >= 2)
        val paddingLen = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
        offset += 2 + paddingLen

        val parsed = ShadowsocksProtocol.decodeUDPPacket(body.copyOfRange(offset, body.size))
            ?: throw ShadowsocksError.InvalidAddress()
        return parsed.payload
    }
}

// =============================================================================
// XChaCha20-Poly1305
// =============================================================================

/**
 * XChaCha20-Poly1305 implementation using HChaCha20 + ChaCha20-Poly1305.
 */
object XChaCha20Poly1305 {

    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(nonce.size == 24 && key.size == 32)

        // HChaCha20: derive subkey from key + nonce[0:16]
        val subkey = hChaCha20(key, nonce.copyOf(16))

        // Standard ChaCha20-Poly1305 with subkey and nonce = [0,0,0,0] + nonce[16:24]
        val chachaNonce = ByteArray(4) + nonce.copyOfRange(16, 24)

        return ShadowsocksAEADCrypto.seal(ShadowsocksCipher.CHACHA20_POLY1305, subkey, chachaNonce, plaintext)
    }

    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        require(nonce.size == 24 && key.size == 32)
        require(ciphertext.size >= 16)

        val subkey = hChaCha20(key, nonce.copyOf(16))
        val chachaNonce = ByteArray(4) + nonce.copyOfRange(16, 24)

        return ShadowsocksAEADCrypto.open(ShadowsocksCipher.CHACHA20_POLY1305, subkey, chachaNonce, ciphertext)
    }

    /**
     * HChaCha20: derives a 256-bit subkey from a 256-bit key and 128-bit nonce.
     */
    private fun hChaCha20(key: ByteArray, nonce: ByteArray): ByteArray {
        val state = IntArray(16)

        // Constants: "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574

        // Key (little-endian)
        for (i in 0 until 8) {
            state[4 + i] = key.readIntLE(i * 4)
        }

        // Nonce (little-endian)
        for (i in 0 until 4) {
            state[12 + i] = nonce.readIntLE(i * 4)
        }

        // 20 rounds (10 double rounds)
        repeat(10) {
            // Column rounds
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)
            // Diagonal rounds
            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        // Output: words 0..3 and 12..15 (8 words = 32 bytes)
        val output = ByteArray(32)
        for (i in 0 until 4) {
            output.writeIntLE(i * 4, state[i])
        }
        for (i in 0 until 4) {
            output.writeIntLE(16 + i * 4, state[12 + i])
        }
        return output
    }

    private fun quarterRound(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] = s[a] + s[b]; s[d] = (s[d] xor s[a]).rotateLeft(16)
        s[c] = s[c] + s[d]; s[b] = (s[b] xor s[c]).rotateLeft(12)
        s[a] = s[a] + s[b]; s[d] = (s[d] xor s[a]).rotateLeft(8)
        s[c] = s[c] + s[d]; s[b] = (s[b] xor s[c]).rotateLeft(7)
    }

    private fun Int.rotateLeft(count: Int): Int =
        (this shl count) or (this ushr (32 - count))
}

// =============================================================================
// Byte manipulation extensions
// =============================================================================

internal fun Long.toBigEndianBytes(): ByteArray {
    val v = this
    return byteArrayOf(
        (v shr 56).toByte(), (v shr 48).toByte(), (v shr 40).toByte(), (v shr 32).toByte(),
        (v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte()
    )
}

internal fun Int.toUShortBigEndian(): ByteArray =
    byteArrayOf((this shr 8).toByte(), (this and 0xFF).toByte())

internal fun ByteArray.readLongBE(offset: Int): Long {
    var value = 0L
    for (i in 0 until 8) {
        value = (value shl 8) or (this[offset + i].toLong() and 0xFF)
    }
    return value
}

internal fun ByteArray.readIntLE(offset: Int): Int =
    (this[offset].toInt() and 0xFF) or
            ((this[offset + 1].toInt() and 0xFF) shl 8) or
            ((this[offset + 2].toInt() and 0xFF) shl 16) or
            ((this[offset + 3].toInt() and 0xFF) shl 24)

internal fun ByteArray.writeIntLE(offset: Int, value: Int) {
    this[offset] = value.toByte()
    this[offset + 1] = (value shr 8).toByte()
    this[offset + 2] = (value shr 16).toByte()
    this[offset + 3] = (value shr 24).toByte()
}
