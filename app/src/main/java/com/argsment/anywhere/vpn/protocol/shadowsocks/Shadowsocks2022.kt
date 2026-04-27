package com.argsment.anywhere.vpn.protocol.shadowsocks

import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.util.AnywhereLogger
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

private val logger = AnywhereLogger("SS2022")

private const val HEADER_TYPE_CLIENT: Byte = 0
private const val HEADER_TYPE_SERVER: Byte = 1
private const val MAX_PADDING_LENGTH = 900
private const val MAX_TIMESTAMP_DIFF = 30L
private const val TAG_SIZE = 16

/**
 * Shadowsocks 2022 TCP connection wrapping a transport with AEAD encryption.
 *
 * Request: `salt + [identity headers] + seal(fixedHeader) + seal(variableHeader+payload) [+ AEAD chunks]`
 * Response: `salt + seal(fixedHeader) + seal(data) [+ AEAD chunks]`
 */
class Shadowsocks2022Connection(
    private val transport: Transport,
    private val cipher: ShadowsocksCipher,
    private val pskList: List<ByteArray>,
    private var addressHeader: ByteArray?
) : ProxyConnection() {

    private val random = SecureRandom()
    private val psk = pskList.last()
    private val pskHashes: List<ByteArray> = (1 until pskList.size).map {
        ShadowsocksKeyDerivation.blake3Hash16(pskList[it])
    }

    private var requestSalt: ByteArray? = null
    private var writeNonce = ShadowsocksNonce(cipher.nonceSize)
    private var writeSubkey: ByteArray? = null
    private var handshakeSent = false

    private var readNonce = ShadowsocksNonce(cipher.nonceSize)
    private var readSubkey: ByteArray? = null
    private var readBuffer = byteArrayOf()
    private var readBufferOffset = 0
    private var responseHeaderParsed = false
    private var pendingVarHeaderLen: Int? = null
    private var pendingPayloadLength: Int? = null

    /** Defer compaction until dead space is significant to avoid O(n) shifts on each read. */
    private companion object {
        const val COMPACT_THRESHOLD = 4096
    }

    private val sendLock = Any()

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
            logger.error("[SS2022] Send error: ${e.message}")
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

    private fun buildRequest(payload: ByteArray, addressHeader: ByteArray): ByteArray {
        val keySize = cipher.keySize

        val salt = ShadowsocksAEADCrypto.generateRandomSalt(keySize)
        requestSalt = salt

        val sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk, salt, keySize)
        writeSubkey = sessionKey

        val output = ByteArrayOutputStream()
        output.write(salt)

        if (pskList.size >= 2) {
            writeIdentityHeaders(output, salt)
        }

        // Fixed header (11 bytes): type(1) + timestamp(8) + variableHeaderLen(2).
        val paddingLen = if (payload.size < MAX_PADDING_LENGTH) random.nextInt(MAX_PADDING_LENGTH) + 1 else 0
        val variableHeaderLen = addressHeader.size + 2 + paddingLen + payload.size

        val fixedHeader = ByteArrayOutputStream(11)
        fixedHeader.write(HEADER_TYPE_CLIENT.toInt())
        val timestamp = System.currentTimeMillis() / 1000
        fixedHeader.write(timestamp.toBigEndianBytes())
        fixedHeader.write(variableHeaderLen.toUShortBigEndian())

        val sealedFixed = ShadowsocksAEADCrypto.seal(cipher, sessionKey, writeNonce.next(), fixedHeader.toByteArray())
        output.write(sealedFixed)

        // Variable header: address + paddingLen(2) + padding + payload.
        val variableHeader = ByteArrayOutputStream(variableHeaderLen)
        variableHeader.write(addressHeader)
        variableHeader.write(paddingLen.toUShortBigEndian())
        if (paddingLen > 0) {
            variableHeader.write(ByteArray(paddingLen))
        }
        variableHeader.write(payload)

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

    /** Standard AEAD chunks for sends after the handshake. */
    private fun sealChunks(plaintext: ByteArray): ByteArray {
        val subkey = writeSubkey ?: throw ShadowsocksError.DecryptionFailed()
        val maxPayload = ShadowsocksAEADWriter.MAX_PAYLOAD_SIZE
        val output = ByteArrayOutputStream()
        var offset = 0

        while (offset < plaintext.size) {
            val remaining = plaintext.size - offset
            val chunkSize = minOf(remaining, maxPayload)
            val chunk = plaintext.copyOfRange(offset, offset + chunkSize)

            val lengthBytes = byteArrayOf((chunkSize shr 8).toByte(), (chunkSize and 0xFF).toByte())
            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, writeNonce.next(), lengthBytes))

            output.write(ShadowsocksAEADCrypto.seal(cipher, subkey, writeNonce.next(), chunk))

            offset += chunkSize
        }

        return output.toByteArray()
    }

    private var _readBufferEnd = 0
    private fun readBufferAvailable(): Int = _readBufferEnd - readBufferOffset

    private fun processReceived(data: ByteArray): ByteArray {
        val activeLen = readBufferAvailable()
        val needed = activeLen + data.size
        if (readBufferOffset + activeLen + data.size > readBuffer.size) {
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

        // salt(keySize) + sealed fixed header(1+8+keySize+2 + tagSize)
        val fixedHeaderPlainLen = 1 + 8 + keySize + 2
        val minNeeded = keySize + fixedHeaderPlainLen + TAG_SIZE
        if (readBufferAvailable() < minNeeded) return null

        val salt = readBuffer.copyOfRange(readBufferOffset, readBufferOffset + keySize)

        val sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk, salt, keySize)
        readSubkey = sessionKey

        val fixedChunkLen = fixedHeaderPlainLen + TAG_SIZE
        val fixedChunk = readBuffer.copyOfRange(readBufferOffset + keySize, readBufferOffset + keySize + fixedChunkLen)
        readBufferOffset += keySize + fixedChunkLen

        val fixedHeader = ShadowsocksAEADCrypto.open(cipher, sessionKey, readNonce.next(), fixedChunk)
        require(fixedHeader.size == fixedHeaderPlainLen)

        var offset = 0
        val headerType = fixedHeader[offset]
        offset++
        if (headerType != HEADER_TYPE_SERVER) throw ShadowsocksError.BadHeaderType()

        val epoch = fixedHeader.readLongBE(offset)
        offset += 8
        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - epoch) > MAX_TIMESTAMP_DIFF) throw ShadowsocksError.BadTimestamp()

        val responseSalt = fixedHeader.copyOfRange(offset, offset + keySize)
        offset += keySize
        requestSalt?.let {
            if (!responseSalt.contentEquals(it)) throw ShadowsocksError.BadRequestSalt()
        }

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

/** XChaCha20-Poly1305 implemented as HChaCha20 + ChaCha20-Poly1305. */
object XChaCha20Poly1305 {

    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(nonce.size == 24 && key.size == 32)

        val subkey = hChaCha20(key, nonce.copyOf(16))

        // ChaCha20-Poly1305 nonce = [0,0,0,0] + nonce[16:24]
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

    /** Derives a 256-bit subkey from a 256-bit key and 128-bit nonce. */
    private fun hChaCha20(key: ByteArray, nonce: ByteArray): ByteArray {
        val state = IntArray(16)

        // "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574

        for (i in 0 until 8) {
            state[4 + i] = key.readIntLE(i * 4)
        }

        for (i in 0 until 4) {
            state[12 + i] = nonce.readIntLE(i * 4)
        }

        // 20 rounds = 10 double rounds (column + diagonal).
        repeat(10) {
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)
            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        // Output is words 0..3 and 12..15 (8 words = 32 bytes).
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
