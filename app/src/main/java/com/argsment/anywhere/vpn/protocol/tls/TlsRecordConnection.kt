package com.argsment.anywhere.vpn.protocol.tls

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.vless.RealityError
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock as withMutexLock
import java.security.MessageDigest
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

private val logger = AnywhereLogger("TLS")

/**
 * TLS record encryption/decryption wrapper supporting TLS 1.2 and 1.3.
 *
 * Encrypts outgoing data into TLS Application Data records and decrypts incoming
 * records. Sequence numbers are tracked independently per direction.
 *
 * TLS 1.3: AEAD-only with inner content type and XOR nonce.
 * TLS 1.2: AEAD with explicit nonce, or CBC with HMAC and per-record IV.
 *
 * [receiveRaw] / [sendRaw] expose a "direct" mode that bypasses encryption for
 * Vision direct-copy transitions.
 */
class TlsRecordConnection private constructor(
    private val clientKey: ByteArray,
    private val clientIV: ByteArray,
    private val serverKey: ByteArray,
    private val serverIV: ByteArray,
    private val cipherSuite: Int,
    private val tlsVersion: Int,
    private val clientMACKey: ByteArray,
    private val serverMACKey: ByteArray,
    initialClientSeqNum: Long,
    initialServerSeqNum: Long
) {
    /** TLS 1.3 constructor. */
    constructor(
        clientKey: ByteArray,
        clientIV: ByteArray,
        serverKey: ByteArray,
        serverIV: ByteArray,
        cipherSuite: Int = TlsCipherSuite.TLS_AES_128_GCM_SHA256
    ) : this(clientKey, clientIV, serverKey, serverIV, cipherSuite,
        0x0304, ByteArray(0), ByteArray(0), 0, 0)

    /** TLS 1.2 constructor with MAC keys and protocol version. */
    constructor(
        tls12ClientKey: ByteArray,
        clientIV: ByteArray,
        serverKey: ByteArray,
        serverIV: ByteArray,
        clientMACKey: ByteArray,
        serverMACKey: ByteArray,
        cipherSuite: Int,
        protocolVersion: Int = 0x0303,
        initialClientSeqNum: Long = 0,
        initialServerSeqNum: Long = 0
    ) : this(tls12ClientKey, clientIV, serverKey, serverIV, cipherSuite,
        protocolVersion, clientMACKey, serverMACKey, initialClientSeqNum, initialServerSeqNum)

    var connection: Transport? = null

    val isTls13: Boolean get() = tlsVersion >= 0x0304

    private val isChaCha = TlsCipherSuite.isChaCha20(cipherSuite)
    private val isAEAD = TlsCipherSuite.isAEAD(cipherSuite)
    private val cipherAlgo = if (isChaCha) "ChaCha20" else "AES"
    private val cipherTransform = if (isChaCha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
    private val clientKeySpec = SecretKeySpec(clientKey, cipherAlgo)
    private val serverKeySpec = SecretKeySpec(serverKey, cipherAlgo)

    // Cipher is not thread-safe, so separate instances for encrypt/decrypt.
    private val encryptCipher: Cipher = Cipher.getInstance(cipherTransform)
    private val decryptCipher: Cipher = Cipher.getInstance(cipherTransform)

    private val cbcEncryptCipher: Cipher by lazy { Cipher.getInstance("AES/CBC/NoPadding") }
    private val cbcDecryptCipher: Cipher by lazy { Cipher.getInstance("AES/CBC/NoPadding") }
    private val cbcClientKeySpec: SecretKeySpec by lazy { SecretKeySpec(clientKey, "AES") }
    private val cbcServerKeySpec: SecretKeySpec by lazy { SecretKeySpec(serverKey, "AES") }

    private var clientSeqNum: Long = initialClientSeqNum
    private var serverSeqNum: Long = initialServerSeqNum
    private val seqLock = ReentrantLock()

    /** Serialises the encrypt-then-enqueue path so TLS records arrive at the
     *  socket in sequence-number order. Without this, two concurrent `send`
     *  calls can allocate consecutive sequence numbers but enqueue the encrypted
     *  records in reverse order, causing TLS decryption failures on the server
     *  and a "Broken pipe" on the next write. */
    private val sendLock = Mutex()

    /** TLS 1.3 maximum plaintext per record (RFC 8446 S5.1). */
    companion object {
        private const val MAX_RECORD_PLAINTEXT = 16384
    }

    private var receiveBuffer = ByteArray(0)
    private var receiveBufferLen = 0
    private val receiveLock = ReentrantLock()

    suspend fun send(data: ByteArray) {
        sendLock.withMutexLock {
            val conn = connection ?: throw RealityError.HandshakeFailed("Connection cancelled")
            val record = buildTLSRecords(data)
            conn.send(record)
        }
    }

    fun sendAsync(data: ByteArray) {
        runBlocking {
            sendLock.withMutexLock {
                val conn = connection ?: return@withMutexLock
                try {
                    val record = buildTLSRecords(data)
                    conn.sendAsync(record)
                } catch (e: Exception) {
                    logger.error("Encryption error: ${e.message}")
                }
            }
        }
    }

    /**
     * @return Decrypted data, or null on connection close.
     * @throws RealityError.DecryptionFailed with raw data on decryption failure
     *   so the caller (Vision) can switch to direct-copy mode.
     */
    suspend fun receive(): ByteArray? {
        val processed = receiveLock.withLock {
            processBuffer()
        }
        if (processed != null) {
            return handleBufferResult(processed)
        }
        return fetchMore()
    }

    /**
     * Receives raw data without decryption (for Vision direct-copy mode).
     * Returns any buffered data first, then reads directly from the socket.
     */
    suspend fun receiveRaw(): ByteArray? {
        receiveLock.withLock {
            if (receiveBufferLen > 0) {
                val data = receiveBuffer.copyOfRange(0, receiveBufferLen)
                receiveBufferLen = 0
                receiveBuffer = ByteArray(0)
                return data
            }
        }

        val conn = connection ?: throw RealityError.HandshakeFailed("Connection cancelled")
        while (true) {
            val data = conn.receive() ?: return null
            if (data.isNotEmpty()) return data
        }
    }

    /** Sends raw data without encryption (for Vision direct-copy mode). */
    suspend fun sendRaw(data: ByteArray) {
        val conn = connection ?: throw RealityError.HandshakeFailed("Connection cancelled")
        conn.send(data)
    }

    fun sendRawAsync(data: ByteArray) {
        val conn = connection ?: return
        conn.sendAsync(data)
    }

    /** Closes the connection. Sends a best-effort TLS close_notify alert before closing. */
    fun cancel() {
        sendCloseNotify()

        receiveLock.withLock {
            receiveBufferLen = 0
            receiveBuffer = ByteArray(0)
        }

        connection?.forceCancel()
        connection = null
    }

    private fun sendCloseNotify() {
        runBlocking {
            sendLock.withMutexLock {
                val conn = connection ?: return@withMutexLock

                val seqNum: Long
                seqLock.withLock {
                    seqNum = clientSeqNum
                    clientSeqNum++
                }

                try {
                    // Alert: level=warning(1), desc=close_notify(0)
                    val alertData = byteArrayOf(0x01, 0x00)
                    val record = if (isTls13) {
                        val innerPlaintext = byteArrayOf(0x01, 0x00, 0x15)
                        val encryptedLen = innerPlaintext.size + 16
                        val nonce = com.argsment.anywhere.vpn.util.PacketUtil.xorNonce(clientIV, seqNum)
                        val aad = byteArrayOf(
                            0x17, 0x03, 0x03,
                            ((encryptedLen shr 8) and 0xFF).toByte(),
                            (encryptedLen and 0xFF).toByte()
                        )
                        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
                        encryptCipher.init(Cipher.ENCRYPT_MODE, clientKeySpec, paramSpec)
                        encryptCipher.updateAAD(aad)
                        val encrypted = encryptCipher.doFinal(innerPlaintext)
                        val r = ByteArray(5 + encrypted.size)
                        r[0] = 0x17; r[1] = 0x03; r[2] = 0x03
                        r[3] = ((encrypted.size shr 8) and 0xFF).toByte()
                        r[4] = (encrypted.size and 0xFF).toByte()
                        System.arraycopy(encrypted, 0, r, 5, encrypted.size)
                        r
                    } else {
                        encryptTls12Record(alertData, 0x15, seqNum)
                    }
                    conn.sendAsync(record)
                } catch (_: Exception) {
                }
            }
        }
    }

    private sealed class BufferResult {
        class Data(val data: ByteArray) : BufferResult()
        class Error(val error: Exception) : BufferResult()
        object NeedMore : BufferResult()
        object Skip : BufferResult()
        class DecryptionFailed(val rawData: ByteArray) : BufferResult()
    }

    /** Must NOT be called under receiveLock. */
    private suspend fun handleBufferResult(result: BufferResult): ByteArray? {
        return when (result) {
            is BufferResult.Data -> result.data
            is BufferResult.Error -> throw result.error
            is BufferResult.NeedMore -> fetchMore()
            is BufferResult.Skip -> receive()
            is BufferResult.DecryptionFailed ->
                throw RealityError.DecryptionFailed(result.rawData)
        }
    }

    private suspend fun fetchMore(): ByteArray? {
        val conn = connection ?: throw RealityError.HandshakeFailed("Connection cancelled")

        while (true) {
            val data = conn.receive() ?: return null
            if (data.isEmpty()) continue

            val result: BufferResult?
            receiveLock.withLock {
                appendToBuffer(data)
                result = processBuffer()
            }

            if (result != null) {
                return handleBufferResult(result)
            }
        }
    }

    /** Prepends data to the receive buffer (e.g., leftover post-handshake NewSessionTicket data). */
    fun prependToReceiveBuffer(data: ByteArray) {
        if (data.isEmpty()) return
        receiveLock.withLock {
            if (receiveBufferLen == 0) {
                appendToBuffer(data)
            } else {
                val newSize = receiveBufferLen + data.size
                val newBuf = ByteArray(maxOf(receiveBuffer.size, newSize))
                System.arraycopy(data, 0, newBuf, 0, data.size)
                System.arraycopy(receiveBuffer, 0, newBuf, data.size, receiveBufferLen)
                receiveBuffer = newBuf
                receiveBufferLen = newSize
            }
        }
    }

    /** Must be called under receiveLock. */
    private fun appendToBuffer(data: ByteArray) {
        if (receiveBufferLen + data.size > receiveBuffer.size) {
            val newSize = maxOf(receiveBuffer.size * 2, receiveBufferLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(receiveBuffer, 0, newBuf, 0, receiveBufferLen)
            receiveBuffer = newBuf
        }
        System.arraycopy(data, 0, receiveBuffer, receiveBufferLen, data.size)
        receiveBufferLen += data.size
    }

    /**
     * Processes all complete TLS records in the receive buffer, returning batched
     * decrypted data. Must be called while holding receiveLock.
     */
    private fun processBuffer(): BufferResult? {
        if (receiveBufferLen == 0) return null

        var batchedData: ByteArray? = null
        var batchedLen = 0
        var hasError: Exception? = null
        var recordsProcessed = 0
        var failedRecordData: ByteArray? = null
        var offset = 0

        while (offset + 5 <= receiveBufferLen) {
            val contentType = receiveBuffer[offset].toInt() and 0xFF
            val recordLen = ((receiveBuffer[offset + 3].toInt() and 0xFF) shl 8) or
                    (receiveBuffer[offset + 4].toInt() and 0xFF)

            val totalLen = 5 + recordLen
            if (offset + totalLen > receiveBufferLen) break

            recordsProcessed++

            if (contentType == 0x17) { // Application Data
                val seqNum: Long
                seqLock.withLock {
                    seqNum = serverSeqNum
                    serverSeqNum++
                }

                try {
                    val header = receiveBuffer.copyOfRange(offset, offset + 5)
                    val body = receiveBuffer.copyOfRange(offset + 5, offset + totalLen)
                    val decrypted = decryptTLSRecord(body, header, seqNum)
                    if (decrypted.isNotEmpty()) {
                        if (batchedData == null) {
                            batchedData = ByteArray(maxOf(decrypted.size, totalLen))
                        }
                        if (batchedLen + decrypted.size > batchedData.size) {
                            val newBatched = ByteArray(maxOf(batchedData.size * 2, batchedLen + decrypted.size))
                            System.arraycopy(batchedData, 0, newBatched, 0, batchedLen)
                            batchedData = newBatched
                        }
                        System.arraycopy(decrypted, 0, batchedData, batchedLen, decrypted.size)
                        batchedLen += decrypted.size
                    }
                } catch (e: Exception) {
                    // Collect the failed record + all remaining unprocessed data.
                    failedRecordData = receiveBuffer.copyOfRange(offset, receiveBufferLen)
                    hasError = e
                    offset = receiveBufferLen
                    break
                }
            } else if (contentType == 0x15) { // Alert
                hasError = RealityError.HandshakeFailed("TLS Alert received")
                offset += totalLen
                break
            }
            offset += totalLen
        }

        val remaining = receiveBufferLen - offset
        if (remaining > 0 && offset > 0) {
            System.arraycopy(receiveBuffer, offset, receiveBuffer, 0, remaining)
        }
        receiveBufferLen = remaining
        if (receiveBufferLen == 0) {
            receiveBuffer = ByteArray(0)
        }

        if (hasError != null) {
            if (batchedData != null && batchedLen > 0) {
                if (failedRecordData != null) {
                    receiveBuffer = failedRecordData
                    receiveBufferLen = failedRecordData.size
                }
                return BufferResult.Data(batchedData.copyOfRange(0, batchedLen))
            }
            if (failedRecordData != null) {
                return BufferResult.DecryptionFailed(failedRecordData)
            }
            return BufferResult.Error(hasError)
        }

        if (batchedData != null && batchedLen > 0) {
            return BufferResult.Data(batchedData.copyOfRange(0, batchedLen))
        }

        if (recordsProcessed > 0) {
            return BufferResult.Skip
        }

        return null
    }

    /**
     * Splits at the TLS 1.3 maximum (16384 bytes) to prevent record_overflow.
     * Sequence numbers are reserved atomically so concurrent sends stay ordered.
     */
    private fun buildTLSRecords(data: ByteArray): ByteArray {
        if (data.size <= MAX_RECORD_PLAINTEXT) {
            val seqNum: Long
            seqLock.withLock {
                seqNum = clientSeqNum
                clientSeqNum++
            }
            return encryptAndBuildTLSRecord(data, seqNum)
        }

        val chunkCount = (data.size + MAX_RECORD_PLAINTEXT - 1) / MAX_RECORD_PLAINTEXT
        val startSeqNum: Long
        seqLock.withLock {
            startSeqNum = clientSeqNum
            clientSeqNum += chunkCount
        }

        // Per-record overhead varies by cipher mode:
        //   TLS 1.3 AEAD: 5 header + 1 content type + 16 tag = 22
        //   TLS 1.2 AEAD GCM: 5 header + 8 nonce + 16 tag = 29
        //   TLS 1.2 AEAD ChaCha20: 5 header + 16 tag = 21
        //   TLS 1.2 CBC: 5 header + 16 IV + 48 MAC(max) + 16 padding(max) = 85
        // Use conservative upper bound to avoid overflow.
        val maxOverheadPerRecord = if (isTls13) 22 else if (!isAEAD) 85 else 29
        val records = ByteArray(data.size + chunkCount * maxOverheadPerRecord)
        var recordsOffset = 0
        var offset = 0
        var seqNum = startSeqNum

        while (offset < data.size) {
            val end = minOf(offset + MAX_RECORD_PLAINTEXT, data.size)
            val chunk = data.copyOfRange(offset, end)
            val record = encryptAndBuildTLSRecord(chunk, seqNum)
            System.arraycopy(record, 0, records, recordsOffset, record.size)
            recordsOffset += record.size
            seqNum++
            offset = end
        }

        return records.copyOfRange(0, recordsOffset)
    }

    private fun decryptTLSRecord(ciphertext: ByteArray, header: ByteArray, seqNum: Long): ByteArray {
        return if (isTls13) {
            decryptTls13Record(ciphertext, header, seqNum)
        } else {
            decryptTls12Record(ciphertext, header, seqNum)
        }
    }

    private fun encryptAndBuildTLSRecord(plaintext: ByteArray, seqNum: Long): ByteArray {
        return if (isTls13) {
            encryptTls13Record(plaintext, seqNum)
        } else {
            encryptTls12Record(plaintext, 0x17, seqNum)
        }
    }

    private fun decryptTls13Record(ciphertext: ByteArray, header: ByteArray, seqNum: Long): ByteArray {
        if (ciphertext.size < 16) {
            throw RealityError.HandshakeFailed("Ciphertext too short")
        }

        val nonce = com.argsment.anywhere.vpn.util.PacketUtil.xorNonce(serverIV, seqNum)
        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        decryptCipher.init(Cipher.DECRYPT_MODE, serverKeySpec, paramSpec)
        decryptCipher.updateAAD(header)
        val decrypted = decryptCipher.doFinal(ciphertext)

        if (decrypted.isEmpty()) {
            throw RealityError.HandshakeFailed("Empty decrypted data")
        }

        val unwrapped = com.argsment.anywhere.vpn.util.PacketUtil.tls13UnwrapContent(decrypted)
            ?: throw RealityError.HandshakeFailed("No content type found")
        if (unwrapped.isEmpty()) {
            throw RealityError.HandshakeFailed("No content type found")
        }

        val innerContentType = unwrapped[0].toInt() and 0xFF
        val content = unwrapped.copyOfRange(1, unwrapped.size)

        if (innerContentType == 0x16) return ByteArray(0)
        return content
    }

    private fun encryptTls13Record(plaintext: ByteArray, seqNum: Long): ByteArray {
        val innerLen = plaintext.size + 1
        val encryptedLen = innerLen + 16

        val nonce = com.argsment.anywhere.vpn.util.PacketUtil.xorNonce(clientIV, seqNum)

        val innerPlaintext = ByteArray(innerLen)
        System.arraycopy(plaintext, 0, innerPlaintext, 0, plaintext.size)
        innerPlaintext[plaintext.size] = 0x17

        val aad = byteArrayOf(
            0x17, 0x03, 0x03,
            ((encryptedLen shr 8) and 0xFF).toByte(),
            (encryptedLen and 0xFF).toByte()
        )

        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        encryptCipher.init(Cipher.ENCRYPT_MODE, clientKeySpec, paramSpec)
        encryptCipher.updateAAD(aad)
        val encrypted = encryptCipher.doFinal(innerPlaintext)

        val record = ByteArray(5 + encrypted.size)
        record[0] = 0x17; record[1] = 0x03; record[2] = 0x03
        record[3] = ((encrypted.size shr 8) and 0xFF).toByte()
        record[4] = (encrypted.size and 0xFF).toByte()
        System.arraycopy(encrypted, 0, record, 5, encrypted.size)
        return record
    }

    private fun encryptTls12Record(plaintext: ByteArray, contentType: Byte, seqNum: Long): ByteArray {
        val versionHi = ((tlsVersion shr 8) and 0xFF).toByte()
        val versionLo = (tlsVersion and 0xFF).toByte()

        if (isAEAD) {
            return encryptTls12AEAD(plaintext, contentType, seqNum, versionHi, versionLo)
        } else {
            return encryptTls12CBC(plaintext, contentType, seqNum, versionHi, versionLo)
        }
    }

    private fun encryptTls12AEAD(
        plaintext: ByteArray, contentType: Byte, seqNum: Long,
        versionHi: Byte, versionLo: Byte
    ): ByteArray {
        val explicitNonceLen = if (isChaCha) 0 else 8

        val nonce: ByteArray
        val explicitNonce: ByteArray
        if (isChaCha) {
            nonce = xorNonce(clientIV, seqNum)
            explicitNonce = ByteArray(0)
        } else {
            // AES-GCM nonce: implicit(4) || explicit(8) where explicit = seq number.
            val seqBytes = seqToBytes(seqNum)
            nonce = ByteArray(clientIV.size + seqBytes.size)
            System.arraycopy(clientIV, 0, nonce, 0, clientIV.size)
            System.arraycopy(seqBytes, 0, nonce, clientIV.size, seqBytes.size)
            explicitNonce = seqBytes
        }

        val aad = ByteArray(13) // seq(8) || type(1) || version(2) || plaintext_length(2)
        val seqBytes = seqToBytes(seqNum)
        System.arraycopy(seqBytes, 0, aad, 0, 8)
        aad[8] = contentType
        aad[9] = versionHi
        aad[10] = versionLo
        aad[11] = ((plaintext.size shr 8) and 0xFF).toByte()
        aad[12] = (plaintext.size and 0xFF).toByte()

        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        encryptCipher.init(Cipher.ENCRYPT_MODE, clientKeySpec, paramSpec)
        encryptCipher.updateAAD(aad)
        val encrypted = encryptCipher.doFinal(plaintext)

        val recordPayloadLen = explicitNonceLen + encrypted.size
        val record = ByteArray(5 + recordPayloadLen)
        record[0] = contentType
        record[1] = versionHi; record[2] = versionLo
        record[3] = ((recordPayloadLen shr 8) and 0xFF).toByte()
        record[4] = (recordPayloadLen and 0xFF).toByte()
        if (explicitNonceLen > 0) {
            System.arraycopy(explicitNonce, 0, record, 5, explicitNonceLen)
        }
        System.arraycopy(encrypted, 0, record, 5 + explicitNonceLen, encrypted.size)
        return record
    }

    private fun encryptTls12CBC(
        plaintext: ByteArray, contentType: Byte, seqNum: Long,
        versionHi: Byte, versionLo: Byte
    ): ByteArray {
        val useSHA384 = TlsCipherSuite.usesSHA384(cipherSuite)
        val useSHA256 = TlsCipherSuite.cbcUsesSHA256(cipherSuite)

        val mac = Tls12KeyDerivation.tls10MAC(
            clientMACKey, seqNum, contentType, tlsVersion, plaintext,
            useSHA384, useSHA256
        )

        val data = ByteArray(plaintext.size + mac.size)
        System.arraycopy(plaintext, 0, data, 0, plaintext.size)
        System.arraycopy(mac, 0, data, plaintext.size, mac.size)

        val blockSize = 16
        val paddingLen = blockSize - (data.size % blockSize)
        val paddingByte = (paddingLen - 1).toByte()
        val padded = ByteArray(data.size + paddingLen)
        System.arraycopy(data, 0, padded, 0, data.size)
        for (i in data.size until padded.size) padded[i] = paddingByte

        // Random IV per record.
        val iv = ByteArray(blockSize)
        java.security.SecureRandom().nextBytes(iv)

        cbcEncryptCipher.init(Cipher.ENCRYPT_MODE, cbcClientKeySpec, IvParameterSpec(iv))
        val encrypted = cbcEncryptCipher.doFinal(padded)

        val recordPayloadLen = blockSize + encrypted.size
        val record = ByteArray(5 + recordPayloadLen)
        record[0] = contentType
        record[1] = versionHi; record[2] = versionLo
        record[3] = ((recordPayloadLen shr 8) and 0xFF).toByte()
        record[4] = (recordPayloadLen and 0xFF).toByte()
        System.arraycopy(iv, 0, record, 5, blockSize)
        System.arraycopy(encrypted, 0, record, 5 + blockSize, encrypted.size)
        return record
    }

    private fun decryptTls12Record(ciphertext: ByteArray, header: ByteArray, seqNum: Long): ByteArray {
        val contentType = header[0]
        if (isAEAD) {
            return decryptTls12AEAD(ciphertext, contentType, seqNum)
        } else {
            return decryptTls12CBC(ciphertext, contentType, seqNum)
        }
    }

    private fun decryptTls12AEAD(ciphertext: ByteArray, contentType: Byte, seqNum: Long): ByteArray {
        val explicitNonceLen = if (isChaCha) 0 else 8
        if (ciphertext.size < explicitNonceLen + 16) {
            throw RealityError.HandshakeFailed("Ciphertext too short for TLS 1.2 AEAD")
        }

        val explicitNonce = if (isChaCha) ByteArray(0)
            else ciphertext.copyOfRange(0, explicitNonceLen)
        val payload = ciphertext.copyOfRange(explicitNonceLen, ciphertext.size)

        val nonce: ByteArray
        if (isChaCha) {
            nonce = xorNonce(serverIV, seqNum)
        } else {
            nonce = ByteArray(serverIV.size + explicitNonce.size)
            System.arraycopy(serverIV, 0, nonce, 0, serverIV.size)
            System.arraycopy(explicitNonce, 0, nonce, serverIV.size, explicitNonce.size)
        }

        val plaintextLen = payload.size - 16
        val aad = ByteArray(13)
        val seqBytes = seqToBytes(seqNum)
        System.arraycopy(seqBytes, 0, aad, 0, 8)
        aad[8] = contentType
        aad[9] = ((tlsVersion shr 8) and 0xFF).toByte()
        aad[10] = (tlsVersion and 0xFF).toByte()
        aad[11] = ((plaintextLen shr 8) and 0xFF).toByte()
        aad[12] = (plaintextLen and 0xFF).toByte()

        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        decryptCipher.init(Cipher.DECRYPT_MODE, serverKeySpec, paramSpec)
        decryptCipher.updateAAD(aad)
        return decryptCipher.doFinal(payload)
    }

    private fun decryptTls12CBC(ciphertext: ByteArray, contentType: Byte, seqNum: Long): ByteArray {
        val blockSize = 16
        if (ciphertext.size < blockSize * 2) {
            throw RealityError.HandshakeFailed("Ciphertext too short for CBC")
        }

        val iv = ciphertext.copyOfRange(0, blockSize)
        val encrypted = ciphertext.copyOfRange(blockSize, ciphertext.size)
        if (encrypted.size % blockSize != 0) {
            throw RealityError.HandshakeFailed("CBC ciphertext not aligned")
        }

        cbcDecryptCipher.init(Cipher.DECRYPT_MODE, cbcServerKeySpec, IvParameterSpec(iv))
        var decrypted = cbcDecryptCipher.doFinal(encrypted)

        // Validate and strip padding (constant-time to mitigate Lucky13).
        val paddingByte = decrypted.last().toInt() and 0xFF
        val paddingLen = paddingByte + 1
        if (paddingLen > decrypted.size) {
            throw RealityError.HandshakeFailed("Invalid CBC padding")
        }
        var paddingGood: Int = 0
        for (i in (decrypted.size - paddingLen) until decrypted.size) {
            paddingGood = paddingGood or (decrypted[i].toInt() and 0xFF xor paddingByte)
        }
        if (paddingGood != 0) {
            throw RealityError.HandshakeFailed("Invalid CBC padding")
        }
        decrypted = decrypted.copyOfRange(0, decrypted.size - paddingLen)

        val macSize = TlsCipherSuite.macLength(cipherSuite)
        if (decrypted.size < macSize) {
            throw RealityError.HandshakeFailed("Decrypted data too short for MAC")
        }
        val payload = decrypted.copyOfRange(0, decrypted.size - macSize)
        val receivedMAC = decrypted.copyOfRange(decrypted.size - macSize, decrypted.size)

        val useSHA384 = TlsCipherSuite.usesSHA384(cipherSuite)
        val useSHA256 = TlsCipherSuite.cbcUsesSHA256(cipherSuite)
        val expectedMAC = Tls12KeyDerivation.tls10MAC(
            serverMACKey, seqNum, contentType, tlsVersion, payload, useSHA384, useSHA256
        )

        // Constant-time comparison to prevent timing attacks.
        if (!MessageDigest.isEqual(receivedMAC, expectedMAC)) {
            throw RealityError.HandshakeFailed("MAC verification failed")
        }
        return payload
    }

    /** XOR sequence number into the last 8 bytes of an IV (for ChaCha20 TLS 1.2). */
    private fun xorNonce(iv: ByteArray, seqNum: Long): ByteArray {
        val nonce = iv.copyOf()
        val base = nonce.size - 8
        for (i in 0 until 8) {
            nonce[base + i] = (nonce[base + i].toInt() xor ((seqNum shr ((7 - i) * 8)) and 0xFF).toInt()).toByte()
        }
        return nonce
    }

    private fun seqToBytes(seqNum: Long): ByteArray {
        val bytes = ByteArray(8)
        for (i in 0 until 8) {
            bytes[i] = ((seqNum shr ((7 - i) * 8)) and 0xFF).toByte()
        }
        return bytes
    }
}
