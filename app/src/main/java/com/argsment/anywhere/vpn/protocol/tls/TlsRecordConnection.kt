package com.argsment.anywhere.vpn.protocol.tls

import android.util.Log
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.vless.RealityError
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock as withMutexLock
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

private const val TAG = "TlsRecordConn"

/**
 * TLS 1.3 application-layer record encryption/decryption wrapper.
 *
 * Encrypts outgoing data into TLS Application Data records using AES-GCM
 * and decrypts incoming records. Sequence numbers are tracked independently
 * for client and server directions.
 *
 * Supports a "direct" mode ([receiveRaw] / [sendRaw]) that bypasses
 * encryption for Vision direct-copy transitions.
 */
class TlsRecordConnection(
    private val clientKey: ByteArray,
    private val clientIV: ByteArray,
    private val serverKey: ByteArray,
    private val serverIV: ByteArray,
    private val cipherSuite: Int = TlsCipherSuite.TLS_AES_128_GCM_SHA256
) {
    /** The underlying transport (NioSocket or TunneledTransport). */
    var connection: Transport? = null

    // Cipher dispatch helpers
    private val isChaCha = cipherSuite == TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
    private val cipherAlgo = if (isChaCha) "ChaCha20" else "AES"
    private val cipherTransform = if (isChaCha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding"
    private val clientKeySpec = SecretKeySpec(clientKey, cipherAlgo)
    private val serverKeySpec = SecretKeySpec(serverKey, cipherAlgo)

    // Cached Cipher instances to avoid Cipher.getInstance() on every record.
    // Cipher is not thread-safe, so separate instances for encrypt/decrypt.
    private val encryptCipher: Cipher = Cipher.getInstance(cipherTransform)
    private val decryptCipher: Cipher = Cipher.getInstance(cipherTransform)

    // Sequence numbers
    private var clientSeqNum: Long = 0
    private var serverSeqNum: Long = 0
    private val seqLock = ReentrantLock()

    /** Serialises the encrypt-then-enqueue path so that TLS records arrive at
     *  the socket in sequence-number order. Without this, two concurrent `send`
     *  calls can allocate consecutive sequence numbers but enqueue the encrypted
     *  records in reverse order, causing TLS decryption failures on the server
     *  and a "Broken pipe" on the next write. Matching iOS sendLock. */
    private val sendLock = Mutex()

    /** TLS 1.3 maximum plaintext per record (RFC 8446 S5.1). */
    companion object {
        private const val MAX_RECORD_PLAINTEXT = 16384
    }

    // Receive buffer for batching reads
    private var receiveBuffer = ByteArray(0)
    private var receiveBufferLen = 0
    private val receiveLock = ReentrantLock()

    // -- Send (Encrypted) --

    /**
     * Sends data through the TLS tunnel, encrypting it as TLS Application Data records.
     */
    suspend fun send(data: ByteArray) {
        sendLock.withMutexLock {
            val conn = connection ?: throw RealityError.HandshakeFailed("Connection cancelled")
            val record = buildTLSRecords(data)
            conn.send(record)
        }
    }

    /**
     * Sends data through the TLS tunnel without tracking completion.
     */
    fun sendAsync(data: ByteArray) {
        runBlocking {
            sendLock.withMutexLock {
                val conn = connection ?: return@withMutexLock
                try {
                    val record = buildTLSRecords(data)
                    conn.sendAsync(record)
                } catch (e: Exception) {
                    Log.e(TAG, "Encryption error: ${e.message}")
                }
            }
        }
    }

    // -- Receive (Encrypted) --

    /**
     * Receives and decrypts data from the TLS tunnel.
     *
     * Uses buffered reading to process multiple TLS records per network read,
     * reducing system call overhead.
     *
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

    // -- Send / Receive (Raw, Unencrypted) --

    /**
     * Receives raw data without decryption (for Vision direct-copy mode).
     *
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

    /**
     * Sends raw data without encryption (for Vision direct-copy mode).
     */
    suspend fun sendRaw(data: ByteArray) {
        val conn = connection ?: throw RealityError.HandshakeFailed("Connection cancelled")
        conn.send(data)
    }

    /**
     * Sends raw data without encryption and without tracking completion.
     */
    fun sendRawAsync(data: ByteArray) {
        val conn = connection ?: return
        conn.sendAsync(data)
    }

    // -- Cancel --

    /**
     * Closes the connection and releases all resources.
     *
     * Sends a TLS close_notify alert (best-effort) before closing.
     */
    fun cancel() {
        sendCloseNotify()

        receiveLock.withLock {
            receiveBufferLen = 0
            receiveBuffer = ByteArray(0)
        }

        connection?.forceCancel()
        connection = null
    }

    /**
     * Sends a TLS close_notify alert record (best-effort, fire-and-forget).
     */
    private fun sendCloseNotify() {
        runBlocking {
            sendLock.withMutexLock {
                val conn = connection ?: return@withMutexLock

                val seqNum: Long
                seqLock.withLock {
                    seqNum = clientSeqNum
                    clientSeqNum++
                }

                // Alert plaintext: level=warning(1), desc=close_notify(0), inner content type=alert(0x15)
                val alertPlaintext = byteArrayOf(0x01, 0x00, 0x15)
                val encryptedLen = alertPlaintext.size + 16 // +16 for GCM tag

                val nonce = NativeBridge.nativeXorNonce(clientIV, seqNum)
                val aad = byteArrayOf(
                    0x17, 0x03, 0x03,
                    ((encryptedLen shr 8) and 0xFF).toByte(),
                    (encryptedLen and 0xFF).toByte()
                )

                try {
                    val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
                    encryptCipher.init(Cipher.ENCRYPT_MODE, clientKeySpec, paramSpec)
                    encryptCipher.updateAAD(aad)
                    val encrypted = encryptCipher.doFinal(alertPlaintext)

                    val record = ByteArray(5 + encrypted.size)
                    record[0] = 0x17
                    record[1] = 0x03
                    record[2] = 0x03
                    record[3] = ((encrypted.size shr 8) and 0xFF).toByte()
                    record[4] = (encrypted.size and 0xFF).toByte()
                    System.arraycopy(encrypted, 0, record, 5, encrypted.size)

                    conn.sendAsync(record)
                } catch (_: Exception) {
                    // Best-effort, ignore errors
                }
            }
        }
    }

    // -- Internal Buffer Processing --

    /** Result of processing buffered TLS records. */
    private sealed class BufferResult {
        class Data(val data: ByteArray) : BufferResult()
        class Error(val error: Exception) : BufferResult()
        object NeedMore : BufferResult()
        object Skip : BufferResult()
        class DecryptionFailed(val rawData: ByteArray) : BufferResult()
    }

    /**
     * Handles a BufferResult, returning data or throwing on error.
     * Must NOT be called under receiveLock.
     */
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

    /** Fetches more data from the network and processes it. */
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
            // No complete record yet, fetch more
        }
    }

    /**
     * Prepends data to the receive buffer (e.g., leftover post-handshake data).
     * Matching iOS prependToReceiveBuffer() for NewSessionTicket data.
     */
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

    /** Appends data to the receive buffer. Must be called under receiveLock. */
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
     * Processes all complete TLS records in the receive buffer.
     * Returns batched decrypted data from multiple records to reduce callback overhead.
     * Must be called while holding receiveLock.
     */
    private fun processBuffer(): BufferResult? {
        if (receiveBufferLen == 0) return null

        var batchedData: ByteArray? = null
        var batchedLen = 0
        var hasError: Exception? = null
        var recordsProcessed = 0
        var failedRecordData: ByteArray? = null
        var offset = 0  // Current read position within receiveBuffer

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
                    // Pass header and body slices without copying the full record
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
                    // Collect the failed record + all remaining unprocessed data
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
            // Other content types (ChangeCipherSpec, etc.) are skipped
            offset += totalLen
        }

        // Compact buffer: shift remaining unprocessed data to front
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

    // -- TLS Record Crypto --

    /**
     * Encrypts plaintext into one or more TLS Application Data records.
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

        // 22 bytes overhead per record: 5 header + 1 content type + 16 GCM tag
        val records = ByteArray(data.size + chunkCount * 22)
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
        if (ciphertext.size < 16) {
            throw RealityError.HandshakeFailed("Ciphertext too short")
        }

        val nonce = NativeBridge.nativeXorNonce(serverIV, seqNum)

        val paramSpec = if (isChaCha) IvParameterSpec(nonce) else GCMParameterSpec(128, nonce)
        decryptCipher.init(Cipher.DECRYPT_MODE, serverKeySpec, paramSpec)
        decryptCipher.updateAAD(header)
        val decrypted = decryptCipher.doFinal(ciphertext)

        if (decrypted.isEmpty()) {
            throw RealityError.HandshakeFailed("Empty decrypted data")
        }

        // Unwrap inner content: strip trailing zeros and content type byte
        val unwrapped = NativeBridge.nativeTls13UnwrapContent(decrypted)
            ?: throw RealityError.HandshakeFailed("No content type found")

        if (unwrapped.isEmpty()) {
            throw RealityError.HandshakeFailed("No content type found")
        }

        val innerContentType = unwrapped[0].toInt() and 0xFF
        val content = unwrapped.copyOfRange(1, unwrapped.size)

        // Skip handshake records (post-handshake messages like NewSessionTicket)
        if (innerContentType == 0x16) {
            return ByteArray(0)
        }

        return content
    }

    private fun encryptAndBuildTLSRecord(plaintext: ByteArray, seqNum: Long): ByteArray {
        val innerLen = plaintext.size + 1  // +1 for content type byte
        val encryptedLen = innerLen + 16   // +16 for GCM tag

        val nonce = NativeBridge.nativeXorNonce(clientIV, seqNum)

        // Build inner plaintext: data + content type (0x17 = application data)
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

        // Build TLS record: header + encrypted (ciphertext + tag)
        val record = ByteArray(5 + encrypted.size)
        record[0] = 0x17
        record[1] = 0x03
        record[2] = 0x03
        record[3] = ((encrypted.size shr 8) and 0xFF).toByte()
        record[4] = (encrypted.size and 0xFF).toByte()
        System.arraycopy(encrypted, 0, record, 5, encrypted.size)

        return record
    }
}
