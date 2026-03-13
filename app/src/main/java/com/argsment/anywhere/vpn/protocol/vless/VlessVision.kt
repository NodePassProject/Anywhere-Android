package com.argsment.anywhere.vpn.protocol.vless

import com.argsment.anywhere.data.model.ProxyError
import java.security.SecureRandom
import kotlin.math.max
import kotlin.math.min

// =============================================================================
// Vision Constants
// =============================================================================

/** Vision padding commands. */
enum class VisionCommand(val value: Byte) {
    PADDING_CONTINUE(0x00),
    PADDING_END(0x01),
    PADDING_DIRECT(0x02);

    companion object {
        fun fromByte(b: Byte): VisionCommand? = entries.find { it.value == b }
    }
}

/** TLS detection constants. */
private val TLS_CLIENT_HANDSHAKE_START = byteArrayOf(0x16, 0x03)
private val TLS_SERVER_HANDSHAKE_START = byteArrayOf(0x16, 0x03, 0x03)
private val TLS_APPLICATION_DATA_START = byteArrayOf(0x17, 0x03, 0x03)
private val TLS13_SUPPORTED_VERSIONS = byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
private const val TLS_HANDSHAKE_TYPE_CLIENT_HELLO: Byte = 0x01
private const val TLS_HANDSHAKE_TYPE_SERVER_HELLO: Byte = 0x02

/** TLS 1.3 cipher suites that support XTLS direct copy. */
private val TLS13_CIPHER_SUITES = setOf<Int>(
    0x1301,  // TLS_AES_128_GCM_SHA256
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256
    0x1304,  // TLS_AES_128_CCM_SHA256
    // 0x1305 (TLS_AES_128_CCM_8_SHA256) is excluded
)

// =============================================================================
// Traffic State
// =============================================================================

/**
 * Tracks TLS detection and padding state for Vision.
 */
class VisionTrafficState(
    val userUUID: ByteArray,
    val testseed: IntArray = intArrayOf(900, 500, 900, 256)
) {
    // TLS detection state
    var numberOfPacketsToFilter: Int = 8
    var enableXtls: Boolean = false
    var isTLS12orAbove: Boolean = false
    var isTLS: Boolean = false
    var cipher: Int = 0
    var remainingServerHello: Int = -1

    // Writer state (for outgoing data)
    var writerIsPadding: Boolean = true
    var writerDirectCopy: Boolean = false

    // Reader state (for incoming data)
    var readerWithinPaddingBuffers: Boolean = true
    var readerDirectCopy: Boolean = false
    var remainingCommand: Int = -1
    var remainingContent: Int = -1
    var remainingPadding: Int = -1
    var currentCommand: Int = 0

    // First packet flag for UUID
    var writeOnceUserUUID: ByteArray? = userUUID.copyOf()

    init {
        require(testseed.size >= 4) { "testseed must have at least 4 elements" }
    }
}

// =============================================================================
// Buffer Reshaping
// =============================================================================

/** Maximum buffer size matching Xray-core's buf.Size */
private const val VISION_BUF_SIZE = 8192

/** Reshape threshold: buffers >= this need splitting to leave room for the 21-byte padding header */
private const val RESHAPE_THRESHOLD = 8192 - 21  // 8171

/**
 * Split data that is too large for a single Vision-padded frame.
 * Tries to split at the last TLS application data boundary; falls back to midpoint.
 * Matches Xray-core's ReshapeMultiBuffer.
 */
private fun reshapeData(data: ByteArray): List<ByteArray> {
    if (data.size < RESHAPE_THRESHOLD) return listOf(data)

    // Find last occurrence of TLS application data header (0x17 0x03 0x03)
    var splitIndex = data.size / 2
    for (i in (data.size - 3) downTo 0) {
        if (data[i] == 0x17.toByte() && data[i + 1] == 0x03.toByte() && data[i + 2] == 0x03.toByte()) {
            if (i in 21..RESHAPE_THRESHOLD) {
                splitIndex = i
                break
            }
        }
    }

    return listOf(
        data.copyOfRange(0, splitIndex),
        data.copyOfRange(splitIndex, data.size)
    )
}

// =============================================================================
// Padding Functions
// =============================================================================

private val secureRandom = SecureRandom()

/**
 * Add Vision padding to data.
 * Format: [UUID (16 bytes, first packet only)] [command (1)] [contentLen (2)] [paddingLen (2)] [content] [padding]
 */
fun visionPadding(data: ByteArray?, command: VisionCommand, state: VisionTrafficState, longPadding: Boolean): ByteArray {
    val contentLen = data?.size ?: 0
    var paddingLen: Int

    // Calculate padding length using testseed: [contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]
    val seed = state.testseed
    if (contentLen < seed[0] && longPadding) {
        paddingLen = secureRandom.nextInt(seed[1]) + seed[2] - contentLen
    } else {
        paddingLen = secureRandom.nextInt(seed[3])
    }

    // Ensure padding doesn't exceed buffer limits (matches Xray-core buf.Size = 8192)
    val maxPadding = 8192 - 21 - contentLen
    paddingLen = min(paddingLen, maxPadding)
    paddingLen = max(paddingLen, 0)

    val uuidPart = state.writeOnceUserUUID
    val uuidLen = uuidPart?.size ?: 0
    if (uuidPart != null) {
        state.writeOnceUserUUID = null
    }

    val result = ByteArray(uuidLen + 5 + contentLen + paddingLen)
    var offset = 0

    // Add UUID on first packet
    if (uuidPart != null) {
        System.arraycopy(uuidPart, 0, result, offset, uuidPart.size)
        offset += uuidPart.size
    }

    // Add command header: [command (1)] [contentLen (2)] [paddingLen (2)]
    result[offset++] = command.value
    result[offset++] = (contentLen shr 8).toByte()
    result[offset++] = (contentLen and 0xFF).toByte()
    result[offset++] = (paddingLen shr 8).toByte()
    result[offset++] = (paddingLen and 0xFF).toByte()

    // Add content
    if (data != null) {
        System.arraycopy(data, 0, result, offset, data.size)
        offset += data.size
    }

    // Add random padding
    if (paddingLen > 0) {
        val padding = ByteArray(paddingLen)
        secureRandom.nextBytes(padding)
        System.arraycopy(padding, 0, result, offset, paddingLen)
    }

    return result
}

/**
 * Remove Vision padding from data and extract content.
 * Returns the extracted content data.
 *
 * Note: [data] is consumed in-place and its contents may be modified.
 * Returns a new ByteArray with the extracted content.
 */
fun visionUnpadding(data: DataCursor, state: VisionTrafficState): ByteArray {
    // Initial state check - look for UUID prefix
    if (state.remainingCommand == -1 && state.remainingContent == -1 && state.remainingPadding == -1) {
        if (data.remaining >= 21 && data.startsWith(state.userUUID)) {
            data.advance(16)
            state.remainingCommand = 5
        } else {
            return data.readAll()
        }
    }

    val result = mutableListOf<Byte>()

    while (data.remaining > 0) {
        if (state.remainingCommand > 0) {
            // Reading command header
            val byte = data.readByte()
            when (state.remainingCommand) {
                5 -> state.currentCommand = byte.toInt() and 0xFF
                4 -> state.remainingContent = (byte.toInt() and 0xFF) shl 8
                3 -> state.remainingContent = state.remainingContent or (byte.toInt() and 0xFF)
                2 -> state.remainingPadding = (byte.toInt() and 0xFF) shl 8
                1 -> state.remainingPadding = state.remainingPadding or (byte.toInt() and 0xFF)
            }
            state.remainingCommand--
        } else if (state.remainingContent > 0) {
            val toRead = min(state.remainingContent, data.remaining)
            result.addAll(data.readBytes(toRead).toList())
            state.remainingContent -= toRead
        } else if (state.remainingPadding > 0) {
            val toSkip = min(state.remainingPadding, data.remaining)
            data.advance(toSkip)
            state.remainingPadding -= toSkip
        }

        // Check if current block is done
        if (state.remainingCommand <= 0 && state.remainingContent <= 0 && state.remainingPadding <= 0) {
            if (state.currentCommand == 0) {
                state.remainingCommand = 5
            } else {
                state.remainingCommand = -1
                state.remainingContent = -1
                state.remainingPadding = -1
                if (data.remaining > 0) {
                    result.addAll(data.readAll().toList())
                }
                break
            }
        }
    }

    return result.toByteArray()
}

/** Mutable cursor over a ByteArray for in-place consumption. */
class DataCursor(private val data: ByteArray, private var offset: Int = 0) {
    val remaining: Int get() = data.size - offset

    fun startsWith(prefix: ByteArray): Boolean {
        if (remaining < prefix.size) return false
        for (i in prefix.indices) {
            if (data[offset + i] != prefix[i]) return false
        }
        return true
    }

    fun advance(count: Int) {
        offset += count
    }

    fun readByte(): Byte = data[offset++]

    fun readBytes(count: Int): ByteArray {
        val result = data.copyOfRange(offset, offset + count)
        offset += count
        return result
    }

    fun readAll(): ByteArray {
        val result = data.copyOfRange(offset, data.size)
        offset = data.size
        return result
    }
}

// =============================================================================
// TLS Filtering
// =============================================================================

/**
 * Filter and detect TLS 1.3 in traffic (for incoming server responses).
 */
fun visionFilterTLS(data: ByteArray, state: VisionTrafficState) {
    if (state.numberOfPacketsToFilter <= 0) return
    state.numberOfPacketsToFilter--

    if (data.size < 6) return

    val byte0 = data[0]
    val byte1 = data[1]
    val byte2 = data[2]
    val byte5 = data[5]

    // Check for Server Hello: 0x16 0x03 0x03 ... 0x02
    if (byte0 == 0x16.toByte() && byte1 == 0x03.toByte() && byte2 == 0x03.toByte() &&
        byte5 == TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
        val byte3 = data[3]
        val byte4 = data[4]
        state.remainingServerHello = ((byte3.toInt() and 0xFF) shl 8 or (byte4.toInt() and 0xFF)) + 5
        state.isTLS12orAbove = true
        state.isTLS = true

        // Try to extract cipher suite
        if (data.size >= 79 && state.remainingServerHello >= 79) {
            val sessionIdLen = data[43].toInt() and 0xFF
            val cipherOffset = 43 + sessionIdLen + 1
            if (data.size > cipherOffset + 2) {
                state.cipher = (data[cipherOffset].toInt() and 0xFF shl 8) or
                        (data[cipherOffset + 1].toInt() and 0xFF)
            }
        }
    } else if (byte0 == 0x16.toByte() && byte1 == 0x03.toByte() &&
        byte5 == TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        state.isTLS = true
    }

    // Check for TLS 1.3 supported versions extension
    if (state.remainingServerHello > 0) {
        val end = min(state.remainingServerHello, data.size)
        state.remainingServerHello -= data.size

        // Search for TLS 1.3 supported versions extension
        if (containsSubarray(data, 0, end, TLS13_SUPPORTED_VERSIONS)) {
            if (state.cipher in TLS13_CIPHER_SUITES) {
                state.enableXtls = true
            }
            state.numberOfPacketsToFilter = 0
            return
        } else if (state.remainingServerHello <= 0) {
            state.numberOfPacketsToFilter = 0
            return
        }
    }
}

/**
 * Detect TLS Client Hello in outgoing data (doesn't decrement counter).
 */
fun visionDetectClientHello(data: ByteArray, state: VisionTrafficState) {
    if (data.size < 6) return

    if (data[0] == 0x16.toByte() && data[1] == 0x03.toByte() &&
        data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        state.isTLS = true
    }
}

/**
 * Check if data contains only complete TLS application data records.
 */
fun isCompleteTlsRecord(data: ByteArray): Boolean {
    if (data.size < 5) return false
    if (data[0] != 0x17.toByte() || data[1] != 0x03.toByte() || data[2] != 0x03.toByte()) return false

    var offset = 0
    while (offset < data.size) {
        if (offset + 5 > data.size) return false
        if (data[offset] != 0x17.toByte() || data[offset + 1] != 0x03.toByte() || data[offset + 2] != 0x03.toByte()) {
            return false
        }
        val recordLen = (data[offset + 3].toInt() and 0xFF shl 8) or (data[offset + 4].toInt() and 0xFF)
        offset += 5
        if (offset + recordLen > data.size) return false
        offset += recordLen
    }

    return offset == data.size
}

private fun containsSubarray(data: ByteArray, fromIndex: Int, toIndex: Int, sub: ByteArray): Boolean {
    if (sub.isEmpty()) return true
    val end = min(toIndex, data.size) - sub.size
    outer@ for (i in fromIndex..end) {
        for (j in sub.indices) {
            if (data[i + j] != sub[j]) continue@outer
        }
        return true
    }
    return false
}

// =============================================================================
// Vision Connection Wrapper
// =============================================================================

/**
 * VLESS connection with Vision flow control.
 */
class VlessVisionConnection(
    private val innerConnection: VlessConnection,
    userUUID: ByteArray,
    testseed: IntArray = intArrayOf(900, 500, 900, 256)
) : VlessConnection() {

    private val trafficState = VisionTrafficState(userUUID, testseed)
    private val lock = Any()

    /**
     * Send an empty padding frame to camouflage the VLESS header.
     * Called when no initial data is available, so the header isn't sent alone.
     * Matches Xray-core outbound.go lines 331-337.
     */
    fun sendEmptyPadding() {
        val padded: ByteArray
        synchronized(lock) {
            padded = visionPadding(null, VisionCommand.PADDING_CONTINUE, trafficState, true)
        }
        innerConnection.sendAsync(padded)
    }

    override val isConnected: Boolean get() = innerConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        val isDirectCopy: Boolean
        val paddedData: ByteArray
        synchronized(lock) {
            isDirectCopy = trafficState.writerDirectCopy
            paddedData = processSendData(data)
        }

        if (isDirectCopy) {
            innerConnection.sendDirectRaw(paddedData)
        } else {
            innerConnection.send(paddedData)
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        val isDirectCopy: Boolean
        val paddedData: ByteArray
        synchronized(lock) {
            isDirectCopy = trafficState.writerDirectCopy
            paddedData = processSendData(data)
        }

        if (isDirectCopy) {
            innerConnection.sendDirectRawAsync(paddedData)
        } else {
            innerConnection.sendAsync(paddedData)
        }
    }

    private fun processSendData(data: ByteArray): ByteArray {
        // Detect Client Hello to enable long padding (don't decrement counter)
        if (!trafficState.isTLS) {
            visionDetectClientHello(data, trafficState)
        }

        // If direct copy mode, send without padding
        if (trafficState.writerDirectCopy) return data

        // If not in padding mode, send directly
        if (!trafficState.writerIsPadding) return data

        val longPadding = trafficState.isTLS
        val isComplete = isCompleteTlsRecord(data)

        // Reshape oversized buffers to ensure room for the 21-byte Vision padding header
        val chunks = reshapeData(data)

        // Check if this is TLS application data and we should end padding
        if (trafficState.isTLS && data.size >= 6 &&
            data[0] == 0x17.toByte() && data[1] == 0x03.toByte() && data[2] == 0x03.toByte() &&
            isComplete) {

            var result = byteArrayOf()
            for ((i, chunk) in chunks.withIndex()) {
                if (i == chunks.size - 1) {
                    val command: VisionCommand
                    if (trafficState.enableXtls) {
                        command = VisionCommand.PADDING_DIRECT
                        trafficState.writerDirectCopy = true
                    } else {
                        command = VisionCommand.PADDING_END
                    }
                    trafficState.writerIsPadding = false
                    result += visionPadding(chunk, command, trafficState, false)
                } else {
                    result += visionPadding(chunk, VisionCommand.PADDING_CONTINUE, trafficState, true)
                }
            }
            return result
        }

        // For compatibility with earlier vision receiver, finish padding 1 packet early
        if (!trafficState.isTLS12orAbove && trafficState.numberOfPacketsToFilter <= 1) {
            trafficState.writerIsPadding = false
            var result = byteArrayOf()
            for ((i, chunk) in chunks.withIndex()) {
                val cmd = if (i == chunks.size - 1) VisionCommand.PADDING_END else VisionCommand.PADDING_CONTINUE
                result += visionPadding(chunk, cmd, trafficState, longPadding)
            }
            return result
        }

        // Continue with padding
        var result = byteArrayOf()
        for (chunk in chunks) {
            result += visionPadding(chunk, VisionCommand.PADDING_CONTINUE, trafficState, longPadding)
        }
        return result
    }

    override suspend fun receiveRaw(): ByteArray? {
        return receiveRawInternal()
    }

    private suspend fun receiveRawInternal(): ByteArray? {
        val isDirectCopy: Boolean
        synchronized(lock) {
            isDirectCopy = trafficState.readerDirectCopy
        }

        if (isDirectCopy) {
            return innerConnection.receiveDirectRaw()
        } else {
            val data: ByteArray?
            try {
                data = innerConnection.receive()
            } catch (e: RealityError.DecryptionFailed) {
                // Reality decryption failed — the server has transitioned to direct copy mode
                // (sending raw inner TLS data without Reality encryption).
                // Switch reader to direct copy and return the raw data.
                synchronized(lock) {
                    trafficState.readerDirectCopy = true
                    trafficState.readerWithinPaddingBuffers = false
                }
                val rawData = e.rawData
                if (rawData != null && rawData.isNotEmpty()) {
                    return rawData
                }
                return innerConnection.receiveDirectRaw()
            }

            if (data == null || data.isEmpty()) return null

            val processedData: ByteArray
            synchronized(lock) {
                processedData = processReceiveData(data)
            }

            // If processed data is empty (e.g., only padding was received),
            // continue receiving instead of returning nil (which would close the connection)
            return if (processedData.isEmpty()) {
                receiveRawInternal()
            } else {
                processedData
            }
        }
    }

    // Override receive to skip response header processing (inner connection handles it)
    override suspend fun receive(): ByteArray? = receiveRaw()

    private fun processReceiveData(data: ByteArray): ByteArray {
        // Filter TLS from server responses
        if (trafficState.numberOfPacketsToFilter > 0) {
            visionFilterTLS(data, trafficState)
        }

        // If direct copy mode, return without unpadding
        if (trafficState.readerDirectCopy) return data

        // If within padding buffers or still filtering, unpad
        if (trafficState.readerWithinPaddingBuffers || trafficState.numberOfPacketsToFilter > 0) {
            val cursor = DataCursor(data)
            val unpadded = visionUnpadding(cursor, trafficState)

            // Update state based on current command
            if (trafficState.remainingContent > 0 || trafficState.remainingPadding > 0 || trafficState.currentCommand == 0) {
                trafficState.readerWithinPaddingBuffers = true
            } else if (trafficState.currentCommand == 1) {
                trafficState.readerWithinPaddingBuffers = false
            } else if (trafficState.currentCommand == 2) {
                trafficState.readerWithinPaddingBuffers = false
                trafficState.readerDirectCopy = true
            }

            return unpadded
        }

        return data
    }

    override fun cancel() {
        innerConnection.cancel()
    }
}
