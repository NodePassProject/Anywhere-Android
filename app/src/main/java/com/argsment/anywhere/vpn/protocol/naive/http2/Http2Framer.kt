package com.argsment.anywhere.vpn.protocol.naive.http2

import java.io.ByteArrayOutputStream

// -- Frame Types and Flags --

/** HTTP/2 frame types (RFC 7540 §6). */
enum class Http2FrameType(val value: Int) {
    DATA(0x0),
    HEADERS(0x1),
    RST_STREAM(0x3),
    SETTINGS(0x4),
    PING(0x6),
    GOAWAY(0x7),
    WINDOW_UPDATE(0x8);

    companion object {
        fun fromValue(value: Int): Http2FrameType? = entries.firstOrNull { it.value == value }
    }
}

/** HTTP/2 frame flag constants. */
object Http2FrameFlags {
    /** DATA: last frame for the stream. HEADERS: same. */
    const val END_STREAM: Int = 0x1
    /** SETTINGS, PING: acknowledgment. */
    const val ACK: Int = 0x1
    /** HEADERS: header block is complete (no CONTINUATION). */
    const val END_HEADERS: Int = 0x4
}

// -- Frame --

/**
 * A single HTTP/2 frame (RFC 7540 §4.1).
 *
 * Wire format (9-byte header + payload):
 * ```
 * [3 bytes] Length  (payload length, unsigned 24-bit)
 * [1 byte]  Type
 * [1 byte]  Flags
 * [4 bytes] Stream ID (bit 0 reserved, always 0)
 * [Length bytes] Payload
 * ```
 */
data class Http2Frame(
    val type: Http2FrameType,
    val flags: Int,
    val streamID: Int,
    val payload: ByteArray
) {
    fun hasFlag(flag: Int): Boolean = flags and flag != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Http2Frame) return false
        return type == other.type && flags == other.flags && streamID == other.streamID &&
                payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + flags
        result = 31 * result + streamID
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

// -- Framer --

/** HTTP/2 frame serializer and deserializer. */
object Http2Framer {
    const val HEADER_SIZE = 9
    const val MAX_DATA_PAYLOAD = 16_384  // HTTP/2 default SETTINGS_MAX_FRAME_SIZE

    // -- Serialize --

    /** Serializes a frame into wire format (9-byte header + payload). */
    fun serialize(frame: Http2Frame): ByteArray {
        val length = frame.payload.size
        val data = ByteArray(HEADER_SIZE + length)
        // 24-bit length (big-endian)
        data[0] = ((length shr 16) and 0xFF).toByte()
        data[1] = ((length shr 8) and 0xFF).toByte()
        data[2] = (length and 0xFF).toByte()
        // Type
        data[3] = frame.type.value.toByte()
        // Flags
        data[4] = frame.flags.toByte()
        // 31-bit stream ID (big-endian, reserved bit 0)
        val sid = frame.streamID and 0x7FFFFFFF
        data[5] = ((sid shr 24) and 0xFF).toByte()
        data[6] = ((sid shr 16) and 0xFF).toByte()
        data[7] = ((sid shr 8) and 0xFF).toByte()
        data[8] = (sid and 0xFF).toByte()
        // Payload
        System.arraycopy(frame.payload, 0, data, HEADER_SIZE, length)
        return data
    }

    // -- Deserialize --

    /**
     * Attempts to deserialize one complete frame from [buffer].
     *
     * On success, removes the consumed bytes from [buffer] and returns the frame.
     * Returns null if [buffer] does not contain a complete frame.
     */
    fun deserialize(buffer: Http2Buffer): Http2Frame? {
        if (buffer.available < HEADER_SIZE) return null

        val b = buffer.peekHeader()

        val length = (b[0].toInt() and 0xFF shl 16) or
                (b[1].toInt() and 0xFF shl 8) or
                (b[2].toInt() and 0xFF)
        val totalSize = HEADER_SIZE + length

        if (buffer.available < totalSize) return null

        val rawType = b[3].toInt() and 0xFF
        val flags = b[4].toInt() and 0xFF
        val streamID = ((b[5].toInt() and 0xFF shl 24) or
                (b[6].toInt() and 0xFF shl 16) or
                (b[7].toInt() and 0xFF shl 8) or
                (b[8].toInt() and 0xFF)) and 0x7FFFFFFF

        // Consume header + payload
        buffer.skip(HEADER_SIZE)
        val payload = buffer.read(length)

        val type = Http2FrameType.fromValue(rawType)
        if (type == null) {
            // Unknown frame type — skip per RFC 7540 §4.1
            return Http2Frame(Http2FrameType.DATA, 0, streamID, ByteArray(0))
        }

        return Http2Frame(type, flags, streamID, payload)
    }

    // -- Convenience Builders --

    /** Creates a SETTINGS frame with the given parameters (id, value pairs). */
    fun settingsFrame(settings: List<Pair<Int, Int>>): Http2Frame {
        val buf = ByteArrayOutputStream(settings.size * 6)
        for ((id, value) in settings) {
            buf.write((id shr 8) and 0xFF)
            buf.write(id and 0xFF)
            buf.write((value shr 24) and 0xFF)
            buf.write((value shr 16) and 0xFF)
            buf.write((value shr 8) and 0xFF)
            buf.write(value and 0xFF)
        }
        return Http2Frame(Http2FrameType.SETTINGS, 0, 0, buf.toByteArray())
    }

    /** Creates a SETTINGS ACK frame. */
    fun settingsAckFrame(): Http2Frame =
        Http2Frame(Http2FrameType.SETTINGS, Http2FrameFlags.ACK, 0, ByteArray(0))

    /** Creates a WINDOW_UPDATE frame. */
    fun windowUpdateFrame(streamID: Int, increment: Int): Http2Frame {
        val inc = increment and 0x7FFFFFFF
        val payload = ByteArray(4)
        payload[0] = ((inc shr 24) and 0xFF).toByte()
        payload[1] = ((inc shr 16) and 0xFF).toByte()
        payload[2] = ((inc shr 8) and 0xFF).toByte()
        payload[3] = (inc and 0xFF).toByte()
        return Http2Frame(Http2FrameType.WINDOW_UPDATE, 0, streamID, payload)
    }

    /** Creates a HEADERS frame (END_HEADERS set) with an HPACK-encoded header block. */
    fun headersFrame(streamID: Int, headerBlock: ByteArray, endStream: Boolean = false): Http2Frame {
        var flags = Http2FrameFlags.END_HEADERS
        if (endStream) flags = flags or Http2FrameFlags.END_STREAM
        return Http2Frame(Http2FrameType.HEADERS, flags, streamID, headerBlock)
    }

    /** Creates a DATA frame. */
    fun dataFrame(streamID: Int, payload: ByteArray, endStream: Boolean = false): Http2Frame {
        var flags = 0
        if (endStream) flags = flags or Http2FrameFlags.END_STREAM
        return Http2Frame(Http2FrameType.DATA, flags, streamID, payload)
    }

    /** Creates a PING ACK frame echoing back the opaque data. */
    fun pingAckFrame(opaqueData: ByteArray): Http2Frame =
        Http2Frame(Http2FrameType.PING, Http2FrameFlags.ACK, 0, opaqueData)

    // -- Payload Parsers --

    /** Parses SETTINGS payload into (id, value) pairs. */
    fun parseSettings(payload: ByteArray): List<Pair<Int, Int>> {
        val result = mutableListOf<Pair<Int, Int>>()
        var offset = 0
        while (offset + 6 <= payload.size) {
            val id = (payload[offset].toInt() and 0xFF shl 8) or (payload[offset + 1].toInt() and 0xFF)
            val value = (payload[offset + 2].toInt() and 0xFF shl 24) or
                    (payload[offset + 3].toInt() and 0xFF shl 16) or
                    (payload[offset + 4].toInt() and 0xFF shl 8) or
                    (payload[offset + 5].toInt() and 0xFF)
            result.add(id to value)
            offset += 6
        }
        return result
    }

    /** Parses WINDOW_UPDATE payload. */
    fun parseWindowUpdate(payload: ByteArray): Int? {
        if (payload.size < 4) return null
        return ((payload[0].toInt() and 0xFF shl 24) or
                (payload[1].toInt() and 0xFF shl 16) or
                (payload[2].toInt() and 0xFF shl 8) or
                (payload[3].toInt() and 0xFF)) and 0x7FFFFFFF
    }

    /** Parses GOAWAY payload. */
    fun parseGoaway(payload: ByteArray): GoawayData? {
        if (payload.size < 8) return null
        val lastStreamID = ((payload[0].toInt() and 0xFF shl 24) or
                (payload[1].toInt() and 0xFF shl 16) or
                (payload[2].toInt() and 0xFF shl 8) or
                (payload[3].toInt() and 0xFF)) and 0x7FFFFFFF
        val errorCode = (payload[4].toInt() and 0xFF shl 24) or
                (payload[5].toInt() and 0xFF shl 16) or
                (payload[6].toInt() and 0xFF shl 8) or
                (payload[7].toInt() and 0xFF)
        return GoawayData(lastStreamID, errorCode)
    }

    data class GoawayData(val lastStreamID: Int, val errorCode: Int)

    /** Parses RST_STREAM payload. */
    fun parseRstStream(payload: ByteArray): Int? {
        if (payload.size < 4) return null
        return (payload[0].toInt() and 0xFF shl 24) or
                (payload[1].toInt() and 0xFF shl 16) or
                (payload[2].toInt() and 0xFF shl 8) or
                (payload[3].toInt() and 0xFF)
    }
}

/**
 * Efficient buffer for HTTP/2 frame deserialization.
 *
 * Avoids Data's copy-on-removeFirst behavior by tracking a read offset.
 */
class Http2Buffer {
    private var buffer = ByteArrayOutputStream()
    private var readOffset = 0

    val available: Int get() = buffer.size() - readOffset

    fun append(data: ByteArray) {
        // Compact if read offset is more than half the buffer
        if (readOffset > 0 && readOffset > buffer.size() / 2) {
            compact()
        }
        buffer.write(data)
    }

    fun peekHeader(): ByteArray {
        val bytes = buffer.toByteArray()
        return bytes.copyOfRange(readOffset, readOffset + Http2Framer.HEADER_SIZE)
    }

    fun skip(count: Int) {
        readOffset += count
    }

    fun read(count: Int): ByteArray {
        if (count == 0) return ByteArray(0)
        val bytes = buffer.toByteArray()
        val result = bytes.copyOfRange(readOffset, readOffset + count)
        readOffset += count
        return result
    }

    val isEmpty: Boolean get() = available <= 0

    fun clear() {
        buffer = ByteArrayOutputStream()
        readOffset = 0
    }

    private fun compact() {
        if (readOffset == 0) return
        val bytes = buffer.toByteArray()
        val remaining = bytes.size - readOffset
        buffer = ByteArrayOutputStream(remaining.coerceAtLeast(256))
        if (remaining > 0) {
            buffer.write(bytes, readOffset, remaining)
        }
        readOffset = 0
    }
}
