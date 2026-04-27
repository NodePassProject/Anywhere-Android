package com.argsment.anywhere.vpn.protocol.naive.http2

import java.io.ByteArrayOutputStream

/** RFC 7540 §6 frame types. */
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

object Http2FrameFlags {
    const val END_STREAM: Int = 0x1
    const val ACK: Int = 0x1
    const val END_HEADERS: Int = 0x4
}

/**
 * RFC 7540 §4.1 frame. Wire format (9-byte header + payload):
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

object Http2Framer {
    const val HEADER_SIZE = 9
    const val MAX_DATA_PAYLOAD = 16_384

    fun serialize(frame: Http2Frame): ByteArray {
        val length = frame.payload.size
        val data = ByteArray(HEADER_SIZE + length)
        data[0] = ((length shr 16) and 0xFF).toByte()
        data[1] = ((length shr 8) and 0xFF).toByte()
        data[2] = (length and 0xFF).toByte()
        data[3] = frame.type.value.toByte()
        data[4] = frame.flags.toByte()
        val sid = frame.streamID and 0x7FFFFFFF
        data[5] = ((sid shr 24) and 0xFF).toByte()
        data[6] = ((sid shr 16) and 0xFF).toByte()
        data[7] = ((sid shr 8) and 0xFF).toByte()
        data[8] = (sid and 0xFF).toByte()
        System.arraycopy(frame.payload, 0, data, HEADER_SIZE, length)
        return data
    }

    /** Returns null when [buffer] doesn't yet contain a complete frame. */
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

        buffer.skip(HEADER_SIZE)
        val payload = buffer.read(length)

        val type = Http2FrameType.fromValue(rawType)
        if (type == null) {
            // Unknown frame type — return empty DATA placeholder per RFC 7540 §4.1.
            return Http2Frame(Http2FrameType.DATA, 0, streamID, ByteArray(0))
        }

        return Http2Frame(type, flags, streamID, payload)
    }

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

    fun settingsAckFrame(): Http2Frame =
        Http2Frame(Http2FrameType.SETTINGS, Http2FrameFlags.ACK, 0, ByteArray(0))

    fun windowUpdateFrame(streamID: Int, increment: Int): Http2Frame {
        val inc = increment and 0x7FFFFFFF
        val payload = ByteArray(4)
        payload[0] = ((inc shr 24) and 0xFF).toByte()
        payload[1] = ((inc shr 16) and 0xFF).toByte()
        payload[2] = ((inc shr 8) and 0xFF).toByte()
        payload[3] = (inc and 0xFF).toByte()
        return Http2Frame(Http2FrameType.WINDOW_UPDATE, 0, streamID, payload)
    }

    /** HEADERS frame with END_HEADERS set; no CONTINUATION supported. */
    fun headersFrame(streamID: Int, headerBlock: ByteArray, endStream: Boolean = false): Http2Frame {
        var flags = Http2FrameFlags.END_HEADERS
        if (endStream) flags = flags or Http2FrameFlags.END_STREAM
        return Http2Frame(Http2FrameType.HEADERS, flags, streamID, headerBlock)
    }

    fun dataFrame(streamID: Int, payload: ByteArray, endStream: Boolean = false): Http2Frame {
        var flags = 0
        if (endStream) flags = flags or Http2FrameFlags.END_STREAM
        return Http2Frame(Http2FrameType.DATA, flags, streamID, payload)
    }

    fun pingAckFrame(opaqueData: ByteArray): Http2Frame =
        Http2Frame(Http2FrameType.PING, Http2FrameFlags.ACK, 0, opaqueData)

    /** RST_STREAM frame with the given error code (RFC 7540 §6.4). */
    fun rstStreamFrame(streamID: Int, errorCode: Int): Http2Frame {
        val payload = ByteArray(4)
        payload[0] = ((errorCode shr 24) and 0xFF).toByte()
        payload[1] = ((errorCode shr 16) and 0xFF).toByte()
        payload[2] = ((errorCode shr 8) and 0xFF).toByte()
        payload[3] = (errorCode and 0xFF).toByte()
        return Http2Frame(Http2FrameType.RST_STREAM, 0, streamID, payload)
    }

    /** RFC 7540 §7 error codes used by RST_STREAM and GOAWAY. */
    object ErrorCode {
        const val NO_ERROR = 0x0
        const val PROTOCOL_ERROR = 0x1
        const val INTERNAL_ERROR = 0x2
        const val FLOW_CONTROL_ERROR = 0x3
        const val SETTINGS_TIMEOUT = 0x4
        const val STREAM_CLOSED = 0x5
        const val FRAME_SIZE_ERROR = 0x6
        const val REFUSED_STREAM = 0x7
        const val CANCEL = 0x8
    }

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

    fun parseWindowUpdate(payload: ByteArray): Int? {
        if (payload.size < 4) return null
        return ((payload[0].toInt() and 0xFF shl 24) or
                (payload[1].toInt() and 0xFF shl 16) or
                (payload[2].toInt() and 0xFF shl 8) or
                (payload[3].toInt() and 0xFF)) and 0x7FFFFFFF
    }

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

    fun parseRstStream(payload: ByteArray): Int? {
        if (payload.size < 4) return null
        return (payload[0].toInt() and 0xFF shl 24) or
                (payload[1].toInt() and 0xFF shl 16) or
                (payload[2].toInt() and 0xFF shl 8) or
                (payload[3].toInt() and 0xFF)
    }
}

/** Buffer for HTTP/2 frame deserialization that avoids per-pop copies via a read offset. */
class Http2Buffer {
    private var buffer = ByteArrayOutputStream()
    private var readOffset = 0

    val available: Int get() = buffer.size() - readOffset

    fun append(data: ByteArray) {
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
