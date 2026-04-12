package com.argsment.anywhere.vpn.protocol.naive.http3

/**
 * HTTP/3 frame types (RFC 9114 §7.2).
 */
object Http3FrameType {
    const val DATA: Long = 0x00
    const val HEADERS: Long = 0x01
    const val CANCEL_PUSH: Long = 0x03
    const val SETTINGS: Long = 0x04
    const val PUSH_PROMISE: Long = 0x05
    const val GOAWAY: Long = 0x07
    const val MAX_PUSH_ID: Long = 0x0D
}

/** HTTP/3 SETTINGS identifiers. */
object Http3SettingsId {
    const val QPACK_MAX_TABLE_CAPACITY: Long = 0x01
    const val MAX_FIELD_SECTION_SIZE: Long = 0x06
    const val QPACK_BLOCKED_STREAMS: Long = 0x07
    /** RFC 9220 — extended CONNECT. */
    const val ENABLE_CONNECT_PROTOCOL: Long = 0x08
    /** RFC 9297 — HTTP Datagrams. */
    const val H3_DATAGRAM: Long = 0x33
}

/** RFC 9114 §8.1 application error codes. */
object Http3ErrorCode {
    const val NO_ERROR: Long = 0x0100
    const val GENERAL_PROTOCOL_ERROR: Long = 0x0101
    const val INTERNAL_ERROR: Long = 0x0102
    const val STREAM_CREATION_ERROR: Long = 0x0103
    const val CLOSED_CRITICAL_STREAM: Long = 0x0104
    const val FRAME_UNEXPECTED: Long = 0x0105
    const val FRAME_ERROR: Long = 0x0106
    const val EXCESSIVE_LOAD: Long = 0x0107
    const val ID_ERROR: Long = 0x0108
    const val SETTINGS_ERROR: Long = 0x0109
    const val MISSING_SETTINGS: Long = 0x010A
    const val REQUEST_REJECTED: Long = 0x010B
    const val REQUEST_CANCELLED: Long = 0x010C
    const val REQUEST_INCOMPLETE: Long = 0x010D
    const val MESSAGE_ERROR: Long = 0x010E
    const val CONNECT_ERROR: Long = 0x010F
    const val VERSION_FALLBACK: Long = 0x0110
}

/** Parsed HTTP/3 frame. */
data class Http3Frame(val type: Long, val payload: ByteArray) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is Http3Frame && type == other.type && payload.contentEquals(other.payload))
    override fun hashCode(): Int = 31 * type.hashCode() + payload.contentHashCode()
}

object Http3Framer {

    // QUIC variable-length integer (RFC 9000 §16)

    fun encodeVarInt(value: Long): ByteArray {
        val v = value.toULong().toLong()
        return when {
            v <= 63 -> byteArrayOf(v.toByte())
            v <= 16_383 -> byteArrayOf(
                (0x40 or ((v ushr 8).toInt())).toByte(),
                (v and 0xFF).toByte()
            )
            v <= 1_073_741_823 -> byteArrayOf(
                (0x80 or ((v ushr 24).toInt())).toByte(),
                ((v ushr 16) and 0xFF).toByte(),
                ((v ushr 8) and 0xFF).toByte(),
                (v and 0xFF).toByte()
            )
            else -> byteArrayOf(
                (0xC0 or ((v ushr 56).toInt())).toByte(),
                ((v ushr 48) and 0xFF).toByte(),
                ((v ushr 40) and 0xFF).toByte(),
                ((v ushr 32) and 0xFF).toByte(),
                ((v ushr 24) and 0xFF).toByte(),
                ((v ushr 16) and 0xFF).toByte(),
                ((v ushr 8) and 0xFF).toByte(),
                (v and 0xFF).toByte()
            )
        }
    }

    /** Returns (value, bytesConsumed) or null if incomplete. */
    fun decodeVarInt(data: ByteArray, offset: Int = 0): Pair<Long, Int>? {
        if (offset >= data.size) return null
        val first = data[offset].toInt() and 0xFF
        return when (first ushr 6) {
            0 -> (first.toLong()) to 1
            1 -> {
                if (offset + 2 > data.size) return null
                val v = ((first and 0x3F).toLong() shl 8) or (data[offset + 1].toLong() and 0xFF)
                v to 2
            }
            2 -> {
                if (offset + 4 > data.size) return null
                var v = (first and 0x3F).toLong() shl 24
                v = v or ((data[offset + 1].toLong() and 0xFF) shl 16)
                v = v or ((data[offset + 2].toLong() and 0xFF) shl 8)
                v = v or (data[offset + 3].toLong() and 0xFF)
                v to 4
            }
            3 -> {
                if (offset + 8 > data.size) return null
                var v = (first and 0x3F).toLong() shl 56
                for (i in 1 until 8) {
                    v = v or ((data[offset + i].toLong() and 0xFF) shl ((7 - i) * 8))
                }
                v to 8
            }
            else -> null
        }
    }

    fun headersFrame(headerBlock: ByteArray): ByteArray {
        val type = encodeVarInt(Http3FrameType.HEADERS)
        val len = encodeVarInt(headerBlock.size.toLong())
        return type + len + headerBlock
    }

    fun dataFrame(payload: ByteArray): ByteArray {
        val type = encodeVarInt(Http3FrameType.DATA)
        val len = encodeVarInt(payload.size.toLong())
        return type + len + payload
    }

    fun clientSettingsFrame(): ByteArray {
        val body = java.io.ByteArrayOutputStream()
        fun put(id: Long, v: Long) {
            body.write(encodeVarInt(id)); body.write(encodeVarInt(v))
        }
        put(Http3SettingsId.QPACK_MAX_TABLE_CAPACITY, 0)
        put(Http3SettingsId.QPACK_BLOCKED_STREAMS, 0)
        put(Http3SettingsId.MAX_FIELD_SECTION_SIZE, 262_144)
        put(Http3SettingsId.ENABLE_CONNECT_PROTOCOL, 1)
        put(Http3SettingsId.H3_DATAGRAM, 1)
        val payload = body.toByteArray()
        return encodeVarInt(Http3FrameType.SETTINGS) + encodeVarInt(payload.size.toLong()) + payload
    }

    /** Attempts to parse one frame. Returns (frame, totalBytes) or null if incomplete. */
    fun parseFrame(data: ByteArray, offset: Int = 0): Pair<Http3Frame, Int>? {
        var pos = offset
        val (type, typeLen) = decodeVarInt(data, pos) ?: return null
        pos += typeLen
        val (payloadLen, lenBytes) = decodeVarInt(data, pos) ?: return null
        pos += lenBytes
        val total = pos - offset + payloadLen.toInt()
        if (offset + total > data.size) return null
        val payload = data.copyOfRange(pos, pos + payloadLen.toInt())
        return Http3Frame(type, payload) to total
    }
}
