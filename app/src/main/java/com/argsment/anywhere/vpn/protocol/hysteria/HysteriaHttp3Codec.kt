package com.argsment.anywhere.vpn.protocol.hysteria

import com.argsment.anywhere.vpn.protocol.naive.http2.HpackHuffman

/**
 * Minimal QPACK / HTTP/3 frame helpers used by the Hysteria v2 /auth handshake.
 *
 * Direct port of iOS `HysteriaHTTP3Codec.swift`. Only encodes a single POST
 * request (HEADERS frame with a static-table-based block) and decodes the
 * subset of QPACK patterns the reference Hysteria server uses for the response.
 */
object HysteriaHttp3Codec {

    data class Header(val name: String, val value: String)

    // Static-table entries that may appear in /auth responses.
    private val ENTRY_BY_INDEX: Map<Int, Header> = mapOf(
        4 to Header("content-length", "0"),
        24 to Header(":status", "103"),
        25 to Header(":status", "200"),
        26 to Header(":status", "304"),
        27 to Header(":status", "404"),
        28 to Header(":status", "503"),
        63 to Header(":status", "100"),
        64 to Header(":status", "204"),
        65 to Header(":status", "206"),
        66 to Header(":status", "302"),
        67 to Header(":status", "400"),
        68 to Header(":status", "403"),
        69 to Header(":status", "421"),
        70 to Header(":status", "425"),
        71 to Header(":status", "500"),
    )

    private val NAME_BY_INDEX: Map<Int, String> = run {
        val m = HashMap<Int, String>()
        m[0] = ":authority"
        m[1] = ":path"
        m[4] = "content-length"
        m[6] = "date"
        for (i in intArrayOf(24, 25, 26, 27, 28, 63, 64, 65, 66, 67, 68, 69, 70, 71)) {
            m[i] = ":status"
        }
        m
    }

    // -- Request encoding --

    /** Builds a complete HTTP/3 HEADERS frame for a POST /auth request. */
    fun encodeAuthRequestFrame(
        authority: String,
        path: String,
        extraHeaders: List<Header>
    ): ByteArray {
        val block = java.io.ByteArrayOutputStream()
        block.write(0x00) // Required Insert Count = 0
        block.write(0x00) // S = 0, Delta Base = 0

        // :method = POST  — static table index 20
        block.write(indexedField(20))
        // :scheme = https — static table index 23
        block.write(indexedField(23))
        // :authority / :path — literal with static name ref
        block.write(literalWithNameRef(0, authority))
        block.write(literalWithNameRef(1, path))

        for (h in extraHeaders) {
            block.write(literalFieldLine(h.name, h.value))
        }

        val blockBytes = block.toByteArray()
        val frameType = encodeQuicVarInt(0x01)
        val lenBytes = encodeQuicVarInt(blockBytes.size.toLong())
        val out = ByteArray(frameType.size + lenBytes.size + blockBytes.size)
        var p = 0
        System.arraycopy(frameType, 0, out, p, frameType.size); p += frameType.size
        System.arraycopy(lenBytes, 0, out, p, lenBytes.size); p += lenBytes.size
        System.arraycopy(blockBytes, 0, out, p, blockBytes.size)
        return out
    }

    // -- Response decoding --

    /** Decodes a QPACK header block. Returns null on malformed input or
     *  references the dynamic table (which we advertise as size 0). */
    fun decodeHeaderBlock(data: ByteArray, start: Int = 0, end: Int = data.size): List<Header>? {
        if (end - start < 2) return null
        var offset = start

        // Required Insert Count (8-bit prefix). Must be 0 for our settings.
        val ric = decodePrefixedInt(data, offset, end, 8) ?: return null
        if (ric.value != 0L) return null
        offset += ric.consumed

        // Delta Base: sign bit + 7-bit prefix.
        if (offset >= end) return null
        val db = decodePrefixedInt(data, offset, end, 7) ?: return null
        offset += db.consumed

        val out = ArrayList<Header>()

        while (offset < end) {
            val byte = data[offset].toInt() and 0xFF
            when {
                byte and 0x80 != 0 -> {
                    // 1 T=? Index — Indexed field line. Dynamic refs rejected.
                    val isStatic = (byte and 0x40) != 0
                    if (!isStatic) return null
                    val idx = decodePrefixedInt(data, offset, end, 6) ?: return null
                    offset += idx.consumed
                    ENTRY_BY_INDEX[idx.value.toInt()]?.let { out.add(it) }
                }
                byte and 0x40 != 0 -> {
                    // 01 N T=? Index — Literal with name reference.
                    val isStatic = (byte and 0x10) != 0
                    if (!isStatic) return null
                    val nameIdx = decodePrefixedInt(data, offset, end, 4) ?: return null
                    offset += nameIdx.consumed
                    val v = decodeString(data, offset, end) ?: return null
                    offset += v.consumed
                    NAME_BY_INDEX[nameIdx.value.toInt()]?.let { name ->
                        out.add(Header(name, v.value))
                    }
                }
                byte and 0x20 != 0 -> {
                    // 001 N H — Literal field line with literal name.
                    val isHuffmanName = (byte and 0x08) != 0
                    val nameLen = decodePrefixedInt(data, offset, end, 3) ?: return null
                    offset += nameLen.consumed
                    val nl = nameLen.value.toInt()
                    if (offset + nl > end) return null
                    val nameBytes = data.copyOfRange(offset, offset + nl)
                    offset += nl
                    val name = if (isHuffmanName) {
                        HpackHuffman.decode(nameBytes)?.toString(Charsets.UTF_8) ?: return null
                    } else {
                        nameBytes.toString(Charsets.UTF_8)
                    }
                    val v = decodeString(data, offset, end) ?: return null
                    offset += v.consumed
                    out.add(Header(name.lowercase(), v.value))
                }
                else -> {
                    // Post-base patterns — dynamic table reference. We advertise 0,
                    // so this is a peer protocol error.
                    return null
                }
            }
        }
        return out
    }

    // -- Encoding helpers --

    private fun indexedField(staticIndex: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        appendPrefixedInt(out, staticIndex.toLong(), 6, 0xC0.toByte())
        return out.toByteArray()
    }

    private fun literalWithNameRef(staticIndex: Int, value: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        appendPrefixedInt(out, staticIndex.toLong(), 4, 0x50.toByte())
        appendString(out, value)
        return out.toByteArray()
    }

    private fun literalFieldLine(name: String, value: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        appendPrefixedInt(out, nameBytes.size.toLong(), 3, 0x20.toByte())
        out.write(nameBytes)
        appendString(out, value)
        return out.toByteArray()
    }

    private fun appendPrefixedInt(out: java.io.ByteArrayOutputStream, value: Long, prefixBits: Int, prefix: Byte) {
        val max = ((1 shl prefixBits) - 1).toLong()
        if (value < max) {
            out.write((prefix.toInt() or value.toInt()) and 0xFF)
            return
        }
        out.write((prefix.toInt() or max.toInt()) and 0xFF)
        var remaining = value - max
        while (remaining >= 128) {
            out.write(((remaining and 0x7F).toInt() or 0x80) and 0xFF)
            remaining = remaining shr 7
        }
        out.write(remaining.toInt() and 0xFF)
    }

    private fun appendString(out: java.io.ByteArrayOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        appendPrefixedInt(out, bytes.size.toLong(), 7, 0x00)
        out.write(bytes)
    }

    // -- Decoding helpers --

    private data class PrefixedInt(val value: Long, val consumed: Int)

    private fun decodePrefixedInt(data: ByteArray, offset: Int, end: Int, prefixBits: Int): PrefixedInt? {
        if (offset >= end) return null
        val mask = (1 shl prefixBits) - 1
        val first = data[offset].toInt() and mask
        if (first < mask) return PrefixedInt(first.toLong(), 1)

        var value = mask.toLong()
        var shift = 0L
        var pos = offset + 1
        while (pos < end) {
            val byte = data[pos].toInt() and 0xFF
            value += ((byte and 0x7F).toLong()) shl shift.toInt()
            pos += 1
            if ((byte and 0x80) == 0) {
                return PrefixedInt(value, pos - offset)
            }
            shift += 7
            if (shift > 63) return null
        }
        return null
    }

    private data class StringResult(val value: String, val consumed: Int)

    private fun decodeString(data: ByteArray, offset: Int, end: Int): StringResult? {
        if (offset >= end) return null
        val isHuffman = (data[offset].toInt() and 0x80) != 0
        val len = decodePrefixedInt(data, offset, end, 7) ?: return null
        val strStart = offset + len.consumed
        if (strStart + len.value.toInt() > end) return null
        val bytes = data.copyOfRange(strStart, strStart + len.value.toInt())
        val str = if (isHuffman) {
            HpackHuffman.decode(bytes)?.toString(Charsets.UTF_8) ?: return null
        } else {
            bytes.toString(Charsets.UTF_8)
        }
        return StringResult(str, len.consumed + len.value.toInt())
    }

    // -- QUIC varint --

    private fun encodeQuicVarInt(value: Long): ByteArray {
        return when {
            value < (1L shl 6) -> byteArrayOf(value.toByte())
            value < (1L shl 14) -> {
                val v = value or (0b01L shl 14)
                byteArrayOf(((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
            }
            value < (1L shl 30) -> {
                val v = value or (0b10L shl 30)
                byteArrayOf(
                    ((v shr 24) and 0xFF).toByte(), ((v shr 16) and 0xFF).toByte(),
                    ((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte()
                )
            }
            else -> {
                val v = value or (0b11L shl 62)
                byteArrayOf(
                    ((v shr 56) and 0xFF).toByte(), ((v shr 48) and 0xFF).toByte(),
                    ((v shr 40) and 0xFF).toByte(), ((v shr 32) and 0xFF).toByte(),
                    ((v shr 24) and 0xFF).toByte(), ((v shr 16) and 0xFF).toByte(),
                    ((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte()
                )
            }
        }
    }
}
