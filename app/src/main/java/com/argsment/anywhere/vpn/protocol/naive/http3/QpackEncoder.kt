package com.argsment.anywhere.vpn.protocol.naive.http3

import com.argsment.anywhere.vpn.protocol.naive.http2.HpackHuffman

/**
 * Minimal QPACK encoder/decoder used by HTTP/3 CONNECT requests. We advertise
 * `QPACK_MAX_TABLE_CAPACITY = 0` in SETTINGS so no dynamic table support is
 * needed — only static references and literal encodings.
 *
 * Mirrors the iOS `QPACKEncoder.swift`.
 */
object QpackEncoder {

    private const val STATIC_METHOD_CONNECT = 15
    private const val STATIC_METHOD_POST = 20
    private const val STATIC_SCHEME_HTTPS = 23

    fun encodeConnectHeaders(
        authority: String,
        protocolPseudo: String? = null,
        path: String? = null,
        extraHeaders: List<Pair<String, String>> = emptyList()
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        // QPACK prefix: Required Insert Count = 0, Delta Base = 0
        out.write(0); out.write(0)

        // :method = CONNECT
        out.write(encodeIndexedFieldLine(STATIC_METHOD_CONNECT))

        if (protocolPseudo != null) {
            // Extended CONNECT (RFC 9220 §3 / RFC 9298 §3)
            out.write(encodeLiteralFieldLine(":protocol", protocolPseudo))
            out.write(encodeIndexedFieldLine(STATIC_SCHEME_HTTPS))
            out.write(encodeLiteralWithNameRef(1, path ?: "/"))
        }

        // :authority = host:port
        out.write(encodeLiteralWithNameRef(0, authority))

        for ((n, v) in extraHeaders) out.write(encodeLiteralFieldLine(n, v))
        return out.toByteArray()
    }

    fun encodePostHeaders(
        authority: String,
        path: String,
        extraHeaders: List<Pair<String, String>> = emptyList()
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(0); out.write(0)
        out.write(encodeIndexedFieldLine(STATIC_METHOD_POST))
        out.write(encodeIndexedFieldLine(STATIC_SCHEME_HTTPS))
        out.write(encodeLiteralWithNameRef(0, authority))
        out.write(encodeLiteralWithNameRef(1, path))
        for ((n, v) in extraHeaders) out.write(encodeLiteralFieldLine(n, v))
        return out.toByteArray()
    }

    /** Decode a QPACK header block into (name, value) pairs. Returns null on invalid/malformed input. */
    fun decodeHeaders(data: ByteArray): List<Pair<String, String>>? {
        if (data.size < 2) return null
        var offset = 0

        // Required Insert Count (must be 0 since dynamic table disabled)
        val (ric, ricLen) = decodeVarIntPrefix(data, offset, 8) ?: return null
        offset += ricLen
        if (ric != 0L) return null

        if (offset >= data.size) return null
        val (_, dbLen) = decodeVarIntPrefix(data, offset, 7) ?: return null
        offset += dbLen

        val headers = mutableListOf<Pair<String, String>>()
        while (offset < data.size) {
            val b = data[offset].toInt() and 0xFF
            when {
                b and 0x80 != 0 -> {
                    // Indexed field line: 1 T index(6+)
                    val isStatic = (b and 0x40) != 0
                    if (!isStatic) return null
                    val (idx, len) = decodeVarIntPrefix(data, offset, 6) ?: return null
                    offset += len
                    staticTableEntry(idx.toInt())?.let { headers.add(it) }
                }
                b and 0x40 != 0 -> {
                    // Literal with name ref: 01 N T nameIdx(4+) value
                    val isStatic = (b and 0x10) != 0
                    if (!isStatic) return null
                    val (nameIdx, nameIdxLen) = decodeVarIntPrefix(data, offset, 4) ?: return null
                    offset += nameIdxLen
                    val (value, vLen) = decodeString(data, offset) ?: return null
                    offset += vLen
                    staticTableName(nameIdx.toInt())?.let { headers.add(it to value) }
                }
                b and 0x20 != 0 -> {
                    // Literal with literal name: 001 N H nameLen(3+) name value
                    val huffmanName = (b and 0x08) != 0
                    val (nameLen, nLenBytes) = decodeVarIntPrefix(data, offset, 3) ?: return null
                    offset += nLenBytes
                    if (offset + nameLen.toInt() > data.size) return null
                    val nameData = data.copyOfRange(offset, offset + nameLen.toInt())
                    offset += nameLen.toInt()
                    val name = if (huffmanName) {
                        HpackHuffman.decode(nameData)?.toString(Charsets.UTF_8) ?: return null
                    } else {
                        String(nameData, Charsets.UTF_8)
                    }
                    val (value, vLen) = decodeString(data, offset) ?: return null
                    offset += vLen
                    headers.add(name to value)
                }
                else -> return null // post-base (dynamic table) references
            }
        }
        return headers
    }

    // -- Encoding helpers --

    private fun encodeIndexedFieldLine(index: Int): ByteArray =
        encodeVarIntPrefix(index.toLong(), 6, 0xC0)

    private fun encodeLiteralWithNameRef(staticIndex: Int, value: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(encodeVarIntPrefix(staticIndex.toLong(), 4, 0x50))
        out.write(encodeStringLiteral(value))
        return out.toByteArray()
    }

    private fun encodeLiteralFieldLine(name: String, value: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val nameBytes = name.lowercase().toByteArray(Charsets.UTF_8)
        out.write(encodeVarIntPrefix(nameBytes.size.toLong(), 3, 0x20))
        out.write(nameBytes)
        out.write(encodeStringLiteral(value))
        return out.toByteArray()
    }

    private fun encodeStringLiteral(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val out = java.io.ByteArrayOutputStream()
        out.write(encodeVarIntPrefix(bytes.size.toLong(), 7, 0x00))
        out.write(bytes)
        return out.toByteArray()
    }

    private fun encodeVarIntPrefix(value: Long, prefixBits: Int, prefix: Int): ByteArray {
        val maxPrefix = (1 shl prefixBits) - 1
        val out = java.io.ByteArrayOutputStream()
        if (value < maxPrefix) {
            out.write((prefix or value.toInt()) and 0xFF)
        } else {
            out.write((prefix or maxPrefix) and 0xFF)
            var remaining = value - maxPrefix
            while (remaining >= 128) {
                out.write(((remaining.toInt() and 0x7F) or 0x80) and 0xFF)
                remaining = remaining ushr 7
            }
            out.write(remaining.toInt() and 0xFF)
        }
        return out.toByteArray()
    }

    // -- Decoding helpers --

    private fun decodeVarIntPrefix(data: ByteArray, offset: Int, prefixBits: Int): Pair<Long, Int>? {
        if (offset >= data.size) return null
        val mask = (1 shl prefixBits) - 1
        val first = data[offset].toInt() and mask
        if (first < mask) return first.toLong() to 1
        var value = mask.toLong()
        var shift = 0
        var pos = offset + 1
        while (pos < data.size) {
            val b = data[pos].toInt() and 0xFF
            value += (b and 0x7F).toLong() shl shift
            pos++
            if (b and 0x80 == 0) return value to (pos - offset)
            shift += 7
        }
        return null
    }

    private fun decodeString(data: ByteArray, offset: Int): Pair<String, Int>? {
        val (length, lenBytes) = decodeVarIntPrefix(data, offset, 7) ?: return null
        val huffman = (data[offset].toInt() and 0x80) != 0
        val start = offset + lenBytes
        if (start + length.toInt() > data.size) return null
        val bytes = data.copyOfRange(start, start + length.toInt())
        val s = if (huffman) {
            HpackHuffman.decode(bytes)?.toString(Charsets.UTF_8) ?: return null
        } else {
            String(bytes, Charsets.UTF_8)
        }
        return s to (lenBytes + length.toInt())
    }

    // -- Static table (partial) --

    private fun staticTableEntry(index: Int): Pair<String, String>? = when (index) {
        0 -> ":authority" to ""
        1 -> ":path" to "/"
        15 -> ":method" to "CONNECT"
        16 -> ":method" to "DELETE"
        17 -> ":method" to "GET"
        18 -> ":method" to "HEAD"
        19 -> ":method" to "OPTIONS"
        20 -> ":method" to "POST"
        21 -> ":method" to "PUT"
        22 -> ":scheme" to "http"
        23 -> ":scheme" to "https"
        24 -> ":status" to "103"
        25 -> ":status" to "200"
        26 -> ":status" to "204"
        27 -> ":status" to "206"
        28 -> ":status" to "304"
        29 -> ":status" to "400"
        30 -> ":status" to "403"
        31 -> ":status" to "404"
        32 -> ":status" to "421"
        33 -> ":status" to "425"
        34 -> ":status" to "500"
        else -> null
    }

    private fun staticTableName(index: Int): String? = when (index) {
        0 -> ":authority"
        1 -> ":path"
        2 -> "age"
        3 -> "content-disposition"
        4 -> "content-length"
        5 -> "cookie"
        6 -> "date"
        7 -> "etag"
        8 -> "if-modified-since"
        9 -> "if-none-match"
        10 -> "last-modified"
        11 -> "link"
        12 -> "location"
        13 -> "referer"
        14 -> "set-cookie"
        15, 16, 17, 18, 19, 20, 21 -> ":method"
        22, 23 -> ":scheme"
        24, 25 -> ":status"
        else -> null
    }
}
