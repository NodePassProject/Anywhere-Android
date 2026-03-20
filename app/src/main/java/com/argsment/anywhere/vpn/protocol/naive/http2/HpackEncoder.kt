package com.argsment.anywhere.vpn.protocol.naive.http2

import java.io.ByteArrayOutputStream

/**
 * Minimal HPACK encoder/decoder for the NaiveProxy CONNECT tunnel.
 *
 * Only implements the subset needed for a single CONNECT request/response:
 * - Integer encoding/decoding (RFC 7541 §5.1)
 * - String encoding (raw only) and decoding (raw + Huffman)
 * - Indexed header field (1xxxxxxx)
 * - Literal without indexing (0000xxxx)
 * - Literal with incremental indexing (01xxxxxx) — decode only
 * - Static table lookup
 */
object HpackEncoder {

    // -- CONNECT Request Encoding --

    /**
     * Encodes an HTTP/2 CONNECT request header block.
     *
     * Produces HPACK-encoded headers:
     * - `:method = CONNECT` (literal with indexed name, static index 2)
     * - `:authority = <authority>` (literal with indexed name, static index 1)
     * - Extra headers (proxy-authorization, padding, etc.)
     */
    fun encodeConnectRequest(
        authority: String,
        extraHeaders: List<Pair<String, String>>
    ): ByteArray {
        val block = ByteArrayOutputStream()
        // :method = CONNECT — literal without indexing, name index 2 (:method)
        encodeLiteralWithoutIndexing(nameIndex = 2, value = "CONNECT", into = block)
        // :authority = host:port — literal without indexing, name index 1 (:authority)
        encodeLiteralWithoutIndexing(nameIndex = 1, value = authority, into = block)
        // Extra headers
        for ((name, value) in extraHeaders) {
            val nameIdx = staticTableNameIndex(name)
            if (nameIdx != null) {
                encodeLiteralWithoutIndexing(nameIndex = nameIdx, value = value, into = block)
            } else {
                encodeLiteralWithoutIndexing(name = name, value = value, into = block)
            }
        }
        return block.toByteArray()
    }

    // -- Response Decoding --

    /**
     * Decodes an HPACK header block into name-value pairs.
     *
     * Handles indexed, literal with/without indexing, and dynamic table size updates.
     * Maintains a local dynamic table for the duration of the decode.
     */
    fun decodeHeaders(data: ByteArray): List<Pair<String, String>>? {
        val headers = mutableListOf<Pair<String, String>>()
        val offset = intArrayOf(0)
        val dynamicTable = mutableListOf<Pair<String, String>>()

        while (offset[0] < data.size) {
            val byte = data[offset[0]].toInt() and 0xFF

            when {
                byte and 0x80 != 0 -> {
                    // §6.1 Indexed Header Field (1xxxxxxx)
                    val index = decodeInteger(data, offset, 7) ?: return null
                    val entry = lookupEntry(index, dynamicTable) ?: return null
                    headers.add(entry)
                }

                byte and 0xC0 == 0x40 -> {
                    // §6.2.1 Literal with Incremental Indexing (01xxxxxx)
                    val (name, value) = decodeLiteral(data, offset, 6, dynamicTable) ?: return null
                    headers.add(name to value)
                    dynamicTable.add(0, name to value)
                }

                byte and 0xF0 == 0x00 || byte and 0xF0 == 0x10 -> {
                    // §6.2.2/§6.2.3 Literal without Indexing / Never Indexed
                    val (name, value) = decodeLiteral(data, offset, 4, dynamicTable) ?: return null
                    headers.add(name to value)
                }

                byte and 0xE0 == 0x20 -> {
                    // §6.3 Dynamic Table Size Update (001xxxxx)
                    decodeInteger(data, offset, 5) // consume but don't enforce
                }

                else -> return null  // Unknown representation
            }
        }

        return headers
    }

    // -- Integer Encoding (RFC 7541 §5.1) --

    /**
     * Encodes an integer with the given prefix bit width, appending to [data].
     */
    private fun encodeInteger(value: Int, prefixBits: Int, into: ByteArrayOutputStream) {
        val maxPrefix = (1 shl prefixBits) - 1
        if (value < maxPrefix) {
            into.write(value)
        } else {
            into.write(maxPrefix)
            var remaining = value - maxPrefix
            while (remaining >= 128) {
                into.write(remaining % 128 + 128)
                remaining /= 128
            }
            into.write(remaining)
        }
    }

    /**
     * Decodes an integer with the given prefix bit width from [data] at [offset].
     * Advances [offset] past the consumed bytes.
     */
    private fun decodeInteger(data: ByteArray, offset: IntArray, prefixBits: Int): Int? {
        if (offset[0] >= data.size) return null
        val maxPrefix = (1 shl prefixBits) - 1
        var value = data[offset[0]].toInt() and maxPrefix
        offset[0]++

        if (value < maxPrefix) {
            return value
        }

        var m = 0
        do {
            if (offset[0] >= data.size) return null
            val b = data[offset[0]].toInt() and 0xFF
            offset[0]++
            value += (b and 0x7F) shl m
            m += 7
            if (b and 0x80 == 0) break
        } while (true)

        return value
    }

    // -- String Encoding (RFC 7541 §5.2) --

    /** Encodes a string in raw (non-Huffman) format. */
    private fun encodeString(string: String, into: ByteArrayOutputStream) {
        val bytes = string.toByteArray(Charsets.UTF_8)
        // H=0 (raw), length
        val lengthBuf = ByteArrayOutputStream()
        encodeInteger(bytes.size, 7, lengthBuf)
        val lengthBytes = lengthBuf.toByteArray()
        lengthBytes[0] = (lengthBytes[0].toInt() and 0x7F).toByte() // Clear H bit
        into.write(lengthBytes)
        into.write(bytes)
    }

    /** Decodes a string (raw or Huffman) from [data] at [offset]. */
    private fun decodeString(data: ByteArray, offset: IntArray): String? {
        if (offset[0] >= data.size) return null
        val huffman = data[offset[0]].toInt() and 0x80 != 0
        val length = decodeInteger(data, offset, 7) ?: return null
        if (offset[0] + length > data.size) return null

        val stringData = data.copyOfRange(offset[0], offset[0] + length)
        offset[0] += length

        return if (huffman) {
            val decoded = HpackHuffman.decode(stringData) ?: return null
            String(decoded, Charsets.UTF_8)
        } else {
            String(stringData, Charsets.UTF_8)
        }
    }

    // -- Literal Header Encoding --

    /** Encodes a literal header without indexing, using an indexed name from the static table. */
    private fun encodeLiteralWithoutIndexing(nameIndex: Int, value: String, into: ByteArrayOutputStream) {
        // 0000xxxx prefix + name index
        val indexBuf = ByteArrayOutputStream()
        encodeInteger(nameIndex, 4, indexBuf)
        val indexBytes = indexBuf.toByteArray()
        indexBytes[0] = (indexBytes[0].toInt() and 0x0F).toByte() // Ensure 0000 prefix
        into.write(indexBytes)
        encodeString(value, into)
    }

    /** Encodes a literal header without indexing, using a literal name. */
    private fun encodeLiteralWithoutIndexing(name: String, value: String, into: ByteArrayOutputStream) {
        into.write(0x00) // 0000 0000 — literal name, no indexing
        encodeString(name, into)
        encodeString(value, into)
    }

    // -- Literal Header Decoding --

    private fun decodeLiteral(
        data: ByteArray,
        offset: IntArray,
        prefixBits: Int,
        dynamicTable: List<Pair<String, String>>
    ): Pair<String, String>? {
        val nameIndex = decodeInteger(data, offset, prefixBits) ?: return null

        val name: String = if (nameIndex == 0) {
            decodeString(data, offset) ?: return null
        } else {
            val entry = lookupEntry(nameIndex, dynamicTable) ?: return null
            entry.first
        }

        val value = decodeString(data, offset) ?: return null
        return name to value
    }

    // -- Table Lookup --

    /**
     * Looks up a header by index (1-based). Static table is indices 1–61,
     * dynamic table starts at 62.
     */
    private fun lookupEntry(
        index: Int,
        dynamicTable: List<Pair<String, String>>
    ): Pair<String, String>? {
        if (index < 1) return null
        if (index <= STATIC_TABLE.size) {
            return STATIC_TABLE[index - 1]
        }
        val dynIndex = index - STATIC_TABLE.size - 1
        if (dynIndex >= dynamicTable.size) return null
        return dynamicTable[dynIndex]
    }

    /** Returns the first static table index whose name matches (case-insensitive), or null. */
    private fun staticTableNameIndex(name: String): Int? {
        val lower = name.lowercase()
        for ((i, entry) in STATIC_TABLE.withIndex()) {
            if (entry.first == lower) return i + 1 // 1-based
        }
        return null
    }

    // -- HPACK Static Table (RFC 7541 Appendix A) --

    // -- HPACK Static Table (accessible to HpackDecoder) --

    internal val STATIC_TABLE: List<Pair<String, String>> = listOf(
        ":authority" to "",                          // 1
        ":method" to "GET",                          // 2
        ":method" to "POST",                         // 3
        ":path" to "/",                              // 4
        ":path" to "/index.html",                    // 5
        ":scheme" to "http",                         // 6
        ":scheme" to "https",                        // 7
        ":status" to "200",                          // 8
        ":status" to "204",                          // 9
        ":status" to "206",                          // 10
        ":status" to "304",                          // 11
        ":status" to "400",                          // 12
        ":status" to "404",                          // 13
        ":status" to "500",                          // 14
        "accept-charset" to "",                      // 15
        "accept-encoding" to "gzip, deflate",        // 16
        "accept-language" to "",                     // 17
        "accept-ranges" to "",                       // 18
        "accept" to "",                              // 19
        "access-control-allow-origin" to "",         // 20
        "age" to "",                                 // 21
        "allow" to "",                               // 22
        "authorization" to "",                       // 23
        "cache-control" to "",                       // 24
        "content-disposition" to "",                 // 25
        "content-encoding" to "",                    // 26
        "content-language" to "",                    // 27
        "content-length" to "",                      // 28
        "content-location" to "",                    // 29
        "content-range" to "",                       // 30
        "content-type" to "",                        // 31
        "cookie" to "",                              // 32
        "date" to "",                                // 33
        "etag" to "",                                // 34
        "expect" to "",                              // 35
        "expires" to "",                             // 36
        "from" to "",                                // 37
        "host" to "",                                // 38
        "if-match" to "",                            // 39
        "if-modified-since" to "",                   // 40
        "if-none-match" to "",                       // 41
        "if-range" to "",                            // 42
        "if-unmodified-since" to "",                 // 43
        "last-modified" to "",                       // 44
        "link" to "",                                // 45
        "location" to "",                            // 46
        "max-forwards" to "",                        // 47
        "proxy-authenticate" to "",                  // 48
        "proxy-authorization" to "",                 // 49
        "range" to "",                               // 50
        "referer" to "",                             // 51
        "refresh" to "",                             // 52
        "retry-after" to "",                         // 53
        "server" to "",                              // 54
        "set-cookie" to "",                          // 55
        "strict-transport-security" to "",           // 56
        "transfer-encoding" to "",                   // 57
        "user-agent" to "",                          // 58
        "vary" to "",                                // 59
        "via" to "",                                 // 60
        "www-authenticate" to "",                    // 61
    )
}

// -- HPACK Huffman Decoder --

/** Huffman decoder for HPACK string literals (RFC 7541 Appendix B). */
object HpackHuffman {

    /** Trie node for Huffman decoding. */
    private class Node {
        var left: Int = -1
        var right: Int = -1
        var symbol: Int = -1  // >= 0 for leaf nodes, 256 = EOS
    }

    /** Lazily-built decode trie. */
    private val tree: Array<Node> by lazy { buildTree() }

    private fun buildTree(): Array<Node> {
        val nodes = mutableListOf(Node())
        for ((sym, entry) in HUFFMAN_TABLE.withIndex()) {
            val (code, bits) = entry
            var idx = 0
            for (bitPos in 0 until bits) {
                val bit = (code.toInt() shr (31 - bitPos)) and 1
                if (bit == 0) {
                    if (nodes[idx].left < 0) {
                        nodes.add(Node())
                        nodes[idx].left = nodes.size - 1
                    }
                    idx = nodes[idx].left
                } else {
                    if (nodes[idx].right < 0) {
                        nodes.add(Node())
                        nodes[idx].right = nodes.size - 1
                    }
                    idx = nodes[idx].right
                }
            }
            nodes[idx].symbol = sym
        }
        return nodes.toTypedArray()
    }

    /** Decodes Huffman-encoded bytes into raw bytes. */
    fun decode(data: ByteArray): ByteArray? {
        val result = ByteArrayOutputStream()
        var nodeIdx = 0

        for (byte in data) {
            for (bitPos in 7 downTo 0) {
                val bit = (byte.toInt() shr bitPos) and 1
                val next = if (bit == 0) tree[nodeIdx].left else tree[nodeIdx].right
                if (next < 0) return null
                nodeIdx = next

                val sym = tree[nodeIdx].symbol
                if (sym >= 0) {
                    if (sym == 256) return result.toByteArray() // EOS
                    result.write(sym)
                    nodeIdx = 0
                }
            }
        }

        return result.toByteArray()
    }

    // -- Huffman Code Table (RFC 7541 Appendix B) --
    // Each entry is (code: UInt left-aligned, bitLength: Int).
    // Indexed by symbol value 0–256 (256 = EOS).

    private val HUFFMAN_TABLE: Array<Pair<UInt, Int>> = arrayOf(
        0xffc00000u to 13, 0xffffb000u to 23, 0xfffffe20u to 28, 0xfffffe30u to 28,
        0xfffffe40u to 28, 0xfffffe50u to 28, 0xfffffe60u to 28, 0xfffffe70u to 28,
        0xfffffe80u to 28, 0xffffea00u to 24, 0xfffffff0u to 30, 0xfffffe90u to 28,
        0xfffffea0u to 28, 0xfffffff4u to 30, 0xfffffeb0u to 28, 0xfffffec0u to 28,
        0xfffffed0u to 28, 0xfffffee0u to 28, 0xfffffef0u to 28, 0xffffff00u to 28,
        0xffffff10u to 28, 0xffffff20u to 28, 0xfffffff8u to 30, 0xffffff30u to 28,
        0xffffff40u to 28, 0xffffff50u to 28, 0xffffff60u to 28, 0xffffff70u to 28,
        0xffffff80u to 28, 0xffffff90u to 28, 0xffffffa0u to 28, 0xffffffb0u to 28,
        // 32–63: printable ASCII
        0x50000000u to 6, 0xfe000000u to 10, 0xfe400000u to 10, 0xffa00000u to 12,
        0xffc80000u to 13, 0x54000000u to 6, 0xf8000000u to 8, 0xff400000u to 11,
        0xfe800000u to 10, 0xfec00000u to 10, 0xf9000000u to 8, 0xff600000u to 11,
        0xfa000000u to 8, 0x58000000u to 6, 0x5c000000u to 6, 0x60000000u to 6,
        0x00000000u to 5, 0x08000000u to 5, 0x10000000u to 5, 0x64000000u to 6,
        0x68000000u to 6, 0x6c000000u to 6, 0x70000000u to 6, 0x74000000u to 6,
        0x78000000u to 6, 0x7c000000u to 6, 0xb8000000u to 7, 0xfb000000u to 8,
        0xfff80000u to 15, 0x80000000u to 6, 0xffb00000u to 12, 0xff000000u to 10,
        // 64–95
        0xffd00000u to 13, 0x84000000u to 6, 0xba000000u to 7, 0xbc000000u to 7,
        0xbe000000u to 7, 0xc0000000u to 7, 0xc2000000u to 7, 0xc4000000u to 7,
        0xc6000000u to 7, 0xc8000000u to 7, 0xca000000u to 7, 0xcc000000u to 7,
        0xce000000u to 7, 0xd0000000u to 7, 0xd2000000u to 7, 0xd4000000u to 7,
        0xd6000000u to 7, 0xd8000000u to 7, 0xda000000u to 7, 0xdc000000u to 7,
        0xde000000u to 7, 0xe0000000u to 7, 0xe2000000u to 7, 0xe4000000u to 7,
        0xfc000000u to 8, 0xe6000000u to 7, 0xfd000000u to 8, 0xffd80000u to 13,
        0xfffe0000u to 19, 0xffe00000u to 13, 0xfff00000u to 14, 0x88000000u to 6,
        // 96–127
        0xfffa0000u to 15, 0x18000000u to 5, 0x8c000000u to 6, 0x20000000u to 5,
        0x90000000u to 6, 0x28000000u to 5, 0x94000000u to 6, 0x98000000u to 6,
        0x9c000000u to 6, 0x30000000u to 5, 0xe8000000u to 7, 0xea000000u to 7,
        0xa0000000u to 6, 0xa4000000u to 6, 0xa8000000u to 6, 0x38000000u to 5,
        0xac000000u to 6, 0xec000000u to 7, 0xb0000000u to 6, 0x40000000u to 5,
        0x48000000u to 5, 0xb4000000u to 6, 0xee000000u to 7, 0xf0000000u to 7,
        0xf2000000u to 7, 0xf4000000u to 7, 0xf6000000u to 7, 0xfffc0000u to 15,
        0xff800000u to 11, 0xfff40000u to 14, 0xffe80000u to 13, 0xffffffc0u to 28,
        // 128–159
        0xfffe6000u to 20, 0xffff4800u to 22, 0xfffe7000u to 20, 0xfffe8000u to 20,
        0xffff4c00u to 22, 0xffff5000u to 22, 0xffff5400u to 22, 0xffffb200u to 23,
        0xffff5800u to 22, 0xffffb400u to 23, 0xffffb600u to 23, 0xffffb800u to 23,
        0xffffba00u to 23, 0xffffbc00u to 23, 0xffffeb00u to 24, 0xffffbe00u to 23,
        0xffffec00u to 24, 0xffffed00u to 24, 0xffff5c00u to 22, 0xffffc000u to 23,
        0xffffee00u to 24, 0xffffc200u to 23, 0xffffc400u to 23, 0xffffc600u to 23,
        0xffffc800u to 23, 0xfffee000u to 21, 0xffff6000u to 22, 0xffffca00u to 23,
        0xffff6400u to 22, 0xffffcc00u to 23, 0xffffce00u to 23, 0xffffef00u to 24,
        // 160–191
        0xffff6800u to 22, 0xfffee800u to 21, 0xfffe9000u to 20, 0xffff6c00u to 22,
        0xffff7000u to 22, 0xffffd000u to 23, 0xffffd200u to 23, 0xfffef000u to 21,
        0xffffd400u to 23, 0xffff7400u to 22, 0xffff7800u to 22, 0xfffff000u to 24,
        0xfffef800u to 21, 0xffff7c00u to 22, 0xffffd600u to 23, 0xffffd800u to 23,
        0xffff0000u to 21, 0xffff0800u to 21, 0xffff8000u to 22, 0xffff1000u to 21,
        0xffffda00u to 23, 0xffff8400u to 22, 0xffffdc00u to 23, 0xffffde00u to 23,
        0xfffea000u to 20, 0xffff8800u to 22, 0xffff8c00u to 22, 0xffff9000u to 22,
        0xffffe000u to 23, 0xffff9400u to 22, 0xffff9800u to 22, 0xffffe200u to 23,
        // 192–223
        0xfffff800u to 26, 0xfffff840u to 26, 0xfffeb000u to 20, 0xfffe2000u to 19,
        0xffff9c00u to 22, 0xffffe400u to 23, 0xffffa000u to 22, 0xfffff600u to 25,
        0xfffff880u to 26, 0xfffff8c0u to 26, 0xfffff900u to 26, 0xfffffbc0u to 27,
        0xfffffbe0u to 27, 0xfffff940u to 26, 0xfffff100u to 24, 0xfffff680u to 25,
        0xfffe4000u to 19, 0xffff1800u to 21, 0xfffff980u to 26, 0xfffffc00u to 27,
        0xfffffc20u to 27, 0xfffff9c0u to 26, 0xfffffc40u to 27, 0xfffff200u to 24,
        0xffff2000u to 21, 0xffff2800u to 21, 0xfffffa00u to 26, 0xfffffa40u to 26,
        0xffffffd0u to 28, 0xfffffc60u to 27, 0xfffffc80u to 27, 0xfffffca0u to 27,
        // 224–256 (256 = EOS)
        0xfffec000u to 20, 0xfffff300u to 24, 0xfffed000u to 20, 0xffff3000u to 21,
        0xffffa400u to 22, 0xffff3800u to 21, 0xffff4000u to 21, 0xffffe600u to 23,
        0xffffa800u to 22, 0xffffac00u to 22, 0xfffff700u to 25, 0xfffff780u to 25,
        0xfffff400u to 24, 0xfffff500u to 24, 0xfffffa80u to 26, 0xffffe800u to 23,
        0xfffffac0u to 26, 0xfffffcc0u to 27, 0xfffffb00u to 26, 0xfffffb40u to 26,
        0xfffffce0u to 27, 0xfffffd00u to 27, 0xfffffd20u to 27, 0xfffffd40u to 27,
        0xfffffd60u to 27, 0xffffffe0u to 28, 0xfffffd80u to 27, 0xfffffda0u to 27,
        0xfffffdc0u to 27, 0xfffffde0u to 27, 0xfffffe00u to 27, 0xfffffb80u to 26,
        0xfffffffcu to 30,  // 256 = EOS
    )
}

/**
 * Stateful HPACK decoder with persistent dynamic table across calls.
 *
 * Used by [Http2Session] for multiplexed streams where the dynamic table must persist
 * across multiple HEADERS frames on the same connection (RFC 7541 §2.3.3).
 * The legacy [HpackEncoder.decodeHeaders] creates a fresh table per call, which is
 * correct only for single-stream connections like [Http2Connection].
 */
class HpackDecoder {
    private val dynamicTable = mutableListOf<Pair<String, String>>()
    private val staticTable = HpackEncoder.STATIC_TABLE

    fun decode(data: ByteArray): List<Pair<String, String>>? {
        val headers = mutableListOf<Pair<String, String>>()
        val offset = intArrayOf(0)

        while (offset[0] < data.size) {
            val byte = data[offset[0]].toInt() and 0xFF

            when {
                byte and 0x80 != 0 -> {
                    // §6.1 Indexed Header Field
                    val index = decodeInteger(data, offset, 7) ?: return null
                    val entry = lookupEntry(index) ?: return null
                    headers.add(entry)
                }

                byte and 0xC0 == 0x40 -> {
                    // §6.2.1 Literal with Incremental Indexing
                    val (name, value) = decodeLiteral(data, offset, 6) ?: return null
                    headers.add(name to value)
                    dynamicTable.add(0, name to value)
                }

                byte and 0xF0 == 0x00 || byte and 0xF0 == 0x10 -> {
                    // §6.2.2/§6.2.3 Literal without Indexing / Never Indexed
                    val (name, value) = decodeLiteral(data, offset, 4) ?: return null
                    headers.add(name to value)
                }

                byte and 0xE0 == 0x20 -> {
                    // §6.3 Dynamic Table Size Update
                    decodeInteger(data, offset, 5)
                }

                else -> return null
            }
        }

        return headers
    }

    fun reset() {
        dynamicTable.clear()
    }

    private fun lookupEntry(index: Int): Pair<String, String>? {
        if (index < 1) return null
        if (index <= staticTable.size) return staticTable[index - 1]
        val dynIndex = index - staticTable.size - 1
        if (dynIndex >= dynamicTable.size) return null
        return dynamicTable[dynIndex]
    }

    private fun decodeLiteral(data: ByteArray, offset: IntArray, prefixBits: Int): Pair<String, String>? {
        val nameIndex = decodeInteger(data, offset, prefixBits) ?: return null
        val name = if (nameIndex == 0) {
            decodeString(data, offset) ?: return null
        } else {
            val entry = lookupEntry(nameIndex) ?: return null
            entry.first
        }
        val value = decodeString(data, offset) ?: return null
        return name to value
    }

    private fun decodeInteger(data: ByteArray, offset: IntArray, prefixBits: Int): Int? {
        if (offset[0] >= data.size) return null
        val maxPrefix = (1 shl prefixBits) - 1
        var value = data[offset[0]].toInt() and maxPrefix
        offset[0]++
        if (value < maxPrefix) return value

        var m = 0
        do {
            if (offset[0] >= data.size) return null
            val b = data[offset[0]].toInt() and 0xFF
            offset[0]++
            value += (b and 0x7F) shl m
            m += 7
            if (b and 0x80 == 0) break
        } while (true)

        return value
    }

    private fun decodeString(data: ByteArray, offset: IntArray): String? {
        if (offset[0] >= data.size) return null
        val huffman = data[offset[0]].toInt() and 0x80 != 0
        val length = decodeInteger(data, offset, 7) ?: return null
        if (offset[0] + length > data.size) return null
        val stringData = data.copyOfRange(offset[0], offset[0] + length)
        offset[0] += length
        return if (huffman) {
            val decoded = HpackHuffman.decode(stringData) ?: return null
            String(decoded, Charsets.UTF_8)
        } else {
            String(stringData, Charsets.UTF_8)
        }
    }
}
