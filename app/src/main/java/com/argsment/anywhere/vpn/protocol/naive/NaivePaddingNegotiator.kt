package com.argsment.anywhere.vpn.protocol.naive

import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * Handles NaiveProxy padding header generation and response parsing.
 */
object NaivePaddingNegotiator {

    enum class PaddingType(val value: Int) {
        NONE(0),
        VARIANT1(1)
    }

    /**
     * The 17 printable ASCII characters (0x20–0x7f) whose HPACK Huffman codes are >= 8 bits,
     * iterated in Huffman table order. Used to generate padding header values that cannot be
     * compactly indexed by HPACK.
     *
     * Characters: ! " # $ & ' ( ) * + , ; < > ? @ X
     */
    private val nonIndexCodes = byteArrayOf(
        0x21, // '!'
        0x22, // '"'
        0x23, // '#'
        0x24, // '$'
        0x26, // '&'
        0x27, // '''
        0x28, // '('
        0x29, // ')'
        0x2A, // '*'
        0x2B, // '+'
        0x2C, // ','
        0x3B, // ';'
        0x3C, // '<'
        0x3E, // '>'
        0x3F, // '?'
        0x40, // '@'
        0x58, // 'X'
    )

    /**
     * Generates a random padding header value of 16–32 non-indexed characters.
     *
     * The first 16 characters are selected using 4-bit chunks from a random 64-bit value
     * (indexing into the first 16 entries of [nonIndexCodes]). Remaining characters use
     * the 17th entry ('X').
     */
    fun generatePaddingValue(): String {
        val length = Random.nextInt(16, 33)
        var uniqueBits = Random.nextLong()
        val chars = ByteArray(length)

        val first = minOf(length, 16)
        for (i in 0 until first) {
            chars[i] = nonIndexCodes[(uniqueBits and 0b1111).toInt()]
            uniqueBits = uniqueBits ushr 4
        }
        for (i in first until length) {
            chars[i] = nonIndexCodes[16]
        }

        return String(chars, Charsets.US_ASCII)
    }

    /**
     * Generates the padding-related headers for a CONNECT request. When [fastOpen] is true,
     * includes `fastopen: 1` (used when the server's padding type is cached from a prior
     * connection).
     */
    fun requestHeaders(fastOpen: Boolean = false): List<Pair<String, String>> {
        val headers = mutableListOf<Pair<String, String>>()
        headers.add("padding" to generatePaddingValue())
        headers.add("padding-type-request" to "1, 0")
        if (fastOpen) {
            headers.add("fastopen" to "1")
        }
        return headers
    }

    /**
     * Caches negotiated padding types per server so subsequent connections can send
     * `fastopen: 1` and skip the negotiation round-trip.
     */
    private val paddingTypeCache = ConcurrentHashMap<String, PaddingType>()

    fun cachedPaddingType(host: String, port: Int, sni: String): PaddingType? =
        paddingTypeCache["$host:$port:$sni"]

    fun cachePaddingType(type: PaddingType, host: String, port: Int, sni: String) {
        paddingTypeCache["$host:$port:$sni"] = type
    }

    /**
     * Parses the server response headers to determine the negotiated padding type:
     * 1. If `padding-type-reply` exists, parse its value.
     * 2. Otherwise, presence of `padding` header implies [PaddingType.VARIANT1] (backward compat).
     * 3. Otherwise [PaddingType.NONE].
     */
    fun parseResponse(headers: List<Pair<String, String>>): PaddingType {
        val replyHeader = headers.firstOrNull { it.first.equals("padding-type-reply", ignoreCase = true) }
        if (replyHeader != null) {
            val trimmed = replyHeader.second.trim()
            val rawValue = trimmed.toIntOrNull()
            if (rawValue != null) {
                return PaddingType.entries.firstOrNull { it.value == rawValue } ?: PaddingType.NONE
            }
        }

        if (headers.any { it.first.equals("padding", ignoreCase = true) }) {
            return PaddingType.VARIANT1
        }

        return PaddingType.NONE
    }
}
