package com.argsment.anywhere.vpn.protocol.hysteria

import java.security.SecureRandom

/**
 * Hysteria v2 wire-format helpers — varint encode/decode, TCP request framing,
 * UDP datagram framing/fragmentation, and random padding generation.
 *
 * Direct port of iOS `Protocols/Hysteria/HysteriaProtocol.swift`.
 */
object HysteriaProtocol {

    /** Frame type varint prefixed on every Hysteria TCP request. (`FrameTypeTCPRequest = 0x401`) */
    const val TCP_REQUEST_FRAME_TYPE: Long = 0x401

    /** QUIC application error codes used by the reference server/client. */
    const val CLOSE_ERR_CODE_OK: Long = 0x100
    const val CLOSE_ERR_CODE_PROTOCOL_ERROR: Long = 0x101

    /** Status byte returned on TCP handshake: 0 = OK, non-zero = error. */
    const val TCP_RESPONSE_STATUS_OK: Byte = 0
    /** HTTP status code the server returns on successful /auth. */
    const val AUTH_SUCCESS_STATUS: Int = 233

    // Padding ranges (from padding.go)
    val AUTH_PADDING_RANGE = 256..2047
    val TCP_REQUEST_PADDING_RANGE = 64..511
    val TCP_RESPONSE_PADDING_RANGE = 128..1023

    // Limits
    const val MAX_ADDRESS_LENGTH = 2048
    const val MAX_RESPONSE_MESSAGE_LENGTH = 2048
    const val MAX_PADDING_LENGTH = 4096

    private val random = SecureRandom()
    private val ALPHABET: ByteArray =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArray(Charsets.US_ASCII)

    // -- VarInt (QUIC RFC 9000 §16) --

    /** Encodes an unsigned integer in QUIC variable-length format.
     *  Returns null if value exceeds the 62-bit maximum. */
    fun encodeVarInt(value: Long): ByteArray? {
        require(value >= 0) { "varint value must be non-negative" }
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
            value < (1L shl 62) -> {
                val v = value or (0b11L shl 62)
                byteArrayOf(
                    ((v shr 56) and 0xFF).toByte(), ((v shr 48) and 0xFF).toByte(),
                    ((v shr 40) and 0xFF).toByte(), ((v shr 32) and 0xFF).toByte(),
                    ((v shr 24) and 0xFF).toByte(), ((v shr 16) and 0xFF).toByte(),
                    ((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte()
                )
            }
            else -> null
        }
    }

    data class VarIntResult(val value: Long, val consumed: Int)

    /** Decodes a QUIC varint from `data` starting at `offset`. */
    fun decodeVarInt(data: ByteArray, offset: Int = 0): VarIntResult? {
        if (offset >= data.size) return null
        val first = data[offset].toInt() and 0xFF
        val prefix = first ushr 6
        val len = 1 shl prefix
        if (offset + len > data.size) return null

        var value = (first and 0x3F).toLong()
        for (i in 1 until len) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return VarIntResult(value, len)
    }

    /** Number of bytes an already-bounded varint will take on the wire. */
    fun varIntLength(value: Long): Int = when {
        value < (1L shl 6) -> 1
        value < (1L shl 14) -> 2
        value < (1L shl 30) -> 4
        else -> 8
    }

    // -- TCP framing --

    /** Builds a Hysteria v2 TCP request: varint(0x401) + varint(addrLen) +
     *  addr + varint(padLen) + random padding. `address` is "host:port". */
    fun encodeTcpRequest(address: String): ByteArray {
        val addrBytes = address.toByteArray(Charsets.UTF_8)
        val padLen = randomInRange(TCP_REQUEST_PADDING_RANGE)
        val padBytes = randomPadding(padLen)

        val frameType = encodeVarInt(TCP_REQUEST_FRAME_TYPE)!!
        val addrLen = encodeVarInt(addrBytes.size.toLong())!!
        val padLenVarInt = encodeVarInt(padBytes.size.toLong())!!

        val out = ByteArray(frameType.size + addrLen.size + addrBytes.size + padLenVarInt.size + padBytes.size)
        var p = 0
        System.arraycopy(frameType, 0, out, p, frameType.size); p += frameType.size
        System.arraycopy(addrLen, 0, out, p, addrLen.size); p += addrLen.size
        System.arraycopy(addrBytes, 0, out, p, addrBytes.size); p += addrBytes.size
        System.arraycopy(padLenVarInt, 0, out, p, padLenVarInt.size); p += padLenVarInt.size
        System.arraycopy(padBytes, 0, out, p, padBytes.size)
        return out
    }

    data class TcpResponse(val status: Byte, val message: String, val consumed: Int)

    /** Parses a Hysteria v2 TCP response: u8 status + varint(msgLen) + msg
     *  + varint(padLen) + pad. Returns null if the buffer is incomplete. */
    fun parseTcpResponse(data: ByteArray, start: Int = 0, end: Int = data.size): TcpResponse? {
        if (start >= end) return null
        var offset = start
        val status = data[offset]; offset += 1

        val msgLenR = decodeVarInt(data, offset) ?: return null
        if (msgLenR.value > MAX_RESPONSE_MESSAGE_LENGTH) return null
        offset += msgLenR.consumed
        if (offset + msgLenR.value.toInt() > end) return null
        val message = String(data, offset, msgLenR.value.toInt(), Charsets.UTF_8)
        offset += msgLenR.value.toInt()

        val padLenR = decodeVarInt(data, offset) ?: return null
        if (padLenR.value > MAX_PADDING_LENGTH) return null
        offset += padLenR.consumed
        if (offset + padLenR.value.toInt() > end) return null
        offset += padLenR.value.toInt()

        return TcpResponse(status, message, offset - start)
    }

    // -- UDP datagram framing --

    /** Fixed portion of a Hysteria UDP datagram header (before addr+data):
     *  u32 SessionID | u16 PacketID | u8 FragID | u8 FragCount. */
    const val UDP_HEADER_FIXED_SIZE: Int = 4 + 2 + 1 + 1

    data class UdpMessage(
        val sessionId: Int,
        val packetId: Int,
        val fragId: Int,
        val fragCount: Int,
        /** UTF-8 "host:port". */
        val address: String,
        val data: ByteArray
    )

    fun encodeUdpMessage(msg: UdpMessage): ByteArray {
        val addrBytes = msg.address.toByteArray(Charsets.UTF_8)
        val addrLenVarInt = encodeVarInt(addrBytes.size.toLong())!!

        val out = ByteArray(UDP_HEADER_FIXED_SIZE + addrLenVarInt.size + addrBytes.size + msg.data.size)
        var p = 0
        // u32 SessionID big-endian
        out[p++] = ((msg.sessionId ushr 24) and 0xFF).toByte()
        out[p++] = ((msg.sessionId ushr 16) and 0xFF).toByte()
        out[p++] = ((msg.sessionId ushr 8) and 0xFF).toByte()
        out[p++] = (msg.sessionId and 0xFF).toByte()
        // u16 PacketID big-endian
        out[p++] = ((msg.packetId ushr 8) and 0xFF).toByte()
        out[p++] = (msg.packetId and 0xFF).toByte()
        out[p++] = (msg.fragId and 0xFF).toByte()
        out[p++] = (msg.fragCount and 0xFF).toByte()
        System.arraycopy(addrLenVarInt, 0, out, p, addrLenVarInt.size); p += addrLenVarInt.size
        System.arraycopy(addrBytes, 0, out, p, addrBytes.size); p += addrBytes.size
        System.arraycopy(msg.data, 0, out, p, msg.data.size)
        return out
    }

    fun decodeUdpMessage(data: ByteArray): UdpMessage? {
        if (data.size < UDP_HEADER_FIXED_SIZE) return null
        var offset = 0
        val sid = ((data[0].toInt() and 0xFF) shl 24) or
                  ((data[1].toInt() and 0xFF) shl 16) or
                  ((data[2].toInt() and 0xFF) shl 8) or
                  (data[3].toInt() and 0xFF)
        offset += 4
        val pid = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        offset += 2
        val fragId = data[offset].toInt() and 0xFF; offset += 1
        val fragCount = data[offset].toInt() and 0xFF; offset += 1

        val addrLenR = decodeVarInt(data, offset) ?: return null
        if (addrLenR.value > MAX_ADDRESS_LENGTH) return null
        offset += addrLenR.consumed
        if (offset + addrLenR.value.toInt() > data.size) return null
        val address = String(data, offset, addrLenR.value.toInt(), Charsets.UTF_8)
        offset += addrLenR.value.toInt()

        val payload = data.copyOfRange(offset, data.size)
        return UdpMessage(sid, pid, fragId, fragCount, address, payload)
    }

    /** Serialized header size (without data) for an address. */
    fun udpHeaderSize(address: String): Int {
        val addrBytes = address.toByteArray(Charsets.UTF_8).size
        return UDP_HEADER_FIXED_SIZE + varIntLength(addrBytes.toLong()) + addrBytes
    }

    /** Splits `data` into N fragments so each datagram fits in `maxDatagramSize`.
     *  Each fragment carries the same PacketID and full addr header. */
    fun fragmentUdp(
        sessionId: Int,
        packetId: Int,
        address: String,
        data: ByteArray,
        maxDatagramSize: Int
    ): List<UdpMessage> {
        val headerSize = udpHeaderSize(address)
        val maxPayload = maxOf(1, maxDatagramSize - headerSize)
        if (data.size <= maxPayload) {
            return listOf(UdpMessage(sessionId, packetId, 0, 1, address, data))
        }
        val chunks = (data.size + maxPayload - 1) / maxPayload
        if (chunks > 255) return emptyList()
        val out = ArrayList<UdpMessage>(chunks)
        for (i in 0 until chunks) {
            val s = i * maxPayload
            val e = minOf(s + maxPayload, data.size)
            out.add(UdpMessage(sessionId, packetId, i, chunks, address, data.copyOfRange(s, e)))
        }
        return out
    }

    // -- Padding generation --

    /** Random ASCII padding [A-Za-z0-9] of `length` bytes. */
    fun randomPadding(length: Int): ByteArray {
        if (length <= 0) return ByteArray(0)
        val out = ByteArray(length)
        random.nextBytes(out)
        for (i in 0 until length) {
            out[i] = ALPHABET[(out[i].toInt() and 0xFF) % ALPHABET.size]
        }
        return out
    }

    /** Random ASCII padding string for the Hysteria-Padding HTTP header. */
    fun randomPaddingString(range: IntRange = AUTH_PADDING_RANGE): String {
        val length = randomInRange(range)
        return String(randomPadding(length), Charsets.US_ASCII)
    }

    private fun randomInRange(range: IntRange): Int {
        val span = range.last - range.first + 1
        return range.first + (random.nextInt(span.coerceAtLeast(1)))
    }
}
