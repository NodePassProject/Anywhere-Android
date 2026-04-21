package com.argsment.anywhere.vpn.util

import com.argsment.anywhere.vpn.TunnelConstants

/**
 * Incremental, bounds-checked parser that extracts the SNI hostname from
 * an inbound TLS ClientHello. Used by
 * [com.argsment.anywhere.vpn.LwipTcpConnection] to enable domain-based
 * routing for traffic that reaches the tunnel by real IP (hardcoded IPs,
 * DoH clients, etc.) — cases where the fake-IP ↔ domain mapping is
 * unavailable.
 *
 * The parser is strictly passive: it buffers up to [bufferLimit] bytes,
 * walks the record / handshake / extensions structure with explicit
 * bounds checks, and returns a terminal state as soon as the first byte
 * rules out TLS or the first server_name extension is reached. No bytes
 * beyond the ClientHello are retained.
 *
 * Mirrors iOS `TLSClientHelloSniffer` in
 * `Anywhere Network Extension/TLSClientHelloSniffer.swift`.
 */
class TlsClientHelloSniffer(
    private val bufferLimit: Int = TunnelConstants.tlsSnifferBufferLimit
) {

    sealed class State {
        /** Need more bytes to decide. Keep calling [feed]. */
        data object NeedMore : State()

        /** First bytes do not start with a TLS Handshake record (0x16). */
        data object NotTls : State()

        /** SNI extracted from a well-formed ClientHello (lowercased). */
        data class Found(val serverName: String) : State()

        /**
         * Input is TLS-shaped but SNI cannot be extracted — malformed
         * record, no server_name extension, or buffer cap reached.
         * Caller should fall back to the IP-based routing decision.
         */
        data object Unavailable : State()
    }

    private var buffer = ByteArray(0)
    private var bufferLen = 0
    var state: State = State.NeedMore
        private set

    /**
     * Appends [data] (of length [length]) and advances the parse state.
     * Returns the new state. After a terminal state is reached, further
     * calls are no-ops.
     */
    fun feed(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): State {
        if (state != State.NeedMore || length <= 0) return state

        // Fast reject before copying: a real TLS record starts with 0x16.
        // This keeps the buffer empty for non-TLS protocols.
        if (bufferLen == 0 && data[offset] != 0x16.toByte()) {
            state = State.NotTls
            return state
        }

        append(data, offset, length)
        if (bufferLen > bufferLimit) {
            state = State.Unavailable
            return state
        }

        state = parse()
        return state
    }

    private fun append(data: ByteArray, offset: Int, length: Int) {
        if (bufferLen + length > buffer.size) {
            var newSize = if (buffer.isEmpty()) 256 else buffer.size
            while (newSize < bufferLen + length) newSize *= 2
            buffer = buffer.copyOf(newSize)
        }
        System.arraycopy(data, offset, buffer, bufferLen, length)
        bufferLen += length
    }

    // -- Parsing --

    /** TLS record layer: `[content_type:1][legacy_version:2][length:2][fragment]` */
    private fun parse(): State {
        if (bufferLen < 5) return State.NeedMore
        if (buffer[0] != 0x16.toByte()) return State.Unavailable

        // RFC 8446 §5.1: record fragment length ≤ 2^14.
        val fragLen = ((buffer[3].toInt() and 0xFF) shl 8) or (buffer[4].toInt() and 0xFF)
        if (fragLen <= 0 || fragLen > 16384) return State.Unavailable

        val recordEnd = 5 + fragLen
        if (bufferLen < recordEnd) return State.NeedMore

        return parseHandshake(5, recordEnd)
    }

    /** Handshake layer: `[msg_type:1][length:3][body]` */
    private fun parseHandshake(start: Int, end: Int): State {
        val cur = Cursor(buffer, start, end)
        val msgType = cur.readU8() ?: return State.Unavailable
        if (msgType != 0x01) return State.Unavailable  // ClientHello
        val bodyLen = cur.readU24() ?: return State.Unavailable
        val bodyEnd = cur.pos + bodyLen
        if (bodyEnd > end) return State.Unavailable
        return parseClientHello(cur.pos, bodyEnd)
    }

    /**
     * ClientHello body (after the 4-byte handshake header):
     *   legacy_version (uint16)
     *   random [32]
     *   session_id             opaque<0..32>         (uint8  len + bytes)
     *   cipher_suites          CipherSuite<2..2^16-2> (uint16 len + bytes)
     *   compression_methods    opaque<1..2^8-1>      (uint8  len + bytes)
     *   extensions             Extension<8..2^16-1>  (uint16 len + bytes)
     */
    private fun parseClientHello(start: Int, end: Int): State {
        val cur = Cursor(buffer, start, end)
        if (!cur.skip(2 + 32)) return State.Unavailable
        val sidLen = cur.readU8() ?: return State.Unavailable
        if (!cur.skip(sidLen)) return State.Unavailable
        val csLen = cur.readU16() ?: return State.Unavailable
        if (!cur.skip(csLen)) return State.Unavailable
        val cmLen = cur.readU8() ?: return State.Unavailable
        if (!cur.skip(cmLen)) return State.Unavailable
        val extLen = cur.readU16() ?: return State.Unavailable
        val extEnd = cur.pos + extLen
        if (extEnd > end) return State.Unavailable
        return parseExtensions(cur.pos, extEnd)
    }

    /** Walks the extension list looking for server_name (type 0x0000). */
    private fun parseExtensions(start: Int, end: Int): State {
        val cur = Cursor(buffer, start, end)
        while (!cur.isAtEnd) {
            val extType = cur.readU16() ?: return State.Unavailable
            val extLen = cur.readU16() ?: return State.Unavailable
            val extEnd = cur.pos + extLen
            if (extEnd > end) return State.Unavailable
            if (extType == 0x0000) {
                return parseServerNameList(cur.pos, extEnd)
                    ?.let { State.Found(it) } ?: State.Unavailable
            }
            cur.pos = extEnd
        }
        return State.Unavailable
    }

    /**
     * server_name extension:
     *   ServerNameList: uint16 length + list of ServerName
     *   ServerName:     uint8 name_type + opaque<0..2^16-1>
     *   name_type 0x00 = HostName (ASCII per RFC 6066)
     */
    private fun parseServerNameList(start: Int, end: Int): String? {
        val cur = Cursor(buffer, start, end)
        val listLen = cur.readU16() ?: return null
        val listEnd = cur.pos + listLen
        if (listEnd > end) return null
        while (cur.pos < listEnd) {
            val nameType = cur.readU8() ?: return null
            val nameLen = cur.readU16() ?: return null
            val nameEnd = cur.pos + nameLen
            if (nameEnd > listEnd) return null
            if (nameType == 0x00 && nameLen > 0) {
                val host = String(buffer, cur.pos, nameLen, Charsets.UTF_8)
                return host.lowercase()
            }
            cur.pos = nameEnd
        }
        return null
    }

    // -- Cursor --

    private class Cursor(val data: ByteArray, start: Int, val end: Int) {
        var pos: Int = start

        val isAtEnd: Boolean get() = pos >= end

        fun skip(n: Int): Boolean {
            if (n < 0 || pos + n > end) return false
            pos += n
            return true
        }

        fun readU8(): Int? {
            if (pos >= end) return null
            val v = data[pos].toInt() and 0xFF
            pos += 1
            return v
        }

        fun readU16(): Int? {
            if (pos + 2 > end) return null
            val v = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            return v
        }

        fun readU24(): Int? {
            if (pos + 3 > end) return null
            val v = ((data[pos].toInt() and 0xFF) shl 16) or
                ((data[pos + 1].toInt() and 0xFF) shl 8) or
                (data[pos + 2].toInt() and 0xFF)
            pos += 3
            return v
        }
    }

}
