package com.argsment.anywhere.vpn.util

/**
 * Pure-Kotlin packet utilities. Port of `jni/packet/CPacket.c` — the VPN stack
 * has no reason to leave the JVM for this logic.
 */
object PacketUtil {

    // -- TLS record / AEAD nonce --

    /**
     * Return a new 12-byte nonce formed by XORing the last 8 bytes of [iv]
     * with the big-endian encoding of [seqNum]. Used for TLS 1.3 AEAD.
     */
    fun xorNonce(iv: ByteArray, seqNum: Long): ByteArray {
        require(iv.size == 12) { "nonce must be 12 bytes" }
        val out = iv.copyOf()
        out[4]  = (out[4].toInt()  xor ((seqNum ushr 56).toInt() and 0xFF)).toByte()
        out[5]  = (out[5].toInt()  xor ((seqNum ushr 48).toInt() and 0xFF)).toByte()
        out[6]  = (out[6].toInt()  xor ((seqNum ushr 40).toInt() and 0xFF)).toByte()
        out[7]  = (out[7].toInt()  xor ((seqNum ushr 32).toInt() and 0xFF)).toByte()
        out[8]  = (out[8].toInt()  xor ((seqNum ushr 24).toInt() and 0xFF)).toByte()
        out[9]  = (out[9].toInt()  xor ((seqNum ushr 16).toInt() and 0xFF)).toByte()
        out[10] = (out[10].toInt() xor ((seqNum ushr 8).toInt()  and 0xFF)).toByte()
        out[11] = (out[11].toInt() xor (seqNum.toInt()            and 0xFF)).toByte()
        return out
    }

    /**
     * Strip TLS 1.3 zero padding and split out the inner content type.
     * Returns a byte array whose first byte is the inner content type
     * and whose tail is the plaintext, or null on invalid input.
     *
     * Matches `tls13_unwrap_content` + `find_tls13_content_end` in CPacket.c.
     */
    fun tls13UnwrapContent(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null

        // Scan backwards to find the last non-zero byte (content type).
        var i = data.size - 1
        while (i >= 0 && data[i].toInt() == 0) i--
        if (i < 0) return null

        // Caller expects [contentType, ...content].
        val result = ByteArray(1 + i)
        result[0] = data[i]
        if (i > 0) System.arraycopy(data, 0, result, 1, i)
        return result
    }

    // -- UDP length framing (2-byte big-endian length prefix) --

    fun frameUdpPayload(payload: ByteArray): ByteArray {
        val out = ByteArray(2 + payload.size)
        out[0] = ((payload.size ushr 8) and 0xFF).toByte()
        out[1] = (payload.size and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 2, payload.size)
        return out
    }

    // -- DNS query parsing (extended with QTYPE) --

    data class DnsQuery(val domain: String, val qtype: Int)

    /**
     * Parse a DNS query packet. Returns the lowercase domain and QTYPE,
     * or null on malformed input. Compressed pointers in QNAME are rejected
     * (they're not expected in queries).
     */
    fun parseDnsQueryExt(data: ByteArray): DnsQuery? {
        if (data.size < 12) return null

        // QDCOUNT >= 1
        val qdcount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (qdcount == 0) return null

        var offset = 12
        val sb = StringBuilder()

        while (offset < data.size) {
            val labelLen = data[offset].toInt() and 0xFF
            offset++
            if (labelLen == 0) break  // end of QNAME
            if ((labelLen and 0xC0) != 0) return null  // compressed pointer rejected
            if (offset + labelLen > data.size) return null

            if (sb.isNotEmpty()) sb.append('.')
            for (k in 0 until labelLen) {
                sb.append((data[offset + k].toInt() and 0xFF).toChar())
            }
            offset += labelLen
        }

        if (sb.isEmpty()) return null

        // QTYPE (QCLASS follows but we don't need it)
        if (offset + 2 > data.size) return null
        val qtype = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

        return DnsQuery(sb.toString(), qtype)
    }

    // -- DNS response generation (fake-IP replies) --

    /**
     * Build a DNS response for [query] that either resolves to [fakeIp]
     * (when non-null and [qtype] is A/AAAA) or a NODATA reply otherwise.
     * Matches `generate_dns_response` in CPacket.c.
     */
    fun generateDnsResponse(query: ByteArray, fakeIp: ByteArray?, qtype: Int): ByteArray? {
        if (query.size < 12) return null

        // Find end of question section: QNAME terminator + QTYPE(2) + QCLASS(2)
        var offset = 12
        while (offset < query.size) {
            val labelLen = query[offset].toInt() and 0xFF
            offset++
            if (labelLen == 0) break
            if ((labelLen and 0xC0) != 0) break  // compressed pointer — stop (2 bytes total)
            offset += labelLen
        }
        offset += 4  // QTYPE + QCLASS
        if (offset > query.size) return null
        val questionEnd = offset

        // Work out RDATA length for A/AAAA.
        var rdLength = 0
        var ansType = 0
        if (fakeIp != null) {
            if (qtype == 1) {           // A
                rdLength = 4
                ansType = 1
            } else if (qtype == 28) {   // AAAA
                rdLength = 16
                ansType = 28
            }
        }

        fun writeHeader(buf: ByteArray, ancount: Int) {
            // Preserve ID + original flags/QDCOUNT, then stamp our own response flags.
            buf[2] = 0x85.toByte()       // QR=1, AA=1, RD=1
            buf[3] = 0x80.toByte()       // RA=1
            buf[6] = ((ancount ushr 8) and 0xFF).toByte()
            buf[7] = (ancount and 0xFF).toByte()
            buf[8] = 0; buf[9] = 0       // NSCOUNT = 0
            buf[10] = 0; buf[11] = 0     // ARCOUNT = 0
        }

        if (rdLength > 0 && fakeIp != null && fakeIp.size >= rdLength) {
            // Answer record: name(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
            val answerLen = 12 + rdLength
            val out = ByteArray(questionEnd + answerLen)
            System.arraycopy(query, 0, out, 0, questionEnd)
            writeHeader(out, 1)

            val ans = questionEnd
            out[ans]     = 0xC0.toByte()
            out[ans + 1] = 0x0C.toByte()                         // pointer to QNAME
            out[ans + 2] = ((ansType ushr 8) and 0xFF).toByte()
            out[ans + 3] = (ansType and 0xFF).toByte()
            out[ans + 4] = 0x00; out[ans + 5] = 0x01             // CLASS = IN
            out[ans + 6] = 0x00; out[ans + 7] = 0x00
            out[ans + 8] = 0x00; out[ans + 9] = 0x01             // TTL = 1s
            out[ans + 10] = ((rdLength ushr 8) and 0xFF).toByte()
            out[ans + 11] = (rdLength and 0xFF).toByte()
            System.arraycopy(fakeIp, 0, out, ans + 12, rdLength)
            return out
        }

        // NODATA
        val out = ByteArray(questionEnd)
        System.arraycopy(query, 0, out, 0, questionEnd)
        writeHeader(out, 0)
        return out
    }

    // -- TLS ServerHello parsing --

    /**
     * Parse a TLS ServerHello record batch and extract the X25519 key-share (group 0x001d)
     * plus the negotiated cipher suite. Returns a 34-byte array: [32-byte key share][cipher BE],
     * or null if no matching ServerHello / X25519 key share is found. Matches
     * `parse_server_hello` in CPacket.c.
     */
    fun parseServerHello(data: ByteArray): ByteArray? {
        var offset = 0
        while (offset + 5 < data.size) {
            val contentType = data[offset].toInt() and 0xFF
            if (contentType != 0x16) return null  // not a handshake record

            val recordLen = ((data[offset + 3].toInt() and 0xFF) shl 8) or
                    (data[offset + 4].toInt() and 0xFF)
            offset += 5
            if (offset + recordLen > data.size) return null
            if ((data[offset].toInt() and 0xFF) != 0x02) {
                // Not ServerHello — skip record.
                offset += recordLen
                continue
            }

            // Skip handshake type(1) + length(3) + version(2) + random(32) = 38
            var sh = offset + 1 + 3 + 2 + 32
            if (sh >= data.size) return null

            // Session ID
            val sessionIdLen = data[sh].toInt() and 0xFF
            sh += 1 + sessionIdLen

            if (sh + 2 > data.size) return null
            val cipherSuite = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
            sh += 3  // cipher(2) + compression(1)

            if (sh + 2 > data.size) return null
            val extLen = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
            sh += 2
            val extEnd = sh + extLen
            if (extEnd > data.size) return null

            // Walk extensions for key_share (0x0033)
            while (sh + 4 <= extEnd) {
                val extType = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
                val extDataLen = ((data[sh + 2].toInt() and 0xFF) shl 8) or (data[sh + 3].toInt() and 0xFF)
                sh += 4

                if (extType == 0x0033) {
                    if (sh + 4 > data.size) return null
                    val group = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
                    val keyLen = ((data[sh + 2].toInt() and 0xFF) shl 8) or (data[sh + 3].toInt() and 0xFF)
                    sh += 4

                    if (group == 0x001d && keyLen == 32) {
                        if (sh + 32 > data.size) return null
                        val result = ByteArray(34)
                        System.arraycopy(data, sh, result, 0, 32)
                        result[32] = ((cipherSuite ushr 8) and 0xFF).toByte()
                        result[33] = (cipherSuite and 0xFF).toByte()
                        return result
                    }
                }

                sh += extDataLen
            }

            return null  // found ServerHello but no X25519 key_share
        }
        return null
    }
}
