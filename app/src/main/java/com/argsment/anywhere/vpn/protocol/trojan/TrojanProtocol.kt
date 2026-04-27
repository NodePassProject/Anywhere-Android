package com.argsment.anywhere.vpn.protocol.trojan

import com.argsment.anywhere.data.model.ProxyError
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.security.MessageDigest

/**
 * Trojan wire format utilities.
 *
 * TCP request header: `hex(sha224(password))` (56 ASCII bytes) + CRLF
 *                   + cmd(1) + ATYP(1) + address(var) + port(2 BE) + CRLF
 * UDP packet format: ATYP(1) + address(var) + port(2 BE) + length(2 BE) + CRLF + payload
 * Address encoding matches SOCKS5 / Shadowsocks: ATYP 0x01 IPv4, 0x03 domain, 0x04 IPv6.
 */
object TrojanProtocol {

    const val COMMAND_TCP: Byte = 0x01
    const val COMMAND_UDP: Byte = 0x03

    /** Max per-packet payload size accepted by upstream Trojan servers. */
    const val MAX_UDP_PAYLOAD_LENGTH: Int = 8192

    private const val ATYP_IPV4: Byte = 0x01
    private const val ATYP_DOMAIN: Byte = 0x03
    private const val ATYP_IPV6: Byte = 0x04

    private val HEX_CHARS = "0123456789abcdef".toByteArray()

    /**
     * SHA224(password) rendered as 56 lowercase-hex ASCII bytes — the exact
     * byte sequence Trojan servers compare against.
     */
    fun passwordKey(password: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-224").digest(password.toByteArray(Charsets.UTF_8))
        val out = ByteArray(56)
        for (i in digest.indices) {
            val b = digest[i].toInt() and 0xFF
            out[i * 2]     = HEX_CHARS[b ushr 4]
            out[i * 2 + 1] = HEX_CHARS[b and 0x0F]
        }
        return out
    }

    fun buildRequestHeader(
        passwordKey: ByteArray,
        command: Byte,
        host: String,
        port: Int
    ): ByteArray {
        val addressPort = encodeAddressPort(host, port)
        val out = ByteArray(passwordKey.size + 2 + 1 + addressPort.size + 2)
        var idx = 0
        System.arraycopy(passwordKey, 0, out, idx, passwordKey.size); idx += passwordKey.size
        out[idx++] = 0x0D; out[idx++] = 0x0A
        out[idx++] = command
        System.arraycopy(addressPort, 0, out, idx, addressPort.size); idx += addressPort.size
        out[idx++] = 0x0D; out[idx] = 0x0A
        return out
    }

    fun encodeAddressPort(host: String, port: Int): ByteArray {
        val ipv4 = parseIPv4(host)
        val ipv6 = if (ipv4 == null) parseIPv6(host) else null

        val prefix: ByteArray = when {
            ipv4 != null -> byteArrayOf(ATYP_IPV4) + ipv4
            ipv6 != null -> byteArrayOf(ATYP_IPV6) + ipv6
            else -> {
                val domainBytes = host.toByteArray(Charsets.UTF_8)
                val trimmed = if (domainBytes.size > 255) domainBytes.copyOf(255) else domainBytes
                byteArrayOf(ATYP_DOMAIN, trimmed.size.toByte()) + trimmed
            }
        }
        val out = ByteArray(prefix.size + 2)
        System.arraycopy(prefix, 0, out, 0, prefix.size)
        out[prefix.size]     = (port ushr 8).toByte()
        out[prefix.size + 1] = (port and 0xFF).toByte()
        return out
    }

    fun encodeUDPPacket(host: String, port: Int, payload: ByteArray): ByteArray {
        val addr = encodeAddressPort(host, port)
        val length = minOf(payload.size, MAX_UDP_PAYLOAD_LENGTH)
        val out = ByteArray(addr.size + 2 + 2 + length)
        var idx = 0
        System.arraycopy(addr, 0, out, idx, addr.size); idx += addr.size
        out[idx++] = (length ushr 8).toByte()
        out[idx++] = (length and 0xFF).toByte()
        out[idx++] = 0x0D; out[idx++] = 0x0A
        System.arraycopy(payload, 0, out, idx, length)
        return out
    }

    /**
     * Attempts to decode a single UDP packet from [buffer]. Returns payload + consumed byte count,
     * or `null` when the buffer is short. Throws on malformed framing.
     */
    fun tryDecodeUDPPacket(buffer: ByteArray): DecodedPacket? {
        if (buffer.isEmpty()) return null
        var offset = 0
        val atyp = buffer[offset]
        offset += 1

        val addrLen: Int = when (atyp) {
            ATYP_IPV4 -> 4
            ATYP_IPV6 -> 16
            ATYP_DOMAIN -> {
                if (offset >= buffer.size) return null
                val domainLen = buffer[offset].toInt() and 0xFF
                offset += 1
                domainLen
            }
            else -> throw ProxyError.ProtocolError("Trojan: unknown ATYP $atyp")
        }

        // Need address + port (2) + length (2) + CRLF (2) before the payload.
        if (buffer.size - offset < addrLen + 2 + 2 + 2) return null
        offset += addrLen + 2

        val length = ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
        offset += 2
        // CRLF
        offset += 2

        if (length > MAX_UDP_PAYLOAD_LENGTH) {
            throw ProxyError.ProtocolError("Trojan: oversize UDP payload ($length)")
        }
        if (buffer.size - offset < length) return null

        val payload = buffer.copyOfRange(offset, offset + length)
        val consumed = offset + length
        return DecodedPacket(payload, consumed)
    }

    data class DecodedPacket(val payload: ByteArray, val consumed: Int)

    private val IPV4_REGEX = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")

    private fun parseIPv4(address: String): ByteArray? {
        if (!IPV4_REGEX.matches(address)) return null
        return try {
            val addr = InetAddress.getByName(address)
            if (addr is Inet4Address) addr.address else null
        } catch (_: Exception) { null }
    }

    private fun parseIPv6(address: String): ByteArray? {
        var clean = address
        if (clean.startsWith("[") && clean.endsWith("]")) {
            clean = clean.substring(1, clean.length - 1)
        }
        if (!clean.contains(':')) return null
        return try {
            val addr = InetAddress.getByName(clean)
            if (addr is Inet6Address) addr.address else null
        } catch (_: Exception) { null }
    }
}
