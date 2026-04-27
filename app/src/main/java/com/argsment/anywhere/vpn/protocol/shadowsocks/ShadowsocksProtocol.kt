package com.argsment.anywhere.vpn.protocol.shadowsocks

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Shadowsocks wire-format utilities.
 *
 * Address format: `ATYP(1) + Address(var) + Port(2, big-endian)`
 * - ATYP 0x01: IPv4 (4 bytes)
 * - ATYP 0x03: Domain (1-byte length + string)
 * - ATYP 0x04: IPv6 (16 bytes)
 */
object ShadowsocksProtocol {

    private const val ATYP_IPV4: Byte = 0x01
    private const val ATYP_DOMAIN: Byte = 0x03
    private const val ATYP_IPV6: Byte = 0x04

    fun buildAddressHeader(host: String, port: Int): ByteArray {
        val ipv4 = parseIPv4(host)
        val ipv6 = if (ipv4 == null) parseIPv6(host) else null

        val buf = ByteBuffer.allocate(1 + 256 + 2)
        when {
            ipv4 != null -> {
                buf.put(ATYP_IPV4)
                buf.put(ipv4)
            }
            ipv6 != null -> {
                buf.put(ATYP_IPV6)
                buf.put(ipv6)
            }
            else -> {
                val domainBytes = host.toByteArray(Charsets.UTF_8)
                buf.put(ATYP_DOMAIN)
                buf.put(domainBytes.size.toByte())
                buf.put(domainBytes)
            }
        }

        buf.put((port shr 8).toByte())
        buf.put((port and 0xFF).toByte())

        buf.flip()
        val result = ByteArray(buf.remaining())
        buf.get(result)
        return result
    }

    /** Address header followed by the raw payload. */
    fun encodeUDPPacket(host: String, port: Int, payload: ByteArray): ByteArray {
        val header = buildAddressHeader(host, port)
        return header + payload
    }

    fun decodeUDPPacket(data: ByteArray): UdpPacket? {
        if (data.isEmpty()) return null
        var offset = 0

        val atyp = data[offset]
        offset++

        val host: String
        when (atyp) {
            ATYP_IPV4 -> {
                if (data.size - offset < 4 + 2) return null
                host = "${data[offset].toInt() and 0xFF}.${data[offset + 1].toInt() and 0xFF}.${data[offset + 2].toInt() and 0xFF}.${data[offset + 3].toInt() and 0xFF}"
                offset += 4
            }
            ATYP_DOMAIN -> {
                if (data.size - offset < 1) return null
                val domainLen = data[offset].toInt() and 0xFF
                offset++
                if (data.size - offset < domainLen + 2) return null
                host = String(data, offset, domainLen, Charsets.UTF_8)
                offset += domainLen
            }
            ATYP_IPV6 -> {
                if (data.size - offset < 16 + 2) return null
                val parts = mutableListOf<String>()
                for (i in 0 until 16 step 2) {
                    val word = ((data[offset + i].toInt() and 0xFF) shl 8) or (data[offset + i + 1].toInt() and 0xFF)
                    parts.add(word.toString(16))
                }
                host = parts.joinToString(":")
                offset += 16
            }
            else -> return null
        }

        if (data.size - offset < 2) return null
        val port = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        offset += 2

        val payload = data.copyOfRange(offset, data.size)
        return UdpPacket(host, port, payload)
    }

    private val IPV4_REGEX = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")

    private fun parseIPv4(address: String): ByteArray? {
        if (!IPV4_REGEX.matches(address)) return null
        return try {
            val addr = InetAddress.getByName(address)
            if (addr is Inet4Address) addr.address else null
        } catch (_: Exception) {
            null
        }
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
        } catch (_: Exception) {
            null
        }
    }

    data class UdpPacket(val host: String, val port: Int, val payload: ByteArray)
}
