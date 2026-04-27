package com.argsment.anywhere.vpn.protocol.mux

import java.io.ByteArrayOutputStream

enum class MuxSessionStatus(val value: Int) {
    NEW(0x01),
    KEEP(0x02),
    END(0x03),
    KEEP_ALIVE(0x04);

    companion object {
        fun fromByte(b: Int): MuxSessionStatus? = entries.find { it.value == (b and 0xFF) }
    }
}

object MuxOption {
    const val DATA: Int = 0x01
    const val ERROR: Int = 0x02
}

enum class MuxNetwork(val value: Int) {
    TCP(0x01),
    UDP(0x02);

    companion object {
        fun fromByte(b: Int): MuxNetwork? = entries.find { it.value == (b and 0xFF) }
    }
}

/** Mux address type (port-first format on the wire). */
private enum class MuxAddressType(val value: Int) {
    IPV4(0x01),
    DOMAIN(0x02),
    IPV6(0x03);

    companion object {
        fun fromByte(b: Int): MuxAddressType? = entries.find { it.value == (b and 0xFF) }
    }
}

data class MuxFrameMetadata(
    val sessionID: Int,          // UInt16 range
    val status: MuxSessionStatus,
    val option: Int,             // bitmask of MuxOption
    val network: MuxNetwork? = null,
    val targetHost: String? = null,
    val targetPort: Int? = null, // UInt16 range
    val globalID: ByteArray? = null  // 8 bytes, for XUDP
) {
    /** Encodes metadata into wire bytes (excluding the 2-byte metadata_length prefix). */
    fun encode(): ByteArray {
        val buf = ByteArrayOutputStream()

        buf.write((sessionID shr 8) and 0xFF)
        buf.write(sessionID and 0xFF)

        buf.write(status.value)

        buf.write(option and 0xFF)

        if (status == MuxSessionStatus.NEW) {
            val net = network
            val host = targetHost
            val port = targetPort
            if (net != null && host != null && port != null) {
                buf.write(net.value)

                // Port (2B big-endian) — port-first format.
                buf.write((port shr 8) and 0xFF)
                buf.write(port and 0xFF)

                encodeAddress(host, buf)

                // GlobalID is written only when XUDP is active.
                if (net == MuxNetwork.UDP) {
                    val gid = globalID
                    if (gid != null && gid.size == 8) {
                        buf.write(gid)
                    }
                }
            }
        }

        return buf.toByteArray()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MuxFrameMetadata) return false
        return sessionID == other.sessionID &&
                status == other.status &&
                option == other.option &&
                network == other.network &&
                targetHost == other.targetHost &&
                targetPort == other.targetPort &&
                (globalID?.contentEquals(other.globalID ?: byteArrayOf()) ?: (other.globalID == null))
    }

    override fun hashCode(): Int {
        var result = sessionID
        result = 31 * result + status.hashCode()
        result = 31 * result + option
        result = 31 * result + (network?.hashCode() ?: 0)
        result = 31 * result + (targetHost?.hashCode() ?: 0)
        result = 31 * result + (targetPort ?: 0)
        result = 31 * result + (globalID?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        /** Returns (metadata, bytesConsumed) or null if insufficient data. */
        fun decode(data: ByteArray): Pair<MuxFrameMetadata, Int>? {
            if (data.size < 4) return null  // 2B id + 1B status + 1B option

            var offset = 0
            val sessionID = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            offset += 2

            val status = MuxSessionStatus.fromByte(data[offset].toInt()) ?: return null
            offset += 1

            val option = data[offset].toInt() and 0xFF
            offset += 1

            var network: MuxNetwork? = null
            var targetHost: String? = null
            var targetPort: Int? = null
            var globalID: ByteArray? = null

            if (status == MuxSessionStatus.NEW) {
                if (data.size < offset + 1) return null
                network = MuxNetwork.fromByte(data[offset].toInt()) ?: return null
                offset += 1

                if (data.size < offset + 2) return null
                targetPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                offset += 2

                val addrResult = decodeAddress(data, offset) ?: return null
                targetHost = addrResult.first
                offset += addrResult.second

                // GlobalID is only present with XUDP.
                if (network == MuxNetwork.UDP && data.size >= offset + 8) {
                    globalID = data.copyOfRange(offset, offset + 8)
                    offset += 8
                }
            }

            val metadata = MuxFrameMetadata(
                sessionID = sessionID,
                status = status,
                option = option,
                network = network,
                targetHost = targetHost,
                targetPort = targetPort,
                globalID = globalID
            )

            return Pair(metadata, offset)
        }

        private fun decodeAddress(data: ByteArray, offset: Int): Pair<String, Int>? {
            if (data.size <= offset) return null
            val addrType = MuxAddressType.fromByte(data[offset].toInt()) ?: return null
            var pos = 1

            return when (addrType) {
                MuxAddressType.IPV4 -> {
                    if (data.size < offset + pos + 4) return null
                    val a = data[offset + pos].toInt() and 0xFF
                    val b = data[offset + pos + 1].toInt() and 0xFF
                    val c = data[offset + pos + 2].toInt() and 0xFF
                    val d = data[offset + pos + 3].toInt() and 0xFF
                    Pair("$a.$b.$c.$d", pos + 4)
                }

                MuxAddressType.DOMAIN -> {
                    if (data.size < offset + pos + 1) return null
                    val domainLen = data[offset + pos].toInt() and 0xFF
                    pos += 1
                    if (data.size < offset + pos + domainLen) return null
                    val domain = String(data, offset + pos, domainLen, Charsets.UTF_8)
                    Pair(domain, pos + domainLen)
                }

                MuxAddressType.IPV6 -> {
                    if (data.size < offset + pos + 16) return null
                    // InetAddress gives proper IPv6 formatting with zero-compression.
                    val ipBytes = data.copyOfRange(offset + pos, offset + pos + 16)
                    val addr = try {
                        java.net.InetAddress.getByAddress(ipBytes).hostAddress ?: "::1"
                    } catch (_: Exception) {
                        val parts = mutableListOf<String>()
                        for (i in 0 until 16 step 2) {
                            val value = ((data[offset + pos + i].toInt() and 0xFF) shl 8) or
                                    (data[offset + pos + i + 1].toInt() and 0xFF)
                            parts.add(value.toString(16))
                        }
                        parts.joinToString(":")
                    }
                    Pair(addr, pos + 16)
                }
            }
        }
    }
}

private fun encodeAddress(host: String, buf: ByteArrayOutputStream) {
    val ipv4 = parseIPv4(host)
    if (ipv4 != null) {
        buf.write(MuxAddressType.IPV4.value)
        buf.write(ipv4)
        return
    }

    val ipv6 = parseIPv6(host)
    if (ipv6 != null) {
        buf.write(MuxAddressType.IPV6.value)
        buf.write(ipv6)
        return
    }

    val domainData = host.toByteArray(Charsets.UTF_8)
    buf.write(MuxAddressType.DOMAIN.value)
    buf.write(domainData.size)
    buf.write(domainData)
}

private fun parseIPv4(address: String): ByteArray? {
    val parts = address.split(".")
    if (parts.size != 4) return null
    val bytes = ByteArray(4)
    for (i in parts.indices) {
        val value = parts[i].toIntOrNull() ?: return null
        if (value < 0 || value > 255) return null
        bytes[i] = value.toByte()
    }
    return bytes
}

private fun parseIPv6(address: String): ByteArray? {
    var addr = address
    if (addr.startsWith("[") && addr.endsWith("]")) {
        addr = addr.substring(1, addr.length - 1)
    }
    if (!addr.contains(':')) return null

    return try {
        val inetAddr = java.net.InetAddress.getByName(addr)
        if (inetAddr is java.net.Inet6Address) inetAddr.address else null
    } catch (_: Exception) {
        null
    }
}

/** Encodes a complete mux frame (metadata length + metadata + optional payload). */
fun encodeMuxFrame(metadata: MuxFrameMetadata, payload: ByteArray?): ByteArray {
    val metaBytes = metadata.encode()
    val metaLen = metaBytes.size

    val hasData = (metadata.option and MuxOption.DATA) != 0
    val capacity = 2 + metaBytes.size + if (hasData && payload != null) 2 + payload.size else 0
    val frame = ByteArrayOutputStream(capacity)

    frame.write((metaLen shr 8) and 0xFF)
    frame.write(metaLen and 0xFF)

    frame.write(metaBytes)

    if (hasData && payload != null) {
        val payloadLen = payload.size
        frame.write((payloadLen shr 8) and 0xFF)
        frame.write(payloadLen and 0xFF)
        frame.write(payload)
    }

    return frame.toByteArray()
}

/** Streaming parser that buffers partial reads and emits complete frames. */
class MuxFrameParser {
    private var buffer = ByteArrayOutputStream()
    private var bufferData = byteArrayOf()

    fun feed(data: ByteArray): List<Pair<MuxFrameMetadata, ByteArray?>> {
        buffer.write(data)
        bufferData = buffer.toByteArray()
        val results = mutableListOf<Pair<MuxFrameMetadata, ByteArray?>>()

        var offset = 0
        while (true) {
            val remaining = bufferData.size - offset

            if (remaining < 2) break

            val metaLen = ((bufferData[offset].toInt() and 0xFF) shl 8) or
                    (bufferData[offset + 1].toInt() and 0xFF)

            if (remaining < 2 + metaLen) break

            val metaData = bufferData.copyOfRange(offset + 2, offset + 2 + metaLen)
            val decoded = MuxFrameMetadata.decode(metaData)
            if (decoded == null) {
                // Corrupt frame: discard buffer.
                buffer.reset()
                bufferData = byteArrayOf()
                break
            }

            val (metadata, _) = decoded
            var consumed = 2 + metaLen
            var payload: ByteArray? = null

            if ((metadata.option and MuxOption.DATA) != 0) {
                if (remaining < consumed + 2) break

                val payloadLen = ((bufferData[offset + consumed].toInt() and 0xFF) shl 8) or
                        (bufferData[offset + consumed + 1].toInt() and 0xFF)
                consumed += 2

                if (remaining < consumed + payloadLen) {
                    break
                }

                if (payloadLen > 0) {
                    payload = bufferData.copyOfRange(offset + consumed, offset + consumed + payloadLen)
                }
                consumed += payloadLen
            }

            results.add(Pair(metadata, payload))
            offset += consumed
        }

        if (offset > 0) {
            val leftover = bufferData.copyOfRange(offset, bufferData.size)
            buffer.reset()
            if (leftover.isNotEmpty()) {
                buffer.write(leftover)
            }
            bufferData = leftover
        }

        return results
    }

    fun reset() {
        buffer.reset()
        bufferData = byteArrayOf()
    }
}
