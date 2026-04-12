package com.argsment.anywhere.vpn.protocol.vless

import java.util.UUID

/**
 * VLESS command types.
 */
enum class VlessCommand(val value: Byte) {
    TCP(0x01),
    UDP(0x02),
    MUX(0x03);

    companion object {
        fun fromByte(b: Byte): VlessCommand? = entries.find { it.value == b }
    }
}

/**
 * VLESS address types.
 */
enum class VlessAddressType(val value: Byte) {
    IPV4(0x01),
    DOMAIN(0x02),
    IPV6(0x03);

    companion object {
        fun fromByte(b: Byte): VlessAddressType? = entries.find { it.value == b }
    }
}

/**
 * VLESS protocol encoder/decoder.
 */
object VlessProtocol {

    /** VLESS protocol version (always 0). */
    const val VERSION: Byte = 0x00

    /**
     * Encode VLESS addons (protobuf format).
     * Addons message: { string Flow = 1; bytes Seed = 2; }
     */
    private fun encodeAddons(flow: String?): ByteArray {
        if (flow.isNullOrEmpty()) return byteArrayOf()

        val flowBytes = flow.toByteArray(Charsets.UTF_8)
        val data = ByteArray(2 + flowBytes.size)
        // Field 1 (Flow): wire type 2 (length-delimited), tag = 0x0A
        data[0] = 0x0A
        // Length of string (varint)
        data[1] = flowBytes.size.toByte()
        // String bytes
        System.arraycopy(flowBytes, 0, data, 2, flowBytes.size)
        return data
    }

    /**
     * Encode a VLESS request header.
     *
     * Format:
     * - 1 byte: Version (0x00)
     * - 16 bytes: UUID
     * - 1 byte: Addons length (0 for no addons)
     * - 1 byte: Command (TCP=0x01, UDP=0x02)
     * - 2 bytes: Port (big-endian)
     * - 1 byte: Address type
     * - Variable: Address data
     */
    fun encodeRequestHeader(
        uuid: UUID,
        command: VlessCommand,
        destinationAddress: String,
        destinationPort: Int,
        flow: String? = null
    ): ByteArray = encodeRequestHeaderKotlin(uuid, command, destinationAddress, destinationPort, flow)

    private fun encodeRequestHeaderKotlin(
        uuid: UUID,
        command: VlessCommand,
        destinationAddress: String,
        destinationPort: Int,
        flow: String?
    ): ByteArray {
        val result = mutableListOf<Byte>()

        // Version (1 byte)
        result.add(VERSION)

        // UUID (16 bytes)
        result.addAll(uuidToBytes(uuid).toList())

        // Addons (protobuf encoded)
        val addons = encodeAddons(flow)
        result.add(addons.size.toByte())
        if (addons.isNotEmpty()) {
            result.addAll(addons.toList())
        }

        // Command (1 byte)
        result.add(command.value)

        // Mux command omits address/port (matching Xray-core encoding.go:50-54)
        if (command != VlessCommand.MUX) {
            // Port (2 bytes, big-endian)
            result.add((destinationPort shr 8).toByte())
            result.add((destinationPort and 0xFF).toByte())

            // Address
            val ipv4 = parseIPv4(destinationAddress)
            val ipv6 = parseIPv6(destinationAddress)
            when {
                ipv4 != null -> {
                    result.add(VlessAddressType.IPV4.value)
                    result.addAll(ipv4.toList())
                }
                ipv6 != null -> {
                    result.add(VlessAddressType.IPV6.value)
                    result.addAll(ipv6.toList())
                }
                else -> {
                    // Domain name
                    val domainBytes = destinationAddress.toByteArray(Charsets.UTF_8)
                    result.add(VlessAddressType.DOMAIN.value)
                    result.add(domainBytes.size.toByte())
                    result.addAll(domainBytes.toList())
                }
            }
        }

        return result.toByteArray()
    }

    /**
     * Decode a VLESS response header.
     * Returns the number of bytes consumed, or 0 if no response header present.
     */
    fun decodeResponseHeader(data: ByteArray, offset: Int = 0): Int {
        val available = data.size - offset
        if (available < 2) return 0

        val version = data[offset]
        // If version is not 0, there's no VLESS response header
        if (version != VERSION) return 0

        val addonsLength = data[offset + 1].toInt() and 0xFF
        val totalLength = 2 + addonsLength

        if (available < totalLength) return 0

        return totalLength
    }

    /** Convert UUID to 16-byte array. */
    fun uuidToBytes(uuid: UUID): ByteArray {
        val bytes = ByteArray(16)
        val msb = uuid.mostSignificantBits
        val lsb = uuid.leastSignificantBits
        for (i in 0..7) {
            bytes[i] = (msb shr (56 - i * 8)).toByte()
        }
        for (i in 0..7) {
            bytes[8 + i] = (lsb shr (56 - i * 8)).toByte()
        }
        return bytes
    }

    /** Parse an IPv4 address string into bytes. */
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

    /** Parse an IPv6 address string into bytes. */
    private fun parseIPv6(address: String): ByteArray? {
        var addr = address
        if (addr.startsWith("[") && addr.endsWith("]")) {
            addr = addr.substring(1, addr.length - 1)
        }

        // Simple IPv6 parsing - expand :: and parse
        var parts = addr.split(":").toMutableList()

        // Handle :: expansion
        val emptyIndex = parts.indexOf("")
        if (emptyIndex >= 0) {
            val before = parts.subList(0, emptyIndex)
            val after = parts.subList(emptyIndex + 1, parts.size).filter { it.isNotEmpty() }
            val missing = 8 - before.size - after.size
            if (missing < 0) return null
            parts = (before + List(missing) { "0" } + after).toMutableList()
        }

        if (parts.size != 8) return null

        val bytes = ByteArray(16)
        for (i in parts.indices) {
            val value = parts[i].toIntOrNull(16) ?: return null
            if (value < 0 || value > 0xFFFF) return null
            bytes[i * 2] = (value shr 8).toByte()
            bytes[i * 2 + 1] = (value and 0xFF).toByte()
        }

        return bytes
    }
}
