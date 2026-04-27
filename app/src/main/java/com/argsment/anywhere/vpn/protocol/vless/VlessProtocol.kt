package com.argsment.anywhere.vpn.protocol.vless

import java.util.UUID

enum class VlessCommand(val value: Byte) {
    TCP(0x01),
    UDP(0x02),
    MUX(0x03);

    companion object {
        fun fromByte(b: Byte): VlessCommand? = entries.find { it.value == b }
    }
}

enum class VlessAddressType(val value: Byte) {
    IPV4(0x01),
    DOMAIN(0x02),
    IPV6(0x03);

    companion object {
        fun fromByte(b: Byte): VlessAddressType? = entries.find { it.value == b }
    }
}

object VlessProtocol {

    const val VERSION: Byte = 0x00

    /** Protobuf-encoded addons message: `{ string Flow = 1; bytes Seed = 2; }`. */
    private fun encodeAddons(flow: String?): ByteArray {
        if (flow.isNullOrEmpty()) return byteArrayOf()

        val flowBytes = flow.toByteArray(Charsets.UTF_8)
        val data = ByteArray(2 + flowBytes.size)
        data[0] = 0x0A // Field 1, wire type 2 (length-delimited)
        data[1] = flowBytes.size.toByte()
        System.arraycopy(flowBytes, 0, data, 2, flowBytes.size)
        return data
    }

    /**
     * Encodes a VLESS request header:
     * - 1 byte version (0x00)
     * - 16 bytes UUID
     * - 1 byte addons length (0 for no addons)
     * - 1 byte command
     * - 2 bytes port (big-endian)
     * - 1 byte address type
     * - Variable address data
     *
     * MUX command omits the address/port section.
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

        result.add(VERSION)
        result.addAll(uuidToBytes(uuid).toList())

        val addons = encodeAddons(flow)
        result.add(addons.size.toByte())
        if (addons.isNotEmpty()) {
            result.addAll(addons.toList())
        }

        result.add(command.value)

        if (command != VlessCommand.MUX) {
            result.add((destinationPort shr 8).toByte())
            result.add((destinationPort and 0xFF).toByte())

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
                    val domainBytes = destinationAddress.toByteArray(Charsets.UTF_8)
                    result.add(VlessAddressType.DOMAIN.value)
                    result.add(domainBytes.size.toByte())
                    result.addAll(domainBytes.toList())
                }
            }
        }

        return result.toByteArray()
    }

    /** Returns bytes consumed for the response header, or 0 if absent or incomplete. */
    fun decodeResponseHeader(data: ByteArray, offset: Int = 0): Int {
        val available = data.size - offset
        if (available < 2) return 0

        val version = data[offset]
        if (version != VERSION) return 0

        val addonsLength = data[offset + 1].toInt() and 0xFF
        val totalLength = 2 + addonsLength

        if (available < totalLength) return 0

        return totalLength
    }

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

        var parts = addr.split(":").toMutableList()

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
