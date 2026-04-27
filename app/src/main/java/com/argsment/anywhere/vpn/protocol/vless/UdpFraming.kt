package com.argsment.anywhere.vpn.protocol.vless

/** UDP packet framing — packets are prefixed with a 2-byte big-endian length. */
object UdpFraming {

    fun frame(data: ByteArray): ByteArray {
        val length = data.size
        val framed = ByteArray(2 + length)
        framed[0] = (length shr 8).toByte()
        framed[1] = (length and 0xFF).toByte()
        System.arraycopy(data, 0, framed, 2, length)
        return framed
    }

    /** Returns null if [state] does not yet contain a complete packet. */
    fun extract(state: UdpBufferState): ByteArray? {
        val available = state.buffer.size - state.offset
        if (available < 2) return null

        val length = (state.buffer[state.offset].toInt() and 0xFF shl 8) or
                (state.buffer[state.offset + 1].toInt() and 0xFF)
        if (available < 2 + length) return null

        val packetStart = state.offset + 2
        val packet = state.buffer.copyOfRange(packetStart, packetStart + length)

        state.offset = packetStart + length

        if (state.offset > 8192) {
            state.buffer = state.buffer.copyOfRange(state.offset, state.buffer.size)
            state.offset = 0
        }

        return packet
    }
}

class UdpBufferState {
    var buffer: ByteArray = byteArrayOf()
    var offset: Int = 0

    fun append(data: ByteArray) {
        buffer = if (buffer.isEmpty() || offset >= buffer.size) {
            data
        } else {
            val remaining = buffer.copyOfRange(offset, buffer.size)
            offset = 0
            remaining + data
        }
    }

    fun clear() {
        buffer = byteArrayOf()
        offset = 0
    }
}
