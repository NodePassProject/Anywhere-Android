package com.argsment.anywhere.vpn.protocol.trojan

import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger

private val logger = AnywhereLogger("Trojan-UDP")

/**
 * Wraps a TLS-backed transport as a Trojan UDP-over-TCP session.
 *
 * Each outgoing datagram is framed as `addr:port + length + CRLF + payload`
 * on top of the Trojan UDP request header (sent once). The inbound side
 * buffers stream bytes from TLS and emits one payload per `receiveRaw` call,
 * silently dropping the per-packet header — the upper layer only sees raw
 * UDP payloads addressed to the destination it originally requested.
 */
class TrojanUdpConnection(
    private val tlsConnection: TlsRecordConnection,
    password: String,
    private val dstHost: String,
    private val dstPort: Int
) : VlessConnection() {

    private val passwordKey: ByteArray = TrojanProtocol.passwordKey(password)

    private var headerSent = false
    /** Accumulates TLS stream bytes across receives. */
    private var receiveBuffer: ByteArray = ByteArray(0)
    private val lock = Any()

    init {
        responseHeaderReceived = true
    }

    override val isConnected: Boolean get() = true
    override val outerTlsVersion: TlsVersion?
        get() = if (tlsConnection.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12

    override suspend fun sendRaw(data: ByteArray) {
        tlsConnection.send(frame(data))
    }

    override fun sendRawAsync(data: ByteArray) {
        try {
            tlsConnection.sendAsync(frame(data))
        } catch (e: Exception) {
            logger.error("[Trojan-UDP] Send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? = deliverNextPacket()

    override fun cancel() {
        synchronized(lock) { receiveBuffer = ByteArray(0) }
        tlsConnection.cancel()
    }

    // -- Framing --

    /** Prepends the one-shot request header (first call only) to a framed UDP packet. */
    private fun frame(payload: ByteArray): ByteArray {
        val packet = TrojanProtocol.encodeUDPPacket(dstHost, dstPort, payload)
        synchronized(lock) {
            if (!headerSent) {
                headerSent = true
                val header = TrojanProtocol.buildRequestHeader(
                    passwordKey = passwordKey,
                    command = TrojanProtocol.COMMAND_UDP,
                    host = dstHost,
                    port = dstPort
                )
                return header + packet
            }
        }
        return packet
    }

    /** Tries to decode one complete packet; reads more bytes when buffer is short. */
    private suspend fun deliverNextPacket(): ByteArray? {
        while (true) {
            val parsed = synchronized(lock) {
                val res = TrojanProtocol.tryDecodeUDPPacket(receiveBuffer)
                if (res != null) {
                    receiveBuffer = receiveBuffer.copyOfRange(res.consumed, receiveBuffer.size)
                }
                res
            }
            if (parsed != null) return parsed.payload

            val data = tlsConnection.receive() ?: return null
            if (data.isEmpty()) return null
            synchronized(lock) {
                receiveBuffer = if (receiveBuffer.isEmpty()) data else receiveBuffer + data
            }
        }
    }
}
