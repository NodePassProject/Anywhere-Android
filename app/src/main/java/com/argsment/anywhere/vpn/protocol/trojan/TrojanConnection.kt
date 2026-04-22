package com.argsment.anywhere.vpn.protocol.trojan

import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger

private val logger = AnywhereLogger("Trojan")

/**
 * Wraps a TLS-backed transport with the Trojan TCP request header.
 *
 * The header — `hex(sha224(password)) + CRLF + cmd + addr:port + CRLF` — is
 * prepended to the first `sendRaw` payload and travels inside the same TLS
 * record, matching Xray-core's `ConnWriter.Write`. The receive path is a
 * pass-through because Trojan servers reply without any framing of their own.
 */
class TrojanConnection(
    private val tlsConnection: TlsRecordConnection,
    password: String,
    destinationHost: String,
    destinationPort: Int
) : VlessConnection() {

    private var pendingHeader: ByteArray? = TrojanProtocol.buildRequestHeader(
        passwordKey = TrojanProtocol.passwordKey(password),
        command = TrojanProtocol.COMMAND_TCP,
        host = destinationHost,
        port = destinationPort
    )
    private val headerLock = Any()

    init {
        // Trojan servers reply without any framing header — no wait state.
        responseHeaderReceived = true
    }

    override val isConnected: Boolean get() = true
    override val outerTlsVersion: TlsVersion?
        get() = if (tlsConnection.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12

    override suspend fun sendRaw(data: ByteArray) {
        val payload = consumeHeader()?.let { it + data } ?: data
        tlsConnection.send(payload)
    }

    override fun sendRawAsync(data: ByteArray) {
        val payload = consumeHeader()?.let { it + data } ?: data
        try {
            tlsConnection.sendAsync(payload)
        } catch (e: Exception) {
            logger.error("[Trojan] Send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? = tlsConnection.receive()

    override fun cancel() = tlsConnection.cancel()

    /** Returns the request header on the first call and `null` thereafter. */
    private fun consumeHeader(): ByteArray? = synchronized(headerLock) {
        val header = pendingHeader
        pendingHeader = null
        header
    }
}
