package com.argsment.anywhere.vpn.protocol.tls

import com.argsment.anywhere.vpn.protocol.Transport

/**
 * Adapts a [TlsRecordConnection] to the [Transport] interface so that protocol
 * handshakes (e.g. SOCKS5, WebSocket) can run over a TLS-encrypted channel without
 * subclassing the VLESS connection hierarchy.
 *
 * Mirrors iOS `TLSRecordTransport` in `SOCKS5Connection.swift`.
 */
class TlsRecordTransport(private val tlsConnection: TlsRecordConnection) : Transport {

    override suspend fun send(data: ByteArray) = tlsConnection.send(data)

    override fun sendAsync(data: ByteArray) = tlsConnection.sendAsync(data)

    override suspend fun receive(): ByteArray? {
        val data = tlsConnection.receive() ?: return null
        return if (data.isEmpty()) null else data
    }

    override fun forceCancel() = tlsConnection.cancel()
}
