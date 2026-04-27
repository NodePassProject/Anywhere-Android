package com.argsment.anywhere.vpn.protocol.naive

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.tls.TlsClient
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.util.NioSocket
import java.io.IOException

private val logger = AnywhereLogger("NaiveTLS")

sealed class NaiveTlsError(message: String) : IOException(message) {
    class ConnectionFailed(msg: String) : NaiveTlsError("Naive TLS connection failed: $msg")
    class NotConnected : NaiveTlsError("Naive TLS not connected")
}

/**
 * TLS transport for NaiveProxy. ALPN is configurable per HTTP version
 * (`["h2"]` or `["http/1.1"]`). Supports direct connections and tunneled
 * connections through an existing [ProxyConnection].
 */
class NaiveTlsTransport(
    private val host: String,
    private val port: Int,
    private val sni: String?,
    private val alpn: List<String> = listOf("h2"),
    private val tunnel: ProxyConnection? = null
) {
    private var tlsConnection: TlsRecordConnection? = null
    var isReady = false
        private set

    suspend fun connect() {
        val config = TlsConfiguration(
            serverName = sni ?: host,
            alpn = alpn
        )
        val client = TlsClient(config)

        try {
            val connection = if (tunnel != null) {
                client.connect(TunneledTransport(tunnel))
            } else {
                client.connect(host, port)
            }
            tlsConnection = connection
            isReady = true
        } catch (e: Exception) {
            logger.error("Connection failed: ${e.message}")
            throw NaiveTlsError.ConnectionFailed(e.message ?: "Unknown error")
        }
    }

    suspend fun send(data: ByteArray) {
        val conn = tlsConnection
        if (conn == null || !isReady) throw NaiveTlsError.NotConnected()
        conn.send(data)
    }

    suspend fun receive(): ByteArray? {
        val conn = tlsConnection
        if (conn == null || !isReady) throw NaiveTlsError.NotConnected()
        return conn.receive()
    }

    fun cancel() {
        isReady = false
        tlsConnection?.cancel()
        tlsConnection = null
    }
}
