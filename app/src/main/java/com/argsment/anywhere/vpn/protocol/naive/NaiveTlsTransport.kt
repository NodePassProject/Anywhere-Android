package com.argsment.anywhere.vpn.protocol.naive

import android.util.Log
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.tls.TlsClient
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.NioSocket
import java.io.IOException

private const val TAG = "NaiveTls"

// -- Error --

sealed class NaiveTlsError(message: String) : IOException(message) {
    class ConnectionFailed(msg: String) : NaiveTlsError("Naive TLS connection failed: $msg")
    class NotConnected : NaiveTlsError("Naive TLS not connected")
}

/**
 * TLS transport for NaiveProxy connections using [NioSocket] + [TlsClient].
 *
 * Reuses Anywhere's existing TLS infrastructure to establish a TLS 1.3 connection
 * to the proxy server. The ALPN protocol list is configurable (e.g. ["h2"] for
 * HTTP/2, ["http/1.1"] for HTTP/1.1). After the handshake, all I/O goes through
 * a [TlsRecordConnection] which handles TLS record encryption/decryption.
 *
 * Supports both direct connections and connections tunneled through an existing
 * [VlessConnection] (for proxy chaining).
 */
class NaiveTlsTransport(
    private val host: String,
    private val port: Int,
    private val sni: String?,
    private val alpn: List<String> = listOf("h2"),
    private val tunnel: VlessConnection? = null
) {
    private var tlsConnection: TlsRecordConnection? = null
    var isReady = false
        private set

    // -- Connect --

    /**
     * Establishes a TLS connection to the proxy server.
     *
     * Uses [NioSocket] for TCP (or tunnels through an existing [VlessConnection])
     * and [TlsClient] for the TLS 1.3 handshake. On success, stores the
     * [TlsRecordConnection] for subsequent I/O.
     */
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
            Log.e(TAG, "Connection failed: ${e.message}")
            throw NaiveTlsError.ConnectionFailed(e.message ?: "Unknown error")
        }
    }

    // -- Send --

    /**
     * Sends data through the TLS connection.
     */
    suspend fun send(data: ByteArray) {
        val conn = tlsConnection
        if (conn == null || !isReady) throw NaiveTlsError.NotConnected()
        conn.send(data)
    }

    // -- Receive --

    /**
     * Receives decrypted data from the TLS connection.
     * Returns null for EOF.
     */
    suspend fun receive(): ByteArray? {
        val conn = tlsConnection
        if (conn == null || !isReady) throw NaiveTlsError.NotConnected()
        return conn.receive()
    }

    // -- Cancel --

    /** Closes the TLS connection and releases all resources. */
    fun cancel() {
        isReady = false
        tlsConnection?.cancel()
        tlsConnection = null
    }
}
