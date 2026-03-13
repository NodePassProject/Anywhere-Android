package com.argsment.anywhere.vpn.protocol.naive.http11

import android.util.Log
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsTransport
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsError

private const val TAG = "Http11"

/**
 * HTTP/1.1 CONNECT tunnel through a TLS proxy.
 *
 * Handles the full HTTP/1.1 CONNECT lifecycle:
 * 1. TLS connection to the proxy server (via [NaiveTlsTransport])
 * 2. Send CONNECT request with Host, Proxy-Connection, User-Agent, and auth headers
 * 3. Parse the HTTP/1.1 response and validate status
 * 4. Bidirectional raw data relay through the tunnel
 *
 * Matches Chromium/NaiveProxy's CONNECT request format:
 * - `Proxy-Connection: keep-alive` for HTTP/1.0 proxy compatibility
 * - `User-Agent` header for probe resistance
 * - HTTP version validation on the response
 * - Rejects extraneous data after the 200 response (security hardening)
 *
 * Does not support NaiveProxy padding (HTTP/1.1 tunnels always use `.none`).
 */
class Http11Connection(
    private val transport: NaiveTlsTransport,
    private val configuration: NaiveConfiguration,
    /** The target `host:port` for the CONNECT tunnel. */
    private val destination: String
) {
    companion object {
        /** Chrome-like User-Agent for the CONNECT request. */
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
    }

    /** HTTP/1.1 CONNECT does not support NaiveProxy padding. */
    val negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE

    private var connected = false

    /** Whether the tunnel is open and ready for data transfer. */
    val isConnected: Boolean get() = connected

    // -- Open Tunnel --

    /**
     * Establishes the TLS connection and opens an HTTP/1.1 CONNECT tunnel.
     *
     * Performs the full setup sequence:
     * 1. TLS connection to the proxy server
     * 2. CONNECT request with proper headers
     * 3. Response validation (HTTP version, status code, no extraneous data)
     */
    suspend fun openTunnel() {
        transport.connect()
        sendConnectRequest()
    }

    // -- Data Transfer --

    /** Sends data through the CONNECT tunnel. */
    suspend fun sendData(data: ByteArray) {
        transport.send(data)
    }

    /** Receives data from the CONNECT tunnel. Returns null for EOF. */
    suspend fun receiveData(): ByteArray? {
        return transport.receive()
    }

    /** Closes the HTTP/1.1 connection. */
    fun close() {
        connected = false
        transport.cancel()
    }

    // -- CONNECT Request --

    /** Sends the HTTP/1.1 CONNECT request with headers matching Chromium/NaiveProxy. */
    private suspend fun sendConnectRequest() {
        val request = buildString {
            append("CONNECT $destination HTTP/1.1\r\n")
            append("Host: $destination\r\n")
            append("Proxy-Connection: keep-alive\r\n")
            append("User-Agent: $USER_AGENT\r\n")
            configuration.basicAuth?.let { auth ->
                append("Proxy-Authorization: Basic $auth\r\n")
            }
            append("\r\n")
        }

        transport.send(request.toByteArray(Charsets.UTF_8))
        receiveConnectResponse()
    }

    // -- CONNECT Response --

    /** Receives the HTTP/1.1 CONNECT response, buffering until the header terminator is found. */
    private suspend fun receiveConnectResponse() {
        val accumulated = java.io.ByteArrayOutputStream()

        while (true) {
            val data = transport.receive()
            if (data == null || data.isEmpty()) {
                throw NaiveTlsError.ConnectionFailed("Connection closed during CONNECT")
            }

            accumulated.write(data)
            val bytes = accumulated.toByteArray()

            // Look for end of HTTP headers (\r\n\r\n)
            val headerEnd = findHeaderEnd(bytes)
            if (headerEnd < 0) continue

            // Parse status line
            val headerData = bytes.copyOfRange(0, headerEnd)
            val headerString = String(headerData, Charsets.UTF_8)
            val statusLine = headerString.takeWhile { it != '\r' && it != '\n' }
            val parts = statusLine.split(" ", limit = 3)

            if (parts.size < 2) {
                throw NaiveTlsError.ConnectionFailed("Malformed CONNECT status line")
            }

            // Validate HTTP version (require HTTP/1.x, matching Chromium)
            if (!parts[0].startsWith("HTTP/1.")) {
                throw NaiveTlsError.ConnectionFailed("Invalid HTTP version in CONNECT response")
            }

            val statusCode = parts[1]
            if (statusCode != "200") {
                Log.e(TAG, "CONNECT rejected: $statusLine")
                if (statusCode == "407") {
                    throw NaiveTlsError.ConnectionFailed("Proxy authentication required (407)")
                } else {
                    throw NaiveTlsError.ConnectionFailed("CONNECT failed with status $statusCode")
                }
            }

            // Reject extraneous data after the headers (matching Chromium's security check)
            val afterHeaders = headerEnd + 4 // skip \r\n\r\n
            if (afterHeaders < bytes.size) {
                throw NaiveTlsError.ConnectionFailed("Proxy sent extraneous data after CONNECT response")
            }

            connected = true
            return
        }
    }

    /** Finds the position of `\r\n\r\n` in the data, returning the index of the first `\r`, or -1. */
    private fun findHeaderEnd(data: ByteArray): Int {
        if (data.size < 4) return -1
        for (i in 0..data.size - 4) {
            if (data[i] == 0x0D.toByte() &&
                data[i + 1] == 0x0A.toByte() &&
                data[i + 2] == 0x0D.toByte() &&
                data[i + 3] == 0x0A.toByte()
            ) {
                return i
            }
        }
        return -1
    }
}
