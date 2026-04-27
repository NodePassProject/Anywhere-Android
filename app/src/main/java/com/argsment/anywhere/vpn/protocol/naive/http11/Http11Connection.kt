package com.argsment.anywhere.vpn.protocol.naive.http11

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsTransport
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsError

private val logger = AnywhereLogger("HTTP11")

/**
 * HTTP/1.1 CONNECT tunnel through a TLS proxy. Always uses padding type `NONE`
 * (HTTP/1.1 tunnels do not support NaiveProxy padding).
 */
class Http11Connection(
    private val transport: NaiveTlsTransport,
    private val configuration: NaiveConfiguration,
    /** The target `host:port` for the CONNECT tunnel. */
    private val destination: String
) {
    companion object {
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
    }

    val negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE

    private var connected = false

    val isConnected: Boolean get() = connected

    suspend fun openTunnel() {
        transport.connect()
        sendConnectRequest()
    }

    suspend fun sendData(data: ByteArray) {
        transport.send(data)
    }

    suspend fun receiveData(): ByteArray? {
        return transport.receive()
    }

    fun close() {
        connected = false
        transport.cancel()
    }

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

    private suspend fun receiveConnectResponse() {
        val accumulated = java.io.ByteArrayOutputStream()

        while (true) {
            val data = transport.receive()
            if (data == null || data.isEmpty()) {
                throw NaiveTlsError.ConnectionFailed("Connection closed during CONNECT")
            }

            accumulated.write(data)
            val bytes = accumulated.toByteArray()

            val headerEnd = findHeaderEnd(bytes)
            if (headerEnd < 0) continue

            val headerData = bytes.copyOfRange(0, headerEnd)
            val headerString = String(headerData, Charsets.UTF_8)
            val statusLine = headerString.takeWhile { it != '\r' && it != '\n' }
            val parts = statusLine.split(" ", limit = 3)

            if (parts.size < 2) {
                throw NaiveTlsError.ConnectionFailed("Malformed CONNECT status line")
            }

            if (!parts[0].startsWith("HTTP/1.")) {
                throw NaiveTlsError.ConnectionFailed("Invalid HTTP version in CONNECT response")
            }

            val statusCode = parts[1]
            if (statusCode != "200") {
                logger.error("CONNECT rejected: $statusLine")
                if (statusCode == "407") {
                    throw NaiveTlsError.ConnectionFailed("Proxy authentication required (407)")
                } else {
                    throw NaiveTlsError.ConnectionFailed("CONNECT failed with status $statusCode")
                }
            }

            // Reject extraneous data after the response headers (security hardening).
            val afterHeaders = headerEnd + 4
            if (afterHeaders < bytes.size) {
                throw NaiveTlsError.ConnectionFailed("Proxy sent extraneous data after CONNECT response")
            }

            connected = true
            return
        }
    }

    /** Finds the position of `\r\n\r\n`, returning the index of the first `\r`, or -1. */
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
