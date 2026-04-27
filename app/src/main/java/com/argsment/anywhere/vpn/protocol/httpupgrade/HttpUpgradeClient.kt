package com.argsment.anywhere.vpn.protocol.httpupgrade

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.HttpUpgradeConfiguration
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.websocket.WebSocketConnection
import com.argsment.anywhere.vpn.util.NioSocket
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val logger = AnywhereLogger("HttpUpgrade")

/**
 * HTTP upgrade connection that performs an HTTP upgrade handshake and then
 * passes data through as raw TCP bytes (no WebSocket framing).
 */
class HttpUpgradeConnection private constructor(
    private val configuration: HttpUpgradeConfiguration,
    private val transportSend: suspend (ByteArray) -> Unit,
    private val transportSendAsync: (ByteArray) -> Unit,
    private val transportReceive: suspend () -> ByteArray?,
    private val transportCancel: () -> Unit
) {
    private var leftoverBuffer = ByteArray(0)
    private var leftoverLen = 0
    private val lock = ReentrantLock()
    private var _isConnected = true

    val isConnected: Boolean
        get() = lock.withLock { _isConnected }

    companion object {
        val chromeUserAgent: String get() = WebSocketConnection.chromeUserAgent
    }

    constructor(socket: NioSocket, configuration: HttpUpgradeConfiguration) : this(
        configuration = configuration,
        transportSend = { data -> socket.send(data) },
        transportSendAsync = { data -> socket.sendAsync(data) },
        transportReceive = { socket.receive() },
        transportCancel = { socket.forceCancel() }
    )

    constructor(
        tlsConnection: TlsRecordConnection,
        configuration: HttpUpgradeConfiguration
    ) : this(
        configuration = configuration,
        transportSend = { data -> tlsConnection.send(data) },
        transportSendAsync = { data -> tlsConnection.sendAsync(data) },
        transportReceive = { tlsConnection.receive() },
        transportCancel = { tlsConnection.cancel() }
    )

    constructor(
        transport: Transport,
        configuration: HttpUpgradeConfiguration
    ) : this(
        configuration = configuration,
        transportSend = { data -> transport.send(data) },
        transportSendAsync = { data -> transport.sendAsync(data) },
        transportReceive = { transport.receive() },
        transportCancel = { transport.forceCancel() }
    )

    /**
     * Sends an HTTP GET with `Connection: Upgrade` and `Upgrade: websocket` headers,
     * then waits for HTTP 101.
     */
    suspend fun performUpgrade() {
        val sb = StringBuilder()
        sb.append("GET ${configuration.path} HTTP/1.1\r\n")
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("Connection: Upgrade\r\n")
        sb.append("Upgrade: websocket\r\n")

        // Custom headers first, then default User-Agent only if no user-supplied
        // header (case-insensitive). Mirrors iOS HTTPUpgradeConnection.swift:84-92.
        for ((key, value) in configuration.headers) {
            sb.append("$key: $value\r\n")
        }

        val hasUserAgent = configuration.headers.keys.any { it.equals("User-Agent", ignoreCase = true) }
        if (!hasUserAgent) {
            sb.append("User-Agent: $chromeUserAgent\r\n")
        }

        sb.append("\r\n")

        val requestData = sb.toString().toByteArray(Charsets.UTF_8)
        transportSend(requestData)

        receiveUpgradeResponse()
    }

    /**
     * Reads the HTTP 101 response and validates upgrade headers:
     * - Status must be "101 Switching Protocols"
     * - `Upgrade` header must be "websocket" (case-insensitive)
     * - `Connection` header must be "upgrade" (case-insensitive)
     */
    private suspend fun receiveUpgradeResponse() {
        while (true) {
            val data = transportReceive()

            if (data == null || data.isEmpty()) {
                throw HttpUpgradeError.UpgradeFailed("Empty response from server")
            }

            lock.withLock {
                appendToLeftover(data)

                val headerEndIdx = findHeaderEnd(leftoverBuffer, leftoverLen)
                if (headerEndIdx < 0) {
                    return@withLock null
                }

                val headerData = leftoverBuffer.copyOfRange(0, headerEndIdx)
                val bodyStart = headerEndIdx + 4 // skip \r\n\r\n
                val leftoverStart = bodyStart
                val remainingLen = leftoverLen - leftoverStart

                // Keep any leftover data after headers for the first receive
                if (remainingLen > 0) {
                    val remaining = leftoverBuffer.copyOfRange(leftoverStart, leftoverLen)
                    leftoverBuffer = remaining
                    leftoverLen = remainingLen
                } else {
                    leftoverBuffer = ByteArray(0)
                    leftoverLen = 0
                }

                val headerString = String(headerData, Charsets.UTF_8)
                val lines = headerString.split("\r\n")
                val statusLine = lines.firstOrNull()
                    ?: throw HttpUpgradeError.UpgradeFailed("Empty response")

                if (!statusLine.contains("101")) {
                    throw HttpUpgradeError.UpgradeFailed("Expected HTTP 101, got: $statusLine")
                }

                var hasUpgradeWebSocket = false
                var hasConnectionUpgrade = false
                for (line in lines.drop(1)) {
                    val parts = line.split(":", limit = 2)
                    if (parts.size != 2) continue
                    val key = parts[0].trim().lowercase()
                    val value = parts[1].trim().lowercase()
                    if (key == "upgrade" && value == "websocket") {
                        hasUpgradeWebSocket = true
                    }
                    if (key == "connection" && value == "upgrade") {
                        hasConnectionUpgrade = true
                    }
                }

                if (!hasUpgradeWebSocket || !hasConnectionUpgrade) {
                    throw HttpUpgradeError.UpgradeFailed(
                        "Missing Upgrade/Connection headers in 101 response"
                    )
                }

                return@withLock Unit
            } ?: continue

            return
        }
    }

    suspend fun send(data: ByteArray) {
        transportSend(data)
    }

    fun sendAsync(data: ByteArray) {
        transportSendAsync(data)
    }

    /** On the first call, returns any leftover data buffered from the HTTP upgrade response. */
    suspend fun receive(): ByteArray? {
        lock.withLock {
            if (leftoverLen > 0) {
                val data = leftoverBuffer.copyOfRange(0, leftoverLen)
                leftoverBuffer = ByteArray(0)
                leftoverLen = 0
                return data
            }
        }

        val data = transportReceive()
        if (data == null || data.isEmpty()) {
            return null
        }
        return data
    }

    fun cancel() {
        lock.withLock {
            _isConnected = false
            leftoverBuffer = ByteArray(0)
            leftoverLen = 0
        }
        transportCancel()
    }

    /** Must be called with lock held. */
    private fun appendToLeftover(data: ByteArray) {
        if (leftoverLen + data.size > leftoverBuffer.size) {
            val newSize = maxOf(leftoverBuffer.size * 2, leftoverLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(leftoverBuffer, 0, newBuf, 0, leftoverLen)
            leftoverBuffer = newBuf
        }
        System.arraycopy(data, 0, leftoverBuffer, leftoverLen, data.size)
        leftoverLen += data.size
    }

    private fun findHeaderEnd(buf: ByteArray, len: Int): Int {
        for (i in 0 until len - 3) {
            if (buf[i] == 0x0D.toByte() && buf[i + 1] == 0x0A.toByte() &&
                buf[i + 2] == 0x0D.toByte() && buf[i + 3] == 0x0A.toByte()
            ) {
                return i
            }
        }
        return -1
    }
}

sealed class HttpUpgradeError(message: String) : Exception(message) {
    class UpgradeFailed(reason: String) : HttpUpgradeError("HTTP upgrade failed: $reason")
}
