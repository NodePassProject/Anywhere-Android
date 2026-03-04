package com.argsment.anywhere.vpn.protocol.websocket

import android.util.Base64
import android.util.Log
import com.argsment.anywhere.data.model.WebSocketConfiguration
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private const val TAG = "WebSocketConnection"

/**
 * WebSocket connection implementing RFC 6455 framing over an arbitrary transport.
 *
 * Suspend-based transport abstraction avoids modifying [NioSocket] or [TlsRecordConnection].
 *
 * Port of iOS WebSocketConnection.swift (474 lines) + WebSocketConfiguration.swift (73 lines).
 */
class WebSocketConnection private constructor(
    private val configuration: WebSocketConfiguration,
    private val transportSend: suspend (ByteArray) -> Unit,
    private val transportSendAsync: (ByteArray) -> Unit,
    private val transportReceive: suspend () -> ByteArray?,
    private val transportCancel: () -> Unit
) {
    // State
    private var receiveBuffer = ByteArray(0)
    private var receiveBufferLen = 0
    private val lock = ReentrantLock()
    private var _isConnected = true
    private var upgraded = false
    private val heartbeatScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var heartbeatJob: Job? = null

    val isConnected: Boolean
        get() = lock.withLock { _isConnected }

    companion object {
        /**
         * Chrome User-Agent string matching Xray-core's `utils.ChromeUA`.
         * Uses a fixed base version (Chrome 144, released 2026-01-13) and advances
         * by one version every ~35 days (midpoint of Xray-core's 25-45 day range).
         */
        val chromeUserAgent: String by lazy {
            val baseVersion = 144
            // Base date: 2026-01-13
            val baseDateMs = 1768348800000L // 2026-01-13 00:00:00 UTC in milliseconds
            val daysSinceBase = maxOf(0, ((System.currentTimeMillis() - baseDateMs) / 86400000L).toInt())
            val version = baseVersion + daysSinceBase / 35
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$version.0.0.0 Safari/537.36"
        }
    }

    // =========================================================================
    // Factory constructors
    // =========================================================================

    /**
     * Creates a WebSocket connection over a plain NioSocket.
     */
    constructor(socket: NioSocket, configuration: WebSocketConfiguration) : this(
        configuration = configuration,
        transportSend = { data -> socket.send(data) },
        transportSendAsync = { data -> socket.sendAsync(data) },
        transportReceive = { socket.receive() },
        transportCancel = { socket.forceCancel() }
    )

    /**
     * Creates a WebSocket connection over a TLS record connection (WSS).
     */
    constructor(tlsConnection: TlsRecordConnection, configuration: WebSocketConfiguration) : this(
        configuration = configuration,
        transportSend = { data -> tlsConnection.send(data) },
        transportSendAsync = { data -> tlsConnection.sendAsync(data) },
        transportReceive = { tlsConnection.receive() },
        transportCancel = { tlsConnection.cancel() }
    )

    // =========================================================================
    // HTTP Upgrade Handshake
    // =========================================================================

    /**
     * Performs the WebSocket HTTP upgrade handshake.
     *
     * @param earlyData Optional early data to embed in the upgrade request header.
     */
    suspend fun performUpgrade(earlyData: ByteArray? = null) {
        // Generate 16-byte random key, base64-encoded
        val keyBytes = ByteArray(16)
        SecureRandom().nextBytes(keyBytes)
        val wsKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)

        // Build HTTP upgrade request
        val sb = StringBuilder()
        sb.append("GET ${configuration.path} HTTP/1.1\r\n")
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("Upgrade: websocket\r\n")
        sb.append("Connection: Upgrade\r\n")
        sb.append("Sec-WebSocket-Key: $wsKey\r\n")
        sb.append("Sec-WebSocket-Version: 13\r\n")

        // Custom headers from configuration
        for ((key, value) in configuration.headers) {
            sb.append("$key: $value\r\n")
        }

        // Default User-Agent (Chrome UA) if not set in custom headers.
        // Matches Xray-core's GetRequestHeader() which sets utils.ChromeUA.
        if (configuration.headers.keys.none { it.equals("User-Agent", ignoreCase = true) }) {
            sb.append("User-Agent: $chromeUserAgent\r\n")
        }

        // Early data: base64url-encode and place in the configured header
        if (earlyData != null && earlyData.isNotEmpty() && configuration.maxEarlyData > 0) {
            val dataToEmbed = if (earlyData.size > configuration.maxEarlyData) {
                earlyData.copyOfRange(0, configuration.maxEarlyData)
            } else {
                earlyData
            }
            val encoded = base64URLEncode(dataToEmbed)
            sb.append("${configuration.earlyDataHeaderName}: $encoded\r\n")
        }

        sb.append("\r\n")

        val requestData = sb.toString().toByteArray(Charsets.UTF_8)
        transportSend(requestData)

        receiveUpgradeResponse()
    }

    /**
     * Reads the HTTP 101 response, buffers any leftover data after the header.
     */
    private suspend fun receiveUpgradeResponse() {
        while (true) {
            val data = transportReceive()

            if (data == null || data.isEmpty()) {
                throw WebSocketError.UpgradeFailed("Empty response from server")
            }

            lock.withLock {
                appendToReceiveBuffer(data)

                // Look for the end of HTTP headers (\r\n\r\n)
                val headerEndIdx = findHeaderEnd(receiveBuffer, receiveBufferLen)
                if (headerEndIdx < 0) {
                    // Haven't received the full header yet, keep reading
                    return@withLock null
                }

                val headerData = receiveBuffer.copyOfRange(0, headerEndIdx)
                val leftoverStart = headerEndIdx + 4 // skip \r\n\r\n
                val leftoverLen = receiveBufferLen - leftoverStart

                // Replace buffer with any leftover data after headers
                if (leftoverLen > 0) {
                    val leftover = receiveBuffer.copyOfRange(leftoverStart, receiveBufferLen)
                    receiveBuffer = leftover
                    receiveBufferLen = leftoverLen
                } else {
                    receiveBuffer = ByteArray(0)
                    receiveBufferLen = 0
                }

                // Validate HTTP 101 response
                val headerString = String(headerData, Charsets.UTF_8)
                val firstLine = headerString.split("\r\n", limit = 2).firstOrNull() ?: ""
                if (!firstLine.contains("101")) {
                    throw WebSocketError.UpgradeFailed("Expected HTTP 101, got: $firstLine")
                }

                upgraded = true
                return@withLock Unit
            } ?: continue // null means need more data

            // Upgrade complete
            startHeartbeat()
            return
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Sends data as a binary WebSocket frame (masked, opcode 0x02).
     */
    suspend fun send(data: ByteArray) {
        val frame = buildFrame(0x02, data)
        transportSend(frame)
    }

    /**
     * Sends data as a binary WebSocket frame without tracking completion.
     */
    fun sendAsync(data: ByteArray) {
        val frame = buildFrame(0x02, data)
        transportSendAsync(frame)
    }

    /**
     * Receives a complete WebSocket frame payload.
     * Uses a loop instead of recursion to handle control frames (Ping/Pong)
     * without risk of stack overflow from many consecutive control frames.
     */
    suspend fun receive(): ByteArray? {
        while (true) {
            // Try to extract a frame from buffered data
            val result = lock.withLock { tryExtractFrame() }
            if (result != null) {
                when (result) {
                    is FrameResult.Binary -> return result.data
                    is FrameResult.Ping -> {
                        val pongFrame = buildFrame(0x0A, result.data)
                        try { transportSend(pongFrame) } catch (_: Exception) {}
                        continue
                    }
                    is FrameResult.Pong -> continue
                    is FrameResult.Close -> {
                        val closePayload = byteArrayOf(
                            (result.code shr 8).toByte(),
                            (result.code and 0xFF).toByte()
                        )
                        val closeFrame = buildFrame(0x08, closePayload)
                        try { transportSend(closeFrame) } catch (_: Exception) {}
                        lock.withLock { _isConnected = false }
                        throw WebSocketError.ConnectionClosed(result.code, result.reason)
                    }
                }
            }

            // Need more data from transport
            val data = transportReceive()
            if (data == null || data.isEmpty()) return null
            lock.withLock { appendToReceiveBuffer(data) }
        }
    }

    /**
     * Cancels the connection.
     */
    fun cancel() {
        lock.withLock {
            _isConnected = false
            receiveBuffer = ByteArray(0)
            receiveBufferLen = 0
            heartbeatJob?.cancel()
            heartbeatJob = null
        }
        heartbeatScope.cancel()
        transportCancel()
    }

    // =========================================================================
    // Heartbeat (Ping Sender)
    // =========================================================================

    /**
     * Starts a periodic ping sender matching Xray-core's heartbeat behavior.
     * Sends a WebSocket Ping frame every heartbeatPeriod seconds.
     * Stops automatically if the send fails (connection closed).
     */
    private fun startHeartbeat() {
        val period = configuration.heartbeatPeriod.toLong()
        if (period <= 0) return

        val job = heartbeatScope.launch {
            while (true) {
                delay(period * 1000)
                if (!isConnected) break
                try {
                    val pingFrame = buildFrame(0x09, byteArrayOf())
                    transportSend(pingFrame)
                } catch (e: Exception) {
                    lock.withLock {
                        heartbeatJob?.cancel()
                        heartbeatJob = null
                    }
                    break
                }
            }
        }

        lock.withLock {
            heartbeatJob = job
        }
    }

    // =========================================================================
    // Frame Building (Client -> Server, MUST be masked)
    // =========================================================================

    /**
     * Builds a WebSocket frame with masking (client -> server).
     */
    private fun buildFrame(opcode: Int, payload: ByteArray): ByteArray {
        val length = payload.size
        var headerSize = 2 + 4 // minimum header + mask key
        if (length > 125) {
            headerSize += if (length <= 65535) 2 else 8
        }

        val frame = ByteArray(headerSize + length)
        var offset = 0

        // FIN=1, opcode
        frame[offset++] = (0x80 or opcode).toByte()

        // Mask bit = 1 + payload length
        if (length <= 125) {
            frame[offset++] = (length or 0x80).toByte()
        } else if (length <= 65535) {
            frame[offset++] = (126 or 0x80).toByte()
            frame[offset++] = ((length shr 8) and 0xFF).toByte()
            frame[offset++] = (length and 0xFF).toByte()
        } else {
            frame[offset++] = (127 or 0x80).toByte()
            for (i in 7 downTo 0) {
                frame[offset++] = ((length shr (i * 8)) and 0xFF).toByte()
            }
        }

        // 4-byte random mask key
        val maskKey = ByteArray(4)
        SecureRandom().nextBytes(maskKey)
        System.arraycopy(maskKey, 0, frame, offset, 4)
        offset += 4

        // XOR-masked payload
        for (i in 0 until length) {
            frame[offset + i] = (payload[i].toInt() xor maskKey[i and 3].toInt()).toByte()
        }

        return frame
    }

    // =========================================================================
    // Frame Parsing (Server -> Client, NOT masked)
    // =========================================================================

    /**
     * Result of attempting to extract a frame from the buffer.
     */
    private sealed class FrameResult {
        class Binary(val data: ByteArray) : FrameResult()
        class Ping(val data: ByteArray) : FrameResult()
        class Pong(val data: ByteArray) : FrameResult()
        class Close(val code: Int, val reason: String) : FrameResult()
    }

    /**
     * Tries to extract a complete frame from receiveBuffer. Must be called with lock held.
     */
    private fun tryExtractFrame(): FrameResult? {
        if (receiveBufferLen < 2) return null

        val byte0 = receiveBuffer[0].toInt() and 0xFF
        val byte1 = receiveBuffer[1].toInt() and 0xFF
        val isMasked = (byte1 and 0x80) != 0
        var payloadLength = (byte1 and 0x7F).toLong()
        var headerSize = 2

        if (payloadLength == 126L) {
            if (receiveBufferLen < 4) return null
            payloadLength = ((receiveBuffer[2].toInt() and 0xFF).toLong() shl 8) or
                    (receiveBuffer[3].toInt() and 0xFF).toLong()
            headerSize = 4
        } else if (payloadLength == 127L) {
            if (receiveBufferLen < 10) return null
            payloadLength = 0
            for (i in 0 until 8) {
                payloadLength = (payloadLength shl 8) or (receiveBuffer[2 + i].toInt() and 0xFF).toLong()
            }
            headerSize = 10
        }

        if (isMasked) {
            headerSize += 4
        }

        val totalFrameSize = headerSize + payloadLength.toInt()
        if (receiveBufferLen < totalFrameSize) return null

        // Extract payload
        val payload: ByteArray
        if (isMasked) {
            val maskStart = headerSize - 4
            val maskKey = byteArrayOf(
                receiveBuffer[maskStart],
                receiveBuffer[maskStart + 1],
                receiveBuffer[maskStart + 2],
                receiveBuffer[maskStart + 3]
            )
            payload = ByteArray(payloadLength.toInt())
            for (i in payload.indices) {
                payload[i] = (receiveBuffer[headerSize + i].toInt() xor maskKey[i and 3].toInt()).toByte()
            }
        } else {
            payload = receiveBuffer.copyOfRange(headerSize, headerSize + payloadLength.toInt())
        }

        // Consume the frame from the buffer
        val remaining = receiveBufferLen - totalFrameSize
        if (remaining > 0) {
            System.arraycopy(receiveBuffer, totalFrameSize, receiveBuffer, 0, remaining)
        }
        receiveBufferLen = remaining

        val opcode = byte0 and 0x0F
        return when (opcode) {
            0x01, 0x02 -> FrameResult.Binary(payload) // Text or Binary
            0x08 -> { // Close
                var code = 1005 // No status code
                var reason = ""
                if (payload.size >= 2) {
                    code = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
                    if (payload.size > 2) {
                        reason = String(payload, 2, payload.size - 2, Charsets.UTF_8)
                    }
                }
                FrameResult.Close(code, reason)
            }
            0x09 -> FrameResult.Ping(payload)
            0x0A -> FrameResult.Pong(payload)
            else -> FrameResult.Binary(payload)
        }
    }

    // handleFrameResult and receiveMore removed — logic inlined into receive() loop
    // to eliminate mutual recursion (handleFrameResult → receive → receiveMore → handleFrameResult)
    // that could cause StackOverflowError from consecutive Ping/Pong frames.

    // =========================================================================
    // Buffer Helpers
    // =========================================================================

    /**
     * Appends data to the receive buffer. Must be called with lock held.
     */
    private fun appendToReceiveBuffer(data: ByteArray) {
        if (receiveBufferLen + data.size > receiveBuffer.size) {
            val newSize = maxOf(receiveBuffer.size * 2, receiveBufferLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(receiveBuffer, 0, newBuf, 0, receiveBufferLen)
            receiveBuffer = newBuf
        }
        System.arraycopy(data, 0, receiveBuffer, receiveBufferLen, data.size)
        receiveBufferLen += data.size
    }

    /**
     * Finds the position of \r\n\r\n in the buffer, or returns -1.
     */
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

    // =========================================================================
    // Base64URL Encoding
    // =========================================================================

    /**
     * RFC 4648 base64url encoding (no padding).
     */
    private fun base64URLEncode(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}

// =============================================================================
// WebSocket Errors
// =============================================================================

/**
 * WebSocket transport errors.
 * Port of iOS WebSocketError enum.
 */
sealed class WebSocketError(message: String) : Exception(message) {
    class UpgradeFailed(reason: String) : WebSocketError("WebSocket upgrade failed: $reason")
    class InvalidFrame(reason: String) : WebSocketError("WebSocket invalid frame: $reason")
    class ConnectionClosed(val code: Int, val reason: String) :
        WebSocketError("WebSocket closed ($code): $reason")
}
