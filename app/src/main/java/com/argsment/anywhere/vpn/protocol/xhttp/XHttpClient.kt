package com.argsment.anywhere.vpn.protocol.xhttp

import android.util.Log
import com.argsment.anywhere.data.model.XHttpConfiguration
import com.argsment.anywhere.data.model.XHttpMode
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.util.NioSocket
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private const val TAG = "XHttpConnection"

/** Default User-Agent matching Xray-core's `utils.ChromeUA` (config.go:51-53). */
private const val DEFAULT_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

// =============================================================================
// Transport Closures
// =============================================================================

/**
 * Abstraction for the set of suspending functions that wrap the underlying transport
 * (NioSocket / TlsRecordConnection).
 */
class TransportClosures(
    val send: suspend (ByteArray) -> Unit,
    val sendAsync: (ByteArray) -> Unit,
    val receive: suspend () -> ByteArray?,
    val cancel: () -> Unit
)

// =============================================================================
// XHttpConnection
// =============================================================================

/**
 * XHTTP connection implementing both packet-up and stream-one modes.
 *
 * Uses the same transport abstraction as [com.argsment.anywhere.vpn.protocol.websocket.WebSocketConnection]
 * and [com.argsment.anywhere.vpn.protocol.httpupgrade.HttpUpgradeConnection].
 *
 * Port of iOS XHTTPConnection.swift (1123 lines) + XHTTPConfiguration.swift (109 lines).
 */
class XHttpConnection private constructor(
    val configuration: XHttpConfiguration,
    val mode: XHttpMode,
    val sessionId: String,
    private val useHTTP2: Boolean,
    // Download / stream-one connection
    private val downloadSend: suspend (ByteArray) -> Unit,
    private val downloadSendAsync: (ByteArray) -> Unit,
    private val downloadReceive: suspend () -> ByteArray?,
    private val downloadCancel: () -> Unit,
    // Upload connection factory (packet-up only)
    private val uploadConnectionFactory: (suspend () -> TransportClosures)?
) {
    // Upload connection state (packet-up only)
    private var uploadSend: (suspend (ByteArray) -> Unit)? = null
    private var uploadSendAsync: ((ByteArray) -> Unit)? = null
    private var uploadReceive: (suspend () -> ByteArray?)? = null
    private var uploadCancel: (() -> Unit)? = null

    // State
    private var nextSeq: Long = 0
    private var chunkedDecoder = ChunkedTransferDecoder()
    private var downloadHeadersParsed = false
    private var _isConnected = true
    private val lock = ReentrantLock()

    /** Leftover data after HTTP response headers. */
    private var headerBuffer = ByteArray(0)
    private var headerBufferLen = 0

    // HTTP/2 state (for Reality + stream-one)
    private var h2ReadBuffer = ByteArray(0)
    private var h2ReadBufferLen = 0
    private var h2DataBuffer = ByteArray(0)
    private var h2DataBufferLen = 0
    private var h2PeerWindowSize: Int = 65535
    private var h2LocalWindowSize: Int = 65535
    private var h2MaxFrameSize: Int = 16384
    private var h2ResponseReceived = false
    private var h2StreamClosed = false

    val isConnected: Boolean
        get() = lock.withLock { _isConnected }

    // =========================================================================
    // Factory constructors
    // =========================================================================

    /**
     * Creates an XHTTP connection over a plain NioSocket (security=none).
     */
    constructor(
        socket: NioSocket,
        configuration: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        useHTTP2: Boolean = false,
        uploadConnectionFactory: (suspend () -> TransportClosures)? = null
    ) : this(
        configuration = configuration,
        mode = mode,
        sessionId = sessionId,
        useHTTP2 = useHTTP2,
        downloadSend = { data -> socket.send(data) },
        downloadSendAsync = { data -> socket.sendAsync(data) },
        downloadReceive = { socket.receive() },
        downloadCancel = { socket.forceCancel() },
        uploadConnectionFactory = uploadConnectionFactory
    )

    /**
     * Creates an XHTTP connection over a TLS record connection (security=tls or reality).
     */
    constructor(
        tlsConnection: TlsRecordConnection,
        configuration: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String,
        useHTTP2: Boolean = false,
        uploadConnectionFactory: (suspend () -> TransportClosures)? = null
    ) : this(
        configuration = configuration,
        mode = mode,
        sessionId = sessionId,
        useHTTP2 = useHTTP2,
        downloadSend = { data -> tlsConnection.send(data) },
        downloadSendAsync = { data -> tlsConnection.sendAsync(data) },
        downloadReceive = { tlsConnection.receive() },
        downloadCancel = { tlsConnection.cancel() },
        uploadConnectionFactory = uploadConnectionFactory
    )

    // =========================================================================
    // X-Padding (matching Xray-core xpadding.go)
    // =========================================================================

    /**
     * Generates the `Referer` header value containing X-Padding.
     *
     * Default non-obfs mode: `Referer: https://{host}{path}?x_padding=XXX...`
     * Server validates padding length is within 100-1000 bytes (default range).
     * Matches Xray-core `ApplyXPaddingToRequest` with `PlacementQueryInHeader`.
     */
    private fun generatePaddingReferer(forPath: String): String {
        val length = (100..1000).random()
        val padding = "X".repeat(length)
        return "https://${configuration.host}${forPath}?x_padding=$padding"
    }

    // =========================================================================
    // Setup
    // =========================================================================

    /**
     * Performs the initial HTTP handshake (sends the initial request and reads the response headers).
     *
     * - For stream-one mode: sends a POST with `Transfer-Encoding: chunked` and reads the response headers.
     * - For packet-up mode: sends a GET request for the download stream, reads response headers,
     *   and establishes the upload connection via the factory.
     */
    suspend fun performSetup() {
        if (useHTTP2) {
            performH2Setup()
        } else if (mode == XHttpMode.STREAM_ONE) {
            performStreamOneSetup()
        } else {
            performPacketUpSetup()
        }
    }

    // MARK: stream-one Setup

    private suspend fun performStreamOneSetup() {
        val sb = StringBuilder()
        sb.append("POST ${configuration.normalizedPath} HTTP/1.1\r\n")
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        sb.append("Referer: ${generatePaddingReferer(configuration.normalizedPath)}\r\n")
        sb.append("Transfer-Encoding: chunked\r\n")
        if (!configuration.noGrpcHeader) {
            sb.append("Content-Type: application/grpc\r\n")
        }
        for ((key, value) in configuration.headers) {
            if (key != "User-Agent") {
                sb.append("$key: $value\r\n")
            }
        }
        sb.append("\r\n")

        val requestData = sb.toString().toByteArray(Charsets.UTF_8)
        downloadSend(requestData)

        receiveResponseHeaders()
    }

    // MARK: packet-up Setup

    private suspend fun performPacketUpSetup() {
        // Send GET request on the download connection
        val getPath = "${configuration.normalizedPath}${sessionId}/"
        val sb = StringBuilder()
        sb.append("GET $getPath HTTP/1.1\r\n")
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        sb.append("Referer: ${generatePaddingReferer(getPath)}\r\n")
        for ((key, value) in configuration.headers) {
            if (key != "User-Agent") {
                sb.append("$key: $value\r\n")
            }
        }
        sb.append("\r\n")

        val requestData = sb.toString().toByteArray(Charsets.UTF_8)
        downloadSend(requestData)

        // Read GET response headers
        receiveResponseHeaders()

        // Establish the upload connection
        val factory = uploadConnectionFactory
            ?: throw XHttpError.SetupFailed("No upload connection factory")

        val closures = factory()
        lock.withLock {
            uploadSend = closures.send
            uploadSendAsync = closures.sendAsync
            uploadReceive = closures.receive
            uploadCancel = closures.cancel
        }
    }

    // =========================================================================
    // HTTP Response Header Parsing
    // =========================================================================

    /**
     * Reads bytes from the download connection until `\r\n\r\n` is found.
     * Validates the status line contains "200".
     */
    private suspend fun receiveResponseHeaders() {
        while (true) {
            val data = downloadReceive()

            if (data == null || data.isEmpty()) {
                throw XHttpError.SetupFailed("Empty response from server")
            }

            lock.withLock {
                appendToHeaderBuffer(data)

                val headerEndIdx = findHeaderEnd(headerBuffer, headerBufferLen)
                if (headerEndIdx < 0) {
                    // Haven't received the full header yet, keep reading
                    return@withLock null
                }

                val headerData = headerBuffer.copyOfRange(0, headerEndIdx)
                val bodyStart = headerEndIdx + 4 // skip \r\n\r\n
                val leftoverLen = headerBufferLen - bodyStart
                downloadHeadersParsed = true

                // Feed leftover data into chunked decoder
                if (leftoverLen > 0) {
                    val leftover = headerBuffer.copyOfRange(bodyStart, headerBufferLen)
                    chunkedDecoder.feed(leftover)
                }
                headerBuffer = ByteArray(0)
                headerBufferLen = 0

                // Validate HTTP 200 response
                val headerString = String(headerData, Charsets.UTF_8)
                val firstLine = headerString.split("\r\n", limit = 2).firstOrNull() ?: ""
                if (!firstLine.contains("200")) {
                    throw XHttpError.HttpError("Expected HTTP 200, got: $firstLine")
                }

                return@withLock Unit
            } ?: continue // null means need more data

            // Headers parsed
            return
        }
    }

    // =========================================================================
    // Send
    // =========================================================================

    /**
     * Sends data through the XHTTP connection.
     */
    suspend fun send(data: ByteArray) {
        if (useHTTP2) {
            sendH2Data(data)
        } else if (mode == XHttpMode.STREAM_ONE) {
            sendStreamOne(data)
        } else {
            sendPacketUp(data)
        }
    }

    /**
     * Sends data without tracking completion.
     */
    fun sendAsync(data: ByteArray) {
        if (useHTTP2) {
            // For H2, build frame and send async
            lock.withLock {
                val maxSize = h2MaxFrameSize
                if (data.size <= maxSize) {
                    val frame = buildH2Frame(H2_FRAME_DATA, 0, 1u, data)
                    downloadSendAsync(frame)
                } else {
                    val firstChunk = data.copyOfRange(0, maxSize)
                    val frame = buildH2Frame(H2_FRAME_DATA, 0, 1u, firstChunk)
                    downloadSendAsync(frame)
                    // Remaining chunks are best-effort async
                    var offset = maxSize
                    while (offset < data.size) {
                        val end = minOf(offset + maxSize, data.size)
                        val chunk = data.copyOfRange(offset, end)
                        downloadSendAsync(buildH2Frame(H2_FRAME_DATA, 0, 1u, chunk))
                        offset = end
                    }
                }
            }
        } else if (mode == XHttpMode.STREAM_ONE) {
            val chunk = ChunkedTransferEncoder.encode(data)
            downloadSendAsync(chunk)
        } else {
            // packet-up mode: must use suspending send, best-effort async via fire-and-forget
            lock.withLock {
                val upSendAsync = uploadSendAsync ?: return
                val seq = nextSeq
                nextSeq++

                val postPath = "${configuration.normalizedPath}${sessionId}/$seq"
                val sb = StringBuilder()
                sb.append("POST $postPath HTTP/1.1\r\n")
                sb.append("Host: ${configuration.host}\r\n")
                sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
                sb.append("Referer: ${generatePaddingReferer(postPath)}\r\n")
                sb.append("Content-Length: ${data.size}\r\n")
                if (!configuration.noGrpcHeader) {
                    sb.append("Content-Type: application/grpc\r\n")
                }
                sb.append("Connection: keep-alive\r\n")
                for ((key, value) in configuration.headers) {
                    if (key != "User-Agent") {
                        sb.append("$key: $value\r\n")
                    }
                }
                sb.append("\r\n")

                val requestData = sb.toString().toByteArray(Charsets.UTF_8) + data
                upSendAsync(requestData)
            }
        }
    }

    // MARK: stream-one Send

    /**
     * Sends data as a chunked-encoded chunk on the stream-one POST.
     */
    private suspend fun sendStreamOne(data: ByteArray) {
        val chunk = ChunkedTransferEncoder.encode(data)
        downloadSend(chunk)
    }

    // MARK: packet-up Send

    /**
     * Sends data as a POST request with sequence number on the upload connection.
     */
    private suspend fun sendPacketUp(data: ByteArray) {
        val upSend: suspend (ByteArray) -> Unit
        val upReceive: suspend () -> ByteArray?
        val seq: Long

        lock.withLock {
            upSend = uploadSend
                ?: throw XHttpError.SetupFailed("Upload connection not established")
            upReceive = uploadReceive
                ?: throw XHttpError.SetupFailed("Upload connection not established")
            seq = nextSeq
            nextSeq++
        }

        // Split data into chunks of scMaxEachPostBytes
        val maxSize = configuration.scMaxEachPostBytes
        if (data.size <= maxSize) {
            sendSinglePost(data, seq, upSend, upReceive)
        } else {
            // Send first chunk with current seq, remaining chunks will use subsequent seqs
            val firstChunk = data.copyOfRange(0, maxSize)
            val remaining = data.copyOfRange(maxSize, data.size)
            sendSinglePost(firstChunk, seq, upSend, upReceive)
            // Recurse for remaining data
            sendPacketUp(remaining)
        }
    }

    /**
     * Sends a single POST request and reads the 200 OK response.
     */
    private suspend fun sendSinglePost(
        data: ByteArray,
        seq: Long,
        upSend: suspend (ByteArray) -> Unit,
        upReceive: suspend () -> ByteArray?
    ) {
        val postPath = "${configuration.normalizedPath}${sessionId}/$seq"
        val sb = StringBuilder()
        sb.append("POST $postPath HTTP/1.1\r\n")
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        sb.append("Referer: ${generatePaddingReferer(postPath)}\r\n")
        sb.append("Content-Length: ${data.size}\r\n")
        if (!configuration.noGrpcHeader) {
            sb.append("Content-Type: application/grpc\r\n")
        }
        sb.append("Connection: keep-alive\r\n")
        for ((key, value) in configuration.headers) {
            if (key != "User-Agent") {
                sb.append("$key: $value\r\n")
            }
        }
        sb.append("\r\n")

        val requestData = sb.toString().toByteArray(Charsets.UTF_8) + data
        upSend(requestData)

        // Read the 200 OK response
        readPostResponse(upReceive)
    }

    /**
     * Reads the HTTP response to a POST request, looking for the end of headers.
     */
    private suspend fun readPostResponse(upReceive: suspend () -> ByteArray?) {
        var buf = ByteArray(0)
        var bufLen = 0

        while (true) {
            val data = upReceive()

            if (data == null || data.isEmpty()) {
                throw XHttpError.HttpError("Empty POST response")
            }

            // Append to local buffer
            if (bufLen + data.size > buf.size) {
                val newBuf = ByteArray(maxOf(buf.size * 2, bufLen + data.size))
                System.arraycopy(buf, 0, newBuf, 0, bufLen)
                buf = newBuf
            }
            System.arraycopy(data, 0, buf, bufLen, data.size)
            bufLen += data.size

            val headerEndIdx = findHeaderEnd(buf, bufLen)
            if (headerEndIdx < 0) {
                // Haven't received the full header yet, keep reading
                continue
            }

            val headerData = buf.copyOfRange(0, headerEndIdx)
            val headerString = String(headerData, Charsets.UTF_8)
            val firstLine = headerString.split("\r\n", limit = 2).firstOrNull() ?: ""
            if (!firstLine.contains("200")) {
                throw XHttpError.HttpError("POST response error: $firstLine")
            }

            return
        }
    }

    // =========================================================================
    // Receive
    // =========================================================================

    /**
     * Receives data from the download stream.
     */
    suspend fun receive(): ByteArray? {
        if (useHTTP2) {
            return receiveH2Data()
        }

        lock.withLock {
            // Try to get data from chunked decoder buffer first
            val decoded = chunkedDecoder.nextChunk()
            if (decoded != null) {
                return decoded
            }

            if (chunkedDecoder.isFinished) {
                return null
            }
        }

        // Need more data from download connection
        while (true) {
            val data = downloadReceive()

            if (data == null || data.isEmpty()) {
                return null // EOF
            }

            lock.withLock {
                chunkedDecoder.feed(data)

                val decoded = chunkedDecoder.nextChunk()
                if (decoded != null) {
                    return decoded
                }

                if (chunkedDecoder.isFinished) {
                    return null
                }
            }

            // Not enough data for a full chunk, keep reading
        }
    }

    // =========================================================================
    // Cancel
    // =========================================================================

    /**
     * Cancels the connection and releases resources.
     */
    fun cancel() {
        val uploadCancelFn: (() -> Unit)?
        lock.withLock {
            _isConnected = false
            chunkedDecoder = ChunkedTransferDecoder()
            headerBuffer = ByteArray(0)
            headerBufferLen = 0
            h2ReadBuffer = ByteArray(0)
            h2ReadBufferLen = 0
            h2DataBuffer = ByteArray(0)
            h2DataBufferLen = 0
            h2StreamClosed = true
            uploadCancelFn = uploadCancel
            uploadSend = null
            uploadSendAsync = null
            uploadReceive = null
            uploadCancel = null
        }

        downloadCancel()
        uploadCancelFn?.invoke()
    }

    // =========================================================================
    // HTTP/2 Support (RFC 7540)
    // =========================================================================

    // HTTP/2 Constants
    companion object {
        /** HTTP/2 connection preface (RFC 7540 S3.5). */
        private val H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.UTF_8)

        /** HTTP/2 frame header size. */
        private const val H2_FRAME_HEADER_SIZE = 9

        // Frame types
        private const val H2_FRAME_DATA: Byte = 0x00
        private const val H2_FRAME_HEADERS: Byte = 0x01
        private const val H2_FRAME_SETTINGS: Byte = 0x04
        private const val H2_FRAME_PING: Byte = 0x06
        private const val H2_FRAME_GOAWAY: Byte = 0x07
        private const val H2_FRAME_WINDOW_UPDATE: Byte = 0x08
        private const val H2_FRAME_RST_STREAM: Byte = 0x03

        // Flags
        private const val H2_FLAG_END_STREAM: Byte = 0x01
        private const val H2_FLAG_END_HEADERS: Byte = 0x04
        private const val H2_FLAG_ACK: Byte = 0x01

        // Go http2 transport defaults
        private const val H2_STREAM_WINDOW_SIZE: Int = 4_194_304  // 4MB
        private const val H2_CONN_WINDOW_SIZE: Int = 1_073_741_824  // 1GB
    }

    // MARK: HTTP/2 Frame I/O

    /**
     * Builds an HTTP/2 frame.
     */
    private fun buildH2Frame(type: Byte, flags: Byte, streamId: UInt, payload: ByteArray): ByteArray {
        val frame = ByteArray(H2_FRAME_HEADER_SIZE + payload.size)
        val len = payload.size
        // Length (24-bit)
        frame[0] = ((len shr 16) and 0xFF).toByte()
        frame[1] = ((len shr 8) and 0xFF).toByte()
        frame[2] = (len and 0xFF).toByte()
        // Type
        frame[3] = type
        // Flags
        frame[4] = flags
        // Stream ID (31-bit, R=0)
        val sid = streamId.toInt() and 0x7FFFFFFF
        frame[5] = ((sid shr 24) and 0xFF).toByte()
        frame[6] = ((sid shr 16) and 0xFF).toByte()
        frame[7] = ((sid shr 8) and 0xFF).toByte()
        frame[8] = (sid and 0xFF).toByte()
        // Payload
        System.arraycopy(payload, 0, frame, H2_FRAME_HEADER_SIZE, payload.size)
        return frame
    }

    private data class H2Frame(val type: Byte, val flags: Byte, val streamId: UInt, val payload: ByteArray)

    /**
     * Attempts to parse one complete frame from h2ReadBuffer.
     * Returns frame or null if not enough data. Must be called with lock held.
     */
    private fun parseH2Frame(): H2Frame? {
        if (h2ReadBufferLen < H2_FRAME_HEADER_SIZE) return null

        val length = ((h2ReadBuffer[0].toInt() and 0xFF) shl 16) or
                ((h2ReadBuffer[1].toInt() and 0xFF) shl 8) or
                (h2ReadBuffer[2].toInt() and 0xFF)
        val type = h2ReadBuffer[3]
        val flags = h2ReadBuffer[4]
        val streamId = (((h2ReadBuffer[5].toInt() and 0xFF) shl 24) or
                ((h2ReadBuffer[6].toInt() and 0xFF) shl 16) or
                ((h2ReadBuffer[7].toInt() and 0xFF) shl 8) or
                (h2ReadBuffer[8].toInt() and 0xFF)).toUInt() and 0x7FFFFFFFu

        val totalSize = H2_FRAME_HEADER_SIZE + length
        if (h2ReadBufferLen < totalSize) return null

        val payload = h2ReadBuffer.copyOfRange(H2_FRAME_HEADER_SIZE, totalSize)

        // Remove parsed frame from buffer
        val remaining = h2ReadBufferLen - totalSize
        if (remaining > 0) {
            System.arraycopy(h2ReadBuffer, totalSize, h2ReadBuffer, 0, remaining)
        }
        h2ReadBufferLen = remaining

        return H2Frame(type, flags, streamId, payload)
    }

    /**
     * Reads from transport into h2ReadBuffer until at least one full frame is available,
     * then parses and returns it.
     */
    private suspend fun readH2Frame(): H2Frame {
        lock.withLock {
            val frame = parseH2Frame()
            if (frame != null) return frame
        }

        while (true) {
            val data = downloadReceive()
                ?: throw XHttpError.ConnectionClosed

            if (data.isEmpty()) throw XHttpError.ConnectionClosed

            lock.withLock {
                appendToH2ReadBuffer(data)

                val frame = parseH2Frame()
                if (frame != null) return frame
            }
        }
    }

    // MARK: HTTP/2 HPACK Encoder (simplified, no Huffman)

    /**
     * Encodes an integer with the given prefix bit width (RFC 7541 S5.1).
     */
    private fun hpackEncodeInteger(value: Int, prefixBits: Int): ByteArray {
        val maxPrefix = (1 shl prefixBits) - 1
        if (value < maxPrefix) {
            return byteArrayOf(value.toByte())
        }
        val result = mutableListOf<Byte>(maxPrefix.toByte())
        var remaining = value - maxPrefix
        while (remaining >= 128) {
            result.add(((remaining and 0x7F) or 0x80).toByte())
            remaining = remaining shr 7
        }
        result.add(remaining.toByte())
        return result.toByteArray()
    }

    /**
     * Encodes a plain (non-Huffman) string (RFC 7541 S5.2).
     */
    private fun hpackEncodeString(string: String): ByteArray {
        val bytes = string.toByteArray(Charsets.UTF_8)
        // H=0 (no Huffman), length with 7-bit prefix
        val lenBytes = hpackEncodeInteger(bytes.size, 7)
        lenBytes[0] = (lenBytes[0].toInt() and 0x7F).toByte() // Clear H bit
        return lenBytes + bytes
    }

    /**
     * Encodes a request header block for stream-one POST.
     */
    private fun encodeH2RequestHeaders(): ByteArray {
        val block = mutableListOf<Byte>()

        // :method POST -- static table index 3 (exact match)
        block.add(0x83.toByte())
        // :scheme https -- static table index 7 (exact match)
        block.add(0x87.toByte())

        // :path -- literal without indexing, name index 4
        val path = configuration.normalizedPath
        if (path == "/") {
            block.add(0x84.toByte()) // Indexed: :path / (index 4)
        } else {
            val pathBytes = hpackEncodeInteger(4, 4)
            pathBytes[0] = (pathBytes[0].toInt() and 0x0F).toByte()
            block.addAll(pathBytes.toList())
            block.addAll(hpackEncodeString(path).toList())
        }

        // :authority -- literal without indexing, name index 1
        val authBytes = hpackEncodeInteger(1, 4)
        authBytes[0] = (authBytes[0].toInt() and 0x0F).toByte()
        block.addAll(authBytes.toList())
        block.addAll(hpackEncodeString(configuration.host).toList())

        // content-type: application/grpc (if enabled)
        if (!configuration.noGrpcHeader) {
            val ctBytes = hpackEncodeInteger(31, 4)
            ctBytes[0] = (ctBytes[0].toInt() and 0x0F).toByte()
            block.addAll(ctBytes.toList())
            block.addAll(hpackEncodeString("application/grpc").toList())
        }

        // user-agent -- name index 58
        val ua = configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT
        val uaBytes = hpackEncodeInteger(58, 4)
        uaBytes[0] = (uaBytes[0].toInt() and 0x0F).toByte()
        block.addAll(uaBytes.toList())
        block.addAll(hpackEncodeString(ua).toList())

        // referer (X-Padding) -- name index 51
        val referer = generatePaddingReferer(configuration.normalizedPath)
        val refBytes = hpackEncodeInteger(51, 4)
        refBytes[0] = (refBytes[0].toInt() and 0x0F).toByte()
        block.addAll(refBytes.toList())
        block.addAll(hpackEncodeString(referer).toList())

        // Custom headers (literal, new names)
        for ((key, value) in configuration.headers) {
            if (key != "User-Agent") {
                // 0x00 = literal without indexing, new name
                block.add(0x00)
                block.addAll(hpackEncodeString(key.lowercase()).toList())
                block.addAll(hpackEncodeString(value).toList())
            }
        }

        return block.toByteArray()
    }

    /**
     * Checks if the HEADERS response block starts with :status 200.
     */
    private fun checkH2ResponseStatus(headerBlock: ByteArray): Boolean {
        if (headerBlock.isEmpty()) return false
        // 0x88 = indexed representation of :status 200 (static table index 8)
        if ((headerBlock[0].toInt() and 0xFF) == 0x88) return true
        // Also accept literal with name index 8, value "200"
        // 0x48 = literal with incremental indexing, name index 8
        if (headerBlock.size >= 5 && (headerBlock[0].toInt() and 0xFF) == 0x48) {
            val valueStart = 2 // skip 0x48 and length byte
            if ((headerBlock[1].toInt() and 0xFF) == 0x03 && headerBlock.size >= valueStart + 3) {
                val value = String(headerBlock, valueStart, 3, Charsets.US_ASCII)
                return value == "200"
            }
        }
        return false
    }

    // MARK: HTTP/2 Setup

    /**
     * Performs HTTP/2 connection setup: sends preface + SETTINGS + WINDOW_UPDATE,
     * exchanges settings with server, sends HEADERS for the stream-one POST.
     */
    private suspend fun performH2Setup() {
        var initData = ByteArray(0)

        // 1. Connection preface
        initData += H2_PREFACE

        // 2. Client SETTINGS frame
        val settingsPayload = byteArrayOf(
            // ENABLE_PUSH = 0
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // INITIAL_WINDOW_SIZE = 4MB
            0x00, 0x04,
            ((H2_STREAM_WINDOW_SIZE shr 24) and 0xFF).toByte(),
            ((H2_STREAM_WINDOW_SIZE shr 16) and 0xFF).toByte(),
            ((H2_STREAM_WINDOW_SIZE shr 8) and 0xFF).toByte(),
            (H2_STREAM_WINDOW_SIZE and 0xFF).toByte()
        )
        initData += buildH2Frame(H2_FRAME_SETTINGS, 0, 0u, settingsPayload)

        // 3. Connection-level WINDOW_UPDATE (increase from default 65535 to 1GB)
        val windowIncrement = H2_CONN_WINDOW_SIZE - 65535
        val wuPayload = byteArrayOf(
            ((windowIncrement shr 24) and 0xFF).toByte(),
            ((windowIncrement shr 16) and 0xFF).toByte(),
            ((windowIncrement shr 8) and 0xFF).toByte(),
            (windowIncrement and 0xFF).toByte()
        )
        initData += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 0u, wuPayload)

        // 4. HEADERS frame for stream 1 (the stream-one POST request)
        val headerBlock = encodeH2RequestHeaders()
        // END_HEADERS (0x04), but NOT END_STREAM (body follows)
        initData += buildH2Frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1u, headerBlock)

        // Send all at once
        downloadSend(initData)

        // Read server frames until we get SETTINGS and HEADERS response
        readH2SetupFrames()
    }

    /**
     * Reads server frames during setup: process SETTINGS, wait for HEADERS response.
     */
    private suspend fun readH2SetupFrames() {
        while (true) {
            val frame = readH2Frame()

            when (frame.type) {
                H2_FRAME_SETTINGS -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) != 0) {
                        // SETTINGS ACK
                    } else {
                        // Server's SETTINGS -- parse and send ACK
                        parseH2Settings(frame.payload)
                        val ack = buildH2Frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0u, byteArrayOf())
                        try { downloadSend(ack) } catch (_: Exception) {}
                    }
                    // Keep reading until we get HEADERS response
                    continue
                }
                H2_FRAME_HEADERS -> {
                    // Response headers for stream 1
                    if (checkH2ResponseStatus(frame.payload)) {
                        lock.withLock { h2ResponseReceived = true }
                        return
                    } else {
                        throw XHttpError.HttpError("H2 response status is not 200")
                    }
                }
                H2_FRAME_WINDOW_UPDATE -> {
                    lock.withLock {
                        if (frame.payload.size >= 4) {
                            val increment = ((frame.payload[0].toInt() and 0xFF) shl 24) or
                                    ((frame.payload[1].toInt() and 0xFF) shl 16) or
                                    ((frame.payload[2].toInt() and 0xFF) shl 8) or
                                    (frame.payload[3].toInt() and 0xFF)
                            h2PeerWindowSize += increment and 0x7FFFFFFF
                        }
                    }
                    continue
                }
                H2_FRAME_PING -> {
                    // Send PONG
                    val pong = buildH2Frame(H2_FRAME_PING, H2_FLAG_ACK, 0u, frame.payload)
                    try { downloadSend(pong) } catch (_: Exception) {}
                    continue
                }
                H2_FRAME_GOAWAY -> {
                    throw XHttpError.SetupFailed("Server sent GOAWAY during setup")
                }
                H2_FRAME_DATA -> {
                    // Early DATA before we saw HEADERS -- buffer it
                    lock.withLock {
                        appendToH2DataBuffer(frame.payload)
                    }
                    continue
                }
                else -> {
                    // Ignore unknown frames
                    continue
                }
            }
        }
    }

    /**
     * Parses server SETTINGS payload to extract initial window size and max frame size.
     */
    private fun parseH2Settings(payload: ByteArray) {
        // Each setting is 6 bytes: 2-byte ID + 4-byte value
        var offset = 0
        while (offset + 6 <= payload.size) {
            val id = ((payload[offset].toInt() and 0xFF) shl 8) or
                    (payload[offset + 1].toInt() and 0xFF)
            val value = ((payload[offset + 2].toInt() and 0xFF) shl 24) or
                    ((payload[offset + 3].toInt() and 0xFF) shl 16) or
                    ((payload[offset + 4].toInt() and 0xFF) shl 8) or
                    (payload[offset + 5].toInt() and 0xFF)
            offset += 6

            when (id) {
                0x04 -> { // INITIAL_WINDOW_SIZE
                    lock.withLock { h2PeerWindowSize = value }
                }
                0x05 -> { // MAX_FRAME_SIZE
                    lock.withLock { h2MaxFrameSize = value }
                }
            }
        }
    }

    // MARK: HTTP/2 Send

    /**
     * Sends data as HTTP/2 DATA frame(s) on stream 1.
     */
    private suspend fun sendH2Data(data: ByteArray) {
        val maxSize = lock.withLock { h2MaxFrameSize }

        if (data.size <= maxSize) {
            val frame = buildH2Frame(H2_FRAME_DATA, 0, 1u, data)
            downloadSend(frame)
        } else {
            // Split into multiple DATA frames
            var offset = 0
            while (offset < data.size) {
                val end = minOf(offset + maxSize, data.size)
                val chunk = data.copyOfRange(offset, end)
                val frame = buildH2Frame(H2_FRAME_DATA, 0, 1u, chunk)
                downloadSend(frame)
                offset = end
            }
        }
    }

    // MARK: HTTP/2 Receive

    /**
     * Receives data from HTTP/2 DATA frames on stream 1.
     */
    private suspend fun receiveH2Data(): ByteArray? {
        // Check buffered data first
        lock.withLock {
            if (h2DataBufferLen > 0) {
                val data = h2DataBuffer.copyOfRange(0, h2DataBufferLen)
                h2DataBuffer = ByteArray(0)
                h2DataBufferLen = 0
                return data
            }
            if (h2StreamClosed) {
                return null
            }
        }

        // Read next frame
        while (true) {
            val frame: H2Frame
            try {
                frame = readH2Frame()
            } catch (e: Exception) {
                return null // EOF
            }

            when (frame.type) {
                H2_FRAME_DATA -> {
                    // Send WINDOW_UPDATE to keep flow control open
                    if (frame.payload.isNotEmpty()) {
                        val increment = frame.payload.size
                        val wuPayload = byteArrayOf(
                            ((increment shr 24) and 0xFF).toByte(),
                            ((increment shr 16) and 0xFF).toByte(),
                            ((increment shr 8) and 0xFF).toByte(),
                            (increment and 0xFF).toByte()
                        )
                        // Stream-level + connection-level WINDOW_UPDATE
                        val updates = buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 1u, wuPayload) +
                                buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 0u, wuPayload)
                        try { downloadSend(updates) } catch (_: Exception) {}
                    }

                    if ((frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0) {
                        lock.withLock { h2StreamClosed = true }
                    }

                    if (frame.payload.isEmpty()) {
                        if ((frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0) {
                            return null
                        }
                        continue
                    } else {
                        return frame.payload
                    }
                }
                H2_FRAME_HEADERS -> {
                    // Could be trailing headers (END_STREAM)
                    if ((frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0) {
                        lock.withLock { h2StreamClosed = true }
                        return null
                    } else if (!h2ResponseReceived) {
                        // Late response headers
                        if (checkH2ResponseStatus(frame.payload)) {
                            lock.withLock { h2ResponseReceived = true }
                        }
                        continue
                    } else {
                        continue
                    }
                }
                H2_FRAME_SETTINGS -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) == 0) {
                        parseH2Settings(frame.payload)
                        val ack = buildH2Frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0u, byteArrayOf())
                        try { downloadSend(ack) } catch (_: Exception) {}
                    }
                    continue
                }
                H2_FRAME_WINDOW_UPDATE -> {
                    lock.withLock {
                        if (frame.payload.size >= 4) {
                            val increment = ((frame.payload[0].toInt() and 0xFF) shl 24) or
                                    ((frame.payload[1].toInt() and 0xFF) shl 16) or
                                    ((frame.payload[2].toInt() and 0xFF) shl 8) or
                                    (frame.payload[3].toInt() and 0xFF)
                            h2PeerWindowSize += increment and 0x7FFFFFFF
                        }
                    }
                    continue
                }
                H2_FRAME_PING -> {
                    val pong = buildH2Frame(H2_FRAME_PING, H2_FLAG_ACK, 0u, frame.payload)
                    try { downloadSend(pong) } catch (_: Exception) {}
                    continue
                }
                H2_FRAME_GOAWAY -> {
                    lock.withLock { h2StreamClosed = true }
                    return null
                }
                H2_FRAME_RST_STREAM -> {
                    lock.withLock { h2StreamClosed = true }
                    return null
                }
                else -> {
                    continue
                }
            }
        }
    }

    // =========================================================================
    // Buffer Helpers
    // =========================================================================

    private fun appendToHeaderBuffer(data: ByteArray) {
        if (headerBufferLen + data.size > headerBuffer.size) {
            val newSize = maxOf(headerBuffer.size * 2, headerBufferLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(headerBuffer, 0, newBuf, 0, headerBufferLen)
            headerBuffer = newBuf
        }
        System.arraycopy(data, 0, headerBuffer, headerBufferLen, data.size)
        headerBufferLen += data.size
    }

    private fun appendToH2ReadBuffer(data: ByteArray) {
        if (h2ReadBufferLen + data.size > h2ReadBuffer.size) {
            val newSize = maxOf(h2ReadBuffer.size * 2, h2ReadBufferLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(h2ReadBuffer, 0, newBuf, 0, h2ReadBufferLen)
            h2ReadBuffer = newBuf
        }
        System.arraycopy(data, 0, h2ReadBuffer, h2ReadBufferLen, data.size)
        h2ReadBufferLen += data.size
    }

    private fun appendToH2DataBuffer(data: ByteArray) {
        if (h2DataBufferLen + data.size > h2DataBuffer.size) {
            val newSize = maxOf(h2DataBuffer.size * 2, h2DataBufferLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(h2DataBuffer, 0, newBuf, 0, h2DataBufferLen)
            h2DataBuffer = newBuf
        }
        System.arraycopy(data, 0, h2DataBuffer, h2DataBufferLen, data.size)
        h2DataBufferLen += data.size
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
}

// =============================================================================
// ChunkedTransferDecoder
// =============================================================================

/**
 * Stateful chunked transfer encoding decoder (HTTP/1.1 RFC 7230 S4.1).
 *
 * Handles partial reads: data can be fed incrementally and chunks extracted
 * as they become complete.
 *
 * Port of iOS ChunkedTransferDecoder struct.
 */
class ChunkedTransferDecoder {
    private var buffer = ByteArray(0)
    private var bufferLen = 0
    private var _isFinished = false

    val isFinished: Boolean get() = _isFinished

    /**
     * Feed raw data from the transport into the decoder.
     */
    fun feed(data: ByteArray) {
        if (bufferLen + data.size > buffer.size) {
            val newSize = maxOf(buffer.size * 2, bufferLen + data.size)
            val newBuf = ByteArray(newSize)
            System.arraycopy(buffer, 0, newBuf, 0, bufferLen)
            buffer = newBuf
        }
        System.arraycopy(data, 0, buffer, bufferLen, data.size)
        bufferLen += data.size
    }

    /**
     * Try to extract the next complete chunk from the buffer.
     *
     * Returns the chunk payload (without framing), or null if not enough data is available yet.
     * Returns null when a zero-length terminator chunk is found (EOF).
     */
    fun nextChunk(): ByteArray? {
        if (_isFinished) return null

        // Look for the chunk-size line ending with \r\n
        val crlfIdx = findCRLF(buffer, bufferLen, 0)
        if (crlfIdx < 0) return null

        val sizeLineData = buffer.copyOfRange(0, crlfIdx)
        val sizeLine = String(sizeLineData, Charsets.US_ASCII)

        // Parse hex chunk size (ignoring chunk extensions after ";")
        val sizeStr = sizeLine.split(";", limit = 2).first().trim()
        val chunkSize: Long
        try {
            chunkSize = sizeStr.toLong(16)
        } catch (e: NumberFormatException) {
            return null
        }

        if (chunkSize == 0L) {
            // Terminal chunk
            _isFinished = true
            // Consume "0\r\n\r\n" (the trailing CRLF after the zero chunk)
            val termEnd = crlfIdx + 2
            if (bufferLen >= termEnd + 2) {
                val remaining = bufferLen - (termEnd + 2)
                if (remaining > 0) {
                    System.arraycopy(buffer, termEnd + 2, buffer, 0, remaining)
                }
                bufferLen = remaining
            } else {
                bufferLen = 0
            }
            return null
        }

        // Check if we have the full chunk data + trailing \r\n
        val dataStart = crlfIdx + 2
        val needed = dataStart + chunkSize.toInt() + 2 // chunk data + \r\n
        if (bufferLen < needed) {
            return null // Need more data
        }

        val chunkData = buffer.copyOfRange(dataStart, dataStart + chunkSize.toInt())

        // Consume the chunk from the buffer (size line + \r\n + data + \r\n)
        val remaining = bufferLen - needed
        if (remaining > 0) {
            System.arraycopy(buffer, needed, buffer, 0, remaining)
        }
        bufferLen = remaining

        return chunkData
    }

    /**
     * Finds the position of \r\n starting from the given offset, or returns -1.
     */
    private fun findCRLF(buf: ByteArray, len: Int, startFrom: Int): Int {
        for (i in startFrom until len - 1) {
            if (buf[i] == 0x0D.toByte() && buf[i + 1] == 0x0A.toByte()) {
                return i
            }
        }
        return -1
    }
}

// =============================================================================
// ChunkedTransferEncoder
// =============================================================================

/**
 * Chunked transfer encoding encoder (HTTP/1.1 RFC 7230 S4.1).
 *
 * Port of iOS ChunkedTransferEncoder enum.
 */
object ChunkedTransferEncoder {

    /**
     * Encodes data as a single chunked-encoded chunk: `{hex-size}\r\n{data}\r\n`.
     */
    fun encode(data: ByteArray): ByteArray {
        val sizeStr = data.size.toString(16)
        val sizeBytes = sizeStr.toByteArray(Charsets.UTF_8)
        val result = ByteArray(sizeBytes.size + 2 + data.size + 2)
        var offset = 0
        System.arraycopy(sizeBytes, 0, result, offset, sizeBytes.size)
        offset += sizeBytes.size
        result[offset++] = 0x0D // \r
        result[offset++] = 0x0A // \n
        System.arraycopy(data, 0, result, offset, data.size)
        offset += data.size
        result[offset++] = 0x0D // \r
        result[offset] = 0x0A   // \n
        return result
    }

    /**
     * Encodes the terminal zero-length chunk: `0\r\n\r\n`.
     */
    fun encodeTerminator(): ByteArray {
        return byteArrayOf(0x30, 0x0D, 0x0A, 0x0D, 0x0A) // "0\r\n\r\n"
    }
}

// =============================================================================
// XHTTP Errors
// =============================================================================

/**
 * XHTTP transport errors.
 * Port of iOS XHTTPError enum.
 */
sealed class XHttpError(message: String) : Exception(message) {
    class SetupFailed(reason: String) : XHttpError("XHTTP setup failed: $reason")
    class HttpError(reason: String) : XHttpError("XHTTP HTTP error: $reason")
    object ConnectionClosed : XHttpError("XHTTP connection closed")
}
