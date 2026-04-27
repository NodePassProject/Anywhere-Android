package com.argsment.anywhere.vpn.protocol.xhttp

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.XHttpConfiguration
import com.argsment.anywhere.data.model.XHttpMode
import com.argsment.anywhere.data.model.XHttpPlacement
import com.argsment.anywhere.vpn.protocol.ProxyUserAgent
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.util.NioSocket
import android.util.Base64
import java.io.IOException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine

private val logger = AnywhereLogger("XHTTP")

private val DEFAULT_USER_AGENT: String
    get() = ProxyUserAgent.chrome

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

/** XHTTP connection implementing packet-up, stream-up, and stream-one modes. */
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

    private var nextSeq: Long = 0
    private var chunkedDecoder = ChunkedTransferDecoder()
    private var downloadHeadersParsed = false
    private var _isConnected = true
    private val lock = ReentrantLock()

    // Packet-up batching: each `send()` in packet-up mode appends to the queue and
    // suspends until the batched POST has been written; a single in-flight flush drains
    // the queue into one POST per `scMinPostsIntervalMs`. Essential for UDP, where each
    // datagram would otherwise become its own HTTP POST request.
    private val packetUpQueue: ArrayDeque<Pair<ByteArray, CompletableDeferred<Unit>>> = ArrayDeque()
    private var packetUpFlushPending = false
    private var packetUpLastFlushTime: Long = 0
    private val packetUpScope: CoroutineScope by lazy {
        CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    private var uploadDrainJob: Job? = null

    /** Leftover data after HTTP response headers. */
    private var headerBuffer = ByteArray(0)
    private var headerBufferLen = 0

    private var h2ReadBuffer = ByteArray(0)
    private var h2ReadBufferLen = 0
    private var h2DataBuffer = ByteArray(0)
    private var h2DataBufferLen = 0

    // HTTP/2 Flow Control (RFC 7540 §6.9)
    /** Connection-level send window (stream 0). Updated by WINDOW_UPDATE on stream 0 only. */
    private var h2PeerConnectionWindow: Int = 65535
    /** Stream-level send window for the active upload/stream-one stream.
     *  Updated by SETTINGS INITIAL_WINDOW_SIZE and stream-level WINDOW_UPDATE. */
    private var h2PeerStreamSendWindow: Int = 65535
    /** Per-stream send windows for packet-up streams that are blocked on flow control.
     *  Keyed by stream ID; entries are created when a packet-up send blocks, updated
     *  by stream-level WINDOW_UPDATE, and removed when the send resumes. */
    private val h2PacketStreamWindows: HashMap<UInt, Int> = HashMap()
    /** Continuations stored when sends are blocked by flow control (window == 0).
     *  All are resumed by the WINDOW_UPDATE handler; each re-checks its own window. */
    private val h2FlowResumptions: MutableList<CancellableContinuation<Unit>> = mutableListOf()

    private var h2PeerInitialWindowSize: Int = 65535
    private var h2LocalWindowSize: Int = 4_194_304    // 4MB
    private var h2MaxFrameSize: Int = 16384
    private var h2MaxReadBufferSize: Int = 2_097_152  // 2MB
    private var h2ResponseReceived = false
    private var h2StreamClosed = false

    /** Bytes received but not yet acknowledged via WINDOW_UPDATE (connection level). */
    private var h2ConnectionReceiveConsumed: Int = 0
    /** Bytes received but not yet acknowledged via WINDOW_UPDATE (stream level, download stream). */
    private var h2StreamReceiveConsumed: Int = 0

    private var h2UploadStreamId: UInt = 3u      // Fixed upload stream for stream-up
    private var h2NextPacketStreamId: UInt = 3u  // Next stream ID for packet-up uploads

    val isConnected: Boolean
        get() = lock.withLock { _isConnected }

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

    constructor(
        transport: Transport,
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
        downloadSend = { data -> transport.send(data) },
        downloadSendAsync = { data -> transport.sendAsync(data) },
        downloadReceive = { transport.receive() },
        downloadCancel = { transport.forceCancel() },
        uploadConnectionFactory = uploadConnectionFactory
    )

    /**
     * Non-obfs mode (default): `Referer: https://{host}{path}?x_padding=XXX...`.
     * Obfs mode: places padding in header, cookie, query, or queryInHeader based on config.
     */
    private fun applyPadding(sb: StringBuilder, forPath: String) {
        val padding = configuration.generatePadding()

        if (!configuration.xPaddingObfsMode) {
            sb.append("Referer: https://${configuration.host}${forPath}?${configuration.xPaddingKey}=$padding\r\n")
            return
        }

        when (configuration.xPaddingPlacement) {
            XHttpPlacement.HEADER ->
                sb.append("${configuration.xPaddingHeader}: $padding\r\n")
            XHttpPlacement.QUERY_IN_HEADER ->
                sb.append("${configuration.xPaddingHeader}: https://${configuration.host}${forPath}?${configuration.xPaddingKey}=$padding\r\n")
            XHttpPlacement.COOKIE ->
                sb.append("Cookie: ${configuration.xPaddingKey}=$padding\r\n")
            XHttpPlacement.QUERY -> {
                // Query padding is appended to the URL path in buildRequestLine
            }
            else -> {}
        }
    }

    private class MutablePath(var value: String)

    private fun applySessionId(sb: StringBuilder, path: MutablePath) {
        if (sessionId.isEmpty()) return
        val key = configuration.normalizedSessionKey
        when (configuration.sessionPlacement) {
            XHttpPlacement.PATH -> path.value = appendToPath(path.value, sessionId)
            XHttpPlacement.HEADER -> sb.append("$key: $sessionId\r\n")
            XHttpPlacement.COOKIE -> sb.append("Cookie: $key=$sessionId\r\n")
            XHttpPlacement.QUERY -> { /* handled in queryParamsForMeta */ }
            else -> {}
        }
    }

    private fun applySeq(sb: StringBuilder, path: MutablePath, seq: Long) {
        val key = configuration.normalizedSeqKey
        when (configuration.seqPlacement) {
            XHttpPlacement.PATH -> path.value = appendToPath(path.value, "$seq")
            XHttpPlacement.HEADER -> sb.append("$key: $seq\r\n")
            XHttpPlacement.COOKIE -> sb.append("Cookie: $key=$seq\r\n")
            XHttpPlacement.QUERY -> { /* handled in queryParamsForMeta */ }
            else -> {}
        }
    }

    /** Returns query string components for session/seq placed in query params. */
    private fun queryParamsForMeta(seq: Long? = null): String {
        val parts = mutableListOf<String>()
        if (sessionId.isNotEmpty() && configuration.sessionPlacement == XHttpPlacement.QUERY) {
            val key = configuration.normalizedSessionKey
            parts.add("$key=$sessionId")
        }
        if (seq != null && configuration.seqPlacement == XHttpPlacement.QUERY) {
            val key = configuration.normalizedSeqKey
            parts.add("$key=$seq")
        }
        return parts.joinToString("&")
    }

    private fun appendToPath(path: String, segment: String): String {
        return if (path.endsWith("/")) "$path$segment" else "$path/$segment"
    }

    private fun buildRequestLine(method: String, path: String, queryParts: List<String>): String {
        var url = path
        val allQuery = queryParts.filter { it.isNotEmpty() }.toMutableList()
        val configQuery = configuration.normalizedQuery
        if (configQuery.isNotEmpty()) {
            allQuery.add(0, configQuery)
        }
        if (configuration.xPaddingObfsMode && configuration.xPaddingPlacement == XHttpPlacement.QUERY) {
            val padding = configuration.generatePadding()
            allQuery.add("${configuration.xPaddingKey}=$padding")
        }
        if (allQuery.isNotEmpty()) {
            url += "?" + allQuery.joinToString("&")
        }
        return "$method $url HTTP/1.1\r\n"
    }

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
        } else if (mode == XHttpMode.STREAM_UP) {
            performStreamUpSetup()
        } else {
            performPacketUpSetup()
        }
    }

    private suspend fun performStreamOneSetup() {
        val method = configuration.uplinkHTTPMethod
        val path = configuration.normalizedPath
        val metaQuery = queryParamsForMeta()
        val sb = StringBuilder()
        // stream-one: no session ID in path
        sb.append(buildRequestLine(method, path, listOf(metaQuery)))
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        applyPadding(sb, path)
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

    /**
     * Sets up stream-up mode:
     * 1. Sends a GET request on the download connection and reads response headers.
     * 2. Establishes the upload connection and sends a streaming POST with chunked encoding.
     */
    private suspend fun performStreamUpSetup() {
        val getRequest = buildDownloadGETRequest()
        downloadSend(getRequest)

        receiveResponseHeaders()

        val factory = uploadConnectionFactory
            ?: throw XHttpError.SetupFailed("No upload connection factory for stream-up")

        val closures = factory()
        lock.withLock {
            uploadSend = closures.send
            uploadSendAsync = closures.sendAsync
            uploadReceive = closures.receive
            uploadCancel = closures.cancel
        }

        val postRequest = buildStreamUpPOSTRequest()
        val upSend = lock.withLock { uploadSend }
            ?: throw XHttpError.SetupFailed("Upload connection not established")
        upSend(postRequest)
    }

    /** Used by packet-up and stream-up. Session ID is placed according to sessionPlacement config. */
    private fun buildDownloadGETRequest(): ByteArray {
        val path = MutablePath(configuration.normalizedPath)
        val headerBlock = StringBuilder()
        applySessionId(headerBlock, path)
        if (!path.value.endsWith("/")) path.value += "/"
        val metaQuery = queryParamsForMeta()
        val sb = StringBuilder()
        sb.append(buildRequestLine("GET", path.value, listOf(metaQuery)))
        sb.append(headerBlock)
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        applyPadding(sb, path.value)
        for ((key, value) in configuration.headers) {
            if (key != "User-Agent") {
                sb.append("$key: $value\r\n")
            }
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Builds the HTTP/1.1 POST request headers for stream-up mode.
     * Session ID placed according to config, no sequence number, chunked transfer.
     */
    private fun buildStreamUpPOSTRequest(): ByteArray {
        val method = configuration.uplinkHTTPMethod
        val path = MutablePath(configuration.normalizedPath)
        val headerBlock = StringBuilder()
        applySessionId(headerBlock, path)
        if (!path.value.endsWith("/")) path.value += "/"
        val metaQuery = queryParamsForMeta()
        val sb = StringBuilder()
        sb.append(buildRequestLine(method, path.value, listOf(metaQuery)))
        sb.append(headerBlock)
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        applyPadding(sb, path.value)
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
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    private suspend fun performPacketUpSetup() {
        val requestData = buildDownloadGETRequest()
        downloadSend(requestData)

        receiveResponseHeaders()

        val factory = uploadConnectionFactory
            ?: throw XHttpError.SetupFailed("No upload connection factory")

        val closures = factory()
        lock.withLock {
            uploadSend = closures.send
            uploadSendAsync = closures.sendAsync
            uploadReceive = closures.receive
            uploadCancel = closures.cancel
        }

        // Continuously drain upload-POST responses to prevent TCP receive buffer
        // saturation and the resulting backpressure on the upload stream.
        startUploadResponseDrain()
    }

    private fun startUploadResponseDrain() {
        uploadDrainJob = CoroutineScope(Dispatchers.IO).launch {
            drainNextUploadResponse()
        }
    }

    private suspend fun drainNextUploadResponse() {
        while (true) {
            val upReceive = lock.withLock {
                if (!_isConnected) return
                uploadReceive ?: return
            }
            try {
                val data = upReceive()
                if (data == null || data.isEmpty()) return
            } catch (_: Exception) {
                return
            }
        }
    }

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
                    return@withLock null
                }

                val headerData = headerBuffer.copyOfRange(0, headerEndIdx)
                val bodyStart = headerEndIdx + 4 // skip \r\n\r\n
                val leftoverLen = headerBufferLen - bodyStart
                downloadHeadersParsed = true

                if (leftoverLen > 0) {
                    val leftover = headerBuffer.copyOfRange(bodyStart, headerBufferLen)
                    chunkedDecoder.feed(leftover)
                }
                headerBuffer = ByteArray(0)
                headerBufferLen = 0

                val headerString = String(headerData, Charsets.UTF_8)
                val firstLine = headerString.split("\r\n", limit = 2).firstOrNull() ?: ""
                if (!firstLine.contains("200")) {
                    throw XHttpError.HttpError("Expected HTTP 200, got: $firstLine")
                }

                return@withLock Unit
            } ?: continue

            return
        }
    }

    suspend fun send(data: ByteArray) {
        if (mode == XHttpMode.PACKET_UP) {
            // Packet-up batches writes through an internal queue (see
            // [enqueuePacketUpSend]). All other modes go directly to the wire.
            enqueuePacketUpSend(data)
            return
        }
        if (useHTTP2) {
            if (mode == XHttpMode.STREAM_UP) {
                sendH2Data(data, h2UploadStreamId)
            } else {
                // stream-one: upload and download share stream 1
                sendH2Data(data, 1u)
            }
        } else if (mode == XHttpMode.STREAM_ONE) {
            sendStreamOne(data)
        } else if (mode == XHttpMode.STREAM_UP) {
            sendStreamUp(data)
        }
    }

    /**
     * Sends data without awaiting completion. Routed through the suspending [send]
     * via [packetUpScope] so that flow control, packet-up batching, and chunked
     * encoding all behave the same as [send].
     */
    fun sendAsync(data: ByteArray) {
        packetUpScope.launch {
            try {
                send(data)
            } catch (_: Throwable) {
                // Best-effort: swallow errors so that fire-and-forget callers
                // don't see exceptions on a closed connection.
            }
        }
    }

    private suspend fun sendStreamOne(data: ByteArray) {
        val chunk = ChunkedTransferEncoder.encode(data)
        downloadSend(chunk)
    }

    private suspend fun sendStreamUp(data: ByteArray) {
        val upSend = lock.withLock {
            uploadSend ?: throw XHttpError.SetupFailed("Upload connection not established")
        }
        val chunk = ChunkedTransferEncoder.encode(data)
        upSend(chunk)
    }

    /**
     * Queues a write for the next batched POST in packet-up mode.
     *
     * Writes append to an in-memory queue and a single in-flight flush coalesces
     * them into one POST per `scMinPostsIntervalMs`. Without this, every individual
     * `send()` (in particular every UDP datagram delivered via UDP relays) would
     * become its own HTTP POST request, causing huge per-packet overhead and, on
     * HTTP/2, rapid stream-ID exhaustion.
     */
    private suspend fun enqueuePacketUpSend(data: ByteArray) {
        val deferred = CompletableDeferred<Unit>()
        val shouldSchedule: Boolean
        lock.withLock {
            if (!_isConnected || (useHTTP2 && h2StreamClosed)) {
                throw XHttpError.ConnectionClosed
            }
            packetUpQueue.addLast(Pair(data, deferred))
            shouldSchedule = !packetUpFlushPending
            if (shouldSchedule) {
                packetUpFlushPending = true
            }
        }
        if (shouldSchedule) {
            schedulePacketUpFlush()
        }
        deferred.await()
    }

    /**
     * Schedules a packet-up flush, respecting the `scMinPostsIntervalMs` interval since
     * the last flush start.
     */
    private fun schedulePacketUpFlush() {
        val delayMs = configuration.scMinPostsIntervalMs
        val elapsedMs: Long = lock.withLock {
            if (packetUpLastFlushTime == 0L) Long.MAX_VALUE
            else (System.nanoTime() - packetUpLastFlushTime) / 1_000_000L
        }
        packetUpScope.launch {
            if (delayMs > 0 && elapsedMs < delayMs) {
                delay(delayMs - elapsedMs)
            }
            flushPacketUpBatch()
        }
    }

    /**
     * Drains the packet-up queue (up to `scMaxEachPostBytes`) into a single batched
     * POST. On completion, completes every queued deferred and chains into the next
     * flush if more data has been enqueued in the meantime.
     */
    private suspend fun flushPacketUpBatch() {
        val batchedData: ByteArray
        val batchedCompletions: List<CompletableDeferred<Unit>>
        val seq: Long
        val isH2: Boolean

        lock.withLock {
            if (!_isConnected || (useHTTP2 && h2StreamClosed)) {
                val pending = packetUpQueue.toList()
                packetUpQueue.clear()
                packetUpFlushPending = false
                for ((_, deferred) in pending) {
                    deferred.completeExceptionally(XHttpError.ConnectionClosed)
                }
                return
            }

            if (packetUpQueue.isEmpty()) {
                packetUpFlushPending = false
                return
            }

            val maxSize = maxOf(1, configuration.scMaxEachPostBytes)
            var size = 0
            val collected = mutableListOf<Pair<ByteArray, CompletableDeferred<Unit>>>()
            // Allow the first chunk to exceed maxSize on its own (sendPacketUp will
            // re-split it); otherwise stop before the limit so the next flush picks
            // up where this one left off.
            while (packetUpQueue.isNotEmpty()) {
                val head = packetUpQueue.first()
                if (collected.isNotEmpty() && size + head.first.size > maxSize) break
                collected.add(packetUpQueue.removeFirst())
                size += head.first.size
            }
            val merged = ByteArray(size)
            var off = 0
            for ((chunk, _) in collected) {
                System.arraycopy(chunk, 0, merged, off, chunk.size)
                off += chunk.size
            }
            batchedData = merged
            batchedCompletions = collected.map { it.second }

            seq = nextSeq
            nextSeq++
            isH2 = useHTTP2
            packetUpLastFlushTime = System.nanoTime()
        }

        val error: Throwable? = try {
            if (isH2) {
                sendH2PacketUp(batchedData, seq)
            } else {
                sendPacketUpHTTP11(batchedData, seq)
            }
            null
        } catch (e: Throwable) {
            e
        }

        for (deferred in batchedCompletions) {
            if (error != null) deferred.completeExceptionally(error)
            else deferred.complete(Unit)
        }

        val shouldChain: Boolean = lock.withLock {
            if (error != null || packetUpQueue.isEmpty()) {
                packetUpFlushPending = false
                false
            } else {
                // packetUpFlushPending stays true; chain into the next flush.
                true
            }
        }
        if (shouldChain) {
            schedulePacketUpFlush()
        }
    }

    /**
     * HTTP/1.1 packet-up POST sender. Splits oversized data into multiple POSTs of
     * at most [XHttpConfiguration.scMaxEachPostBytes] bytes, each with its own
     * sequence number. Responses are drained asynchronously by [drainNextUploadResponse].
     *
     * Supports uplink data placement in body (default), headers, or cookies via
     * [XHttpConfiguration.uplinkDataPlacement].
     */
    private suspend fun sendPacketUpHTTP11(data: ByteArray, firstSeq: Long) {
        val upSend: suspend (ByteArray) -> Unit = lock.withLock {
            uploadSend ?: throw XHttpError.SetupFailed("Upload connection not established")
        }

        val maxSize = maxOf(1, configuration.scMaxEachPostBytes)
        var offset = 0
        var seq = firstSeq
        while (offset < data.size) {
            val end = minOf(offset + maxSize, data.size)
            val chunk = if (offset == 0 && end == data.size) data else data.copyOfRange(offset, end)
            sendSinglePost(chunk, seq, upSend)
            offset = end
            if (offset < data.size) {
                seq = lock.withLock { val s = nextSeq; nextSeq++; s }
            }
        }
    }

    /**
     * Sends a single HTTP/1.1 POST request with the given sequence number.
     * Supports uplink data placement in body (default), headers, or cookies.
     */
    private suspend fun sendSinglePost(
        data: ByteArray,
        seq: Long,
        upSend: suspend (ByteArray) -> Unit
    ) {
        val method = configuration.uplinkHTTPMethod
        val path = MutablePath(configuration.normalizedPath)
        val headerBlock = StringBuilder()

        applySessionId(headerBlock, path)
        applySeq(headerBlock, path, seq)

        val bodyData: ByteArray
        if (configuration.uplinkDataPlacement != XHttpPlacement.BODY) {
            // Encode data as base64url and place in headers or cookies
            val encoded = Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val chunkSize = if (configuration.uplinkChunkSize > 0)
                configuration.uplinkChunkSize else encoded.length
            val key = configuration.uplinkDataKey

            when (configuration.uplinkDataPlacement) {
                XHttpPlacement.HEADER -> {
                    var i = 0
                    var chunkIndex = 0
                    while (i < encoded.length) {
                        val end = minOf(i + chunkSize, encoded.length)
                        val chunk = encoded.substring(i, end)
                        headerBlock.append("$key-$chunkIndex: $chunk\r\n")
                        i = end
                        chunkIndex++
                    }
                    headerBlock.append("$key-Length: ${encoded.length}\r\n")
                    headerBlock.append("$key-Upstream: 1\r\n")
                }
                XHttpPlacement.COOKIE -> {
                    headerBlock.append("Cookie: $key=$encoded\r\n")
                }
                else -> {}
            }
            bodyData = ByteArray(0)
        } else {
            bodyData = data
        }

        val metaQuery = queryParamsForMeta(seq)
        val sb = StringBuilder()
        sb.append(buildRequestLine(method, path.value, listOf(metaQuery)))
        sb.append(headerBlock)
        sb.append("Host: ${configuration.host}\r\n")
        sb.append("User-Agent: ${configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT}\r\n")
        applyPadding(sb, path.value)
        sb.append("Content-Length: ${bodyData.size}\r\n")
        sb.append("Connection: keep-alive\r\n")
        for ((key, value) in configuration.headers) {
            if (key != "User-Agent") {
                sb.append("$key: $value\r\n")
            }
        }
        sb.append("\r\n")

        val requestData = sb.toString().toByteArray(Charsets.UTF_8) + bodyData
        upSend(requestData)
    }

    suspend fun receive(): ByteArray? {
        if (useHTTP2) {
            return receiveH2Data()
        }

        lock.withLock {
            val decoded = chunkedDecoder.nextChunk()
            if (decoded != null) {
                return decoded
            }

            if (chunkedDecoder.isFinished) {
                return null
            }
        }

        while (true) {
            val data = downloadReceive()

            if (data == null || data.isEmpty()) {
                return null
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
        }
    }

    fun cancel() {
        val uploadCancelFn: (() -> Unit)?
        val pendingPackets: List<Pair<ByteArray, CompletableDeferred<Unit>>>
        val pendingResumptions: List<CancellableContinuation<Unit>>
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
            pendingPackets = packetUpQueue.toList()
            packetUpQueue.clear()
            packetUpFlushPending = false
            pendingResumptions = h2FlowResumptions.toList()
            h2FlowResumptions.clear()
            h2PacketStreamWindows.clear()
        }

        for ((_, deferred) in pendingPackets) {
            deferred.completeExceptionally(XHttpError.ConnectionClosed)
        }
        for (cont in pendingResumptions) {
            if (cont.isActive) cont.resumeWithException(XHttpError.ConnectionClosed)
        }

        uploadDrainJob?.cancel()
        uploadDrainJob = null
        packetUpScope.coroutineContext[Job]?.cancelChildren()
        downloadCancel()
        uploadCancelFn?.invoke()
    }

    companion object {
        /** HTTP/2 connection preface (RFC 7540 S3.5). */
        private val H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.UTF_8)

        private const val H2_FRAME_HEADER_SIZE = 9

        private const val H2_FRAME_DATA: Byte = 0x00
        private const val H2_FRAME_HEADERS: Byte = 0x01
        private const val H2_FRAME_SETTINGS: Byte = 0x04
        private const val H2_FRAME_PING: Byte = 0x06
        private const val H2_FRAME_GOAWAY: Byte = 0x07
        private const val H2_FRAME_WINDOW_UPDATE: Byte = 0x08
        private const val H2_FRAME_RST_STREAM: Byte = 0x03

        private const val H2_FLAG_END_STREAM: Byte = 0x01
        private const val H2_FLAG_END_HEADERS: Byte = 0x04
        private const val H2_FLAG_ACK: Byte = 0x01

        private const val H2_STREAM_WINDOW_SIZE: Int = 4_194_304  // 4MB
        private const val H2_CONN_WINDOW_SIZE: Int = 1_073_741_824  // 1GB
    }

    private fun buildH2Frame(type: Byte, flags: Byte, streamId: UInt, payload: ByteArray): ByteArray {
        val frame = ByteArray(H2_FRAME_HEADER_SIZE + payload.size)
        val len = payload.size
        frame[0] = ((len shr 16) and 0xFF).toByte()
        frame[1] = ((len shr 8) and 0xFF).toByte()
        frame[2] = (len and 0xFF).toByte()
        frame[3] = type
        frame[4] = flags
        // Stream ID (31-bit, R=0)
        val sid = streamId.toInt() and 0x7FFFFFFF
        frame[5] = ((sid shr 24) and 0xFF).toByte()
        frame[6] = ((sid shr 16) and 0xFF).toByte()
        frame[7] = ((sid shr 8) and 0xFF).toByte()
        frame[8] = (sid and 0xFF).toByte()
        System.arraycopy(payload, 0, frame, H2_FRAME_HEADER_SIZE, payload.size)
        return frame
    }

    private data class H2Frame(val type: Byte, val flags: Byte, val streamId: UInt, val payload: ByteArray)

    /** Must be called with lock held. Returns null if not enough data. */
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

        val remaining = h2ReadBufferLen - totalSize
        if (remaining > 0) {
            System.arraycopy(h2ReadBuffer, totalSize, h2ReadBuffer, 0, remaining)
        }
        h2ReadBufferLen = remaining

        return H2Frame(type, flags, streamId, payload)
    }

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

    /** Encodes an integer with the given prefix bit width (RFC 7541 S5.1). */
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

    /** Encodes a plain (non-Huffman) string (RFC 7541 S5.2). */
    private fun hpackEncodeString(string: String): ByteArray {
        val bytes = string.toByteArray(Charsets.UTF_8)
        val lenBytes = hpackEncodeInteger(bytes.size, 7)
        lenBytes[0] = (lenBytes[0].toInt() and 0x7F).toByte() // Clear H bit
        return lenBytes + bytes
    }

    /** Encodes a request header block for stream-one POST or stream-up/packet-up download GET. */
    private fun encodeH2RequestHeaders(method: String = "POST", includeMeta: Boolean = false): ByteArray {
        val block = mutableListOf<Byte>()

        // Pseudo-header order: :authority, :method, :path, :scheme

        val authBytes = hpackEncodeInteger(1, 6)
        authBytes[0] = (authBytes[0].toInt() or 0x40).toByte()
        block.addAll(authBytes.toList())
        block.addAll(hpackEncodeString(configuration.host).toList())

        if (method == "GET") {
            block.add(0x82.toByte()) // GET = index 2
        } else {
            block.add(0x83.toByte()) // POST = index 3
        }

        var path = configuration.normalizedPath
        if (includeMeta && sessionId.isNotEmpty() && configuration.sessionPlacement == XHttpPlacement.PATH) {
            path = appendToPath(path, sessionId)
        }
        val queryParts = mutableListOf<String>()
        val configQuery = configuration.normalizedQuery
        if (configQuery.isNotEmpty()) {
            queryParts.add(configQuery)
        }
        if (includeMeta && sessionId.isNotEmpty() && configuration.sessionPlacement == XHttpPlacement.QUERY) {
            queryParts.add("${configuration.normalizedSessionKey}=$sessionId")
        }
        if (queryParts.isNotEmpty()) {
            path += "?" + queryParts.joinToString("&")
        }

        if (path == "/") {
            block.add(0x84.toByte()) // Indexed: :path / (index 4)
        } else {
            val pathBytes = hpackEncodeInteger(4, 6)
            pathBytes[0] = (pathBytes[0].toInt() or 0x40).toByte()
            block.addAll(pathBytes.toList())
            block.addAll(hpackEncodeString(path).toList())
        }

        // :scheme https — static table index 7
        block.add(0x87.toByte())

        if (method != "GET" && !configuration.noGrpcHeader) {
            val ctBytes = hpackEncodeInteger(31, 6)
            ctBytes[0] = (ctBytes[0].toInt() or 0x40).toByte()
            block.addAll(ctBytes.toList())
            block.addAll(hpackEncodeString("application/grpc").toList())
        }

        if (includeMeta && sessionId.isNotEmpty()) {
            when (configuration.sessionPlacement) {
                XHttpPlacement.HEADER -> {
                    block.add(0x40)
                    block.addAll(hpackEncodeString(configuration.normalizedSessionKey.lowercase()).toList())
                    block.addAll(hpackEncodeString(sessionId).toList())
                }
                XHttpPlacement.COOKIE -> {
                    val cookieBytes = hpackEncodeInteger(32, 6)
                    cookieBytes[0] = (cookieBytes[0].toInt() or 0x40).toByte()
                    block.addAll(cookieBytes.toList())
                    block.addAll(hpackEncodeString("${configuration.normalizedSessionKey}=$sessionId").toList())
                }
                else -> {} // path and query handled above
            }
        }

        appendH2CommonHeaders(block, path)

        return block.toByteArray()
    }

    /**
     * Encodes HEADERS for an upload POST stream (stream-up or packet-up).
     *
     * @param seq Sequence number for packet-up (null for stream-up).
     * @param contentLength Content length for packet-up POST (null for stream-up).
     */
    private fun encodeH2UploadHeaders(seq: Long?, contentLength: Int? = null): ByteArray {
        val block = mutableListOf<Byte>()

        val authBytes = hpackEncodeInteger(1, 6)
        authBytes[0] = (authBytes[0].toInt() or 0x40).toByte()
        block.addAll(authBytes.toList())
        block.addAll(hpackEncodeString(configuration.host).toList())

        val method = configuration.uplinkHTTPMethod
        when (method) {
            "POST" -> block.add(0x83.toByte())
            "GET" -> block.add(0x82.toByte())
            else -> {
                val methodBytes = hpackEncodeInteger(2, 6)
                methodBytes[0] = (methodBytes[0].toInt() or 0x40).toByte()
                block.addAll(methodBytes.toList())
                block.addAll(hpackEncodeString(method).toList())
            }
        }

        var path = configuration.normalizedPath
        if (sessionId.isNotEmpty() && configuration.sessionPlacement == XHttpPlacement.PATH) {
            path = appendToPath(path, sessionId)
        }
        if (seq != null && configuration.seqPlacement == XHttpPlacement.PATH) {
            path = appendToPath(path, "$seq")
        }
        val queryParts = mutableListOf<String>()
        val configQuery = configuration.normalizedQuery
        if (configQuery.isNotEmpty()) {
            queryParts.add(configQuery)
        }
        if (sessionId.isNotEmpty() && configuration.sessionPlacement == XHttpPlacement.QUERY) {
            queryParts.add("${configuration.normalizedSessionKey}=$sessionId")
        }
        if (seq != null && configuration.seqPlacement == XHttpPlacement.QUERY) {
            queryParts.add("${configuration.normalizedSeqKey}=$seq")
        }
        if (queryParts.isNotEmpty()) {
            path += "?" + queryParts.joinToString("&")
        }

        val pathBytes = hpackEncodeInteger(4, 6)
        pathBytes[0] = (pathBytes[0].toInt() or 0x40).toByte()
        block.addAll(pathBytes.toList())
        block.addAll(hpackEncodeString(path).toList())

        block.add(0x87.toByte())

        // content-type: only for stream-up (no seq), not packet-up
        if (seq == null && !configuration.noGrpcHeader) {
            val ctBytes = hpackEncodeInteger(31, 6)
            ctBytes[0] = (ctBytes[0].toInt() or 0x40).toByte()
            block.addAll(ctBytes.toList())
            block.addAll(hpackEncodeString("application/grpc").toList())
        }

        if (contentLength != null) {
            val clBytes = hpackEncodeInteger(28, 6)
            clBytes[0] = (clBytes[0].toInt() or 0x40).toByte()
            block.addAll(clBytes.toList())
            block.addAll(hpackEncodeString("$contentLength").toList())
        }

        if (sessionId.isNotEmpty()) {
            when (configuration.sessionPlacement) {
                XHttpPlacement.HEADER -> {
                    block.add(0x40)
                    block.addAll(hpackEncodeString(configuration.normalizedSessionKey.lowercase()).toList())
                    block.addAll(hpackEncodeString(sessionId).toList())
                }
                XHttpPlacement.COOKIE -> {
                    val cookieBytes = hpackEncodeInteger(32, 6)
                    cookieBytes[0] = (cookieBytes[0].toInt() or 0x40).toByte()
                    block.addAll(cookieBytes.toList())
                    block.addAll(hpackEncodeString("${configuration.normalizedSessionKey}=$sessionId").toList())
                }
                else -> {}
            }
        }

        if (seq != null) {
            when (configuration.seqPlacement) {
                XHttpPlacement.HEADER -> {
                    block.add(0x40)
                    block.addAll(hpackEncodeString(configuration.normalizedSeqKey.lowercase()).toList())
                    block.addAll(hpackEncodeString("$seq").toList())
                }
                XHttpPlacement.COOKIE -> {
                    val cookieBytes = hpackEncodeInteger(32, 6)
                    cookieBytes[0] = (cookieBytes[0].toInt() or 0x40).toByte()
                    block.addAll(cookieBytes.toList())
                    block.addAll(hpackEncodeString("${configuration.normalizedSeqKey}=$seq").toList())
                }
                else -> {}
            }
        }

        appendH2CommonHeaders(block, path)

        return block.toByteArray()
    }

    /** Appends common HPACK headers (user-agent, padding, custom headers) to a header block. */
    private fun appendH2CommonHeaders(block: MutableList<Byte>, path: String) {
        val ua = configuration.headers["User-Agent"] ?: DEFAULT_USER_AGENT
        val uaBytes = hpackEncodeInteger(58, 6)
        uaBytes[0] = (uaBytes[0].toInt() or 0x40).toByte()
        block.addAll(uaBytes.toList())
        block.addAll(hpackEncodeString(ua).toList())

        val padding = configuration.generatePadding()
        val paddingPath = configuration.normalizedPath
        if (!configuration.xPaddingObfsMode) {
            val referer = "https://${configuration.host}${paddingPath}?x_padding=$padding"
            val refBytes = hpackEncodeInteger(51, 6)
            refBytes[0] = (refBytes[0].toInt() or 0x40).toByte()
            block.addAll(refBytes.toList())
            block.addAll(hpackEncodeString(referer).toList())
        } else {
            when (configuration.xPaddingPlacement) {
                XHttpPlacement.HEADER -> {
                    block.add(0x40)
                    block.addAll(hpackEncodeString(configuration.xPaddingHeader.lowercase()).toList())
                    block.addAll(hpackEncodeString(padding).toList())
                }
                XHttpPlacement.QUERY_IN_HEADER -> {
                    val headerValue = "https://${configuration.host}${paddingPath}?${configuration.xPaddingKey}=$padding"
                    block.add(0x40)
                    block.addAll(hpackEncodeString(configuration.xPaddingHeader.lowercase()).toList())
                    block.addAll(hpackEncodeString(headerValue).toList())
                }
                XHttpPlacement.COOKIE -> {
                    val cookieBytes = hpackEncodeInteger(32, 6)
                    cookieBytes[0] = (cookieBytes[0].toInt() or 0x40).toByte()
                    block.addAll(cookieBytes.toList())
                    block.addAll(hpackEncodeString("${configuration.xPaddingKey}=$padding").toList())
                }
                else -> {}
            }
        }

        // Filter hop-by-hop headers forbidden in HTTP/2
        val h2ForbiddenHeaders = setOf(
            "host", "connection", "proxy-connection", "transfer-encoding",
            "upgrade", "keep-alive", "content-length", "user-agent"
        )
        for ((key, value) in configuration.headers) {
            val lk = key.lowercase()
            if (h2ForbiddenHeaders.contains(lk)) continue
            block.add(0x40)
            block.addAll(hpackEncodeString(lk).toList())
            block.addAll(hpackEncodeString(value).toList())
        }
    }

    /**
     * Checks if the HEADERS response block starts with :status 200.
     * Handles indexed representation, literal with/without/never indexing,
     * HPACK dynamic table size updates, and Huffman-encoded values.
     */
    private fun checkH2ResponseStatus(headerBlock: ByteArray): Boolean {
        if (headerBlock.isEmpty()) return false

        // Skip HPACK dynamic table size updates (prefix 001xxxxx, RFC 7541 §6.3)
        var offset = 0
        while (offset < headerBlock.size && (headerBlock[offset].toInt() and 0xE0) == 0x20) {
            val initial = headerBlock[offset].toInt() and 0x1F
            offset++
            if (initial == 0x1F) {
                while (offset < headerBlock.size && (headerBlock[offset].toInt() and 0x80) != 0) offset++
                offset++
            }
        }
        if (offset >= headerBlock.size) return false

        val first = headerBlock[offset].toInt() and 0xFF

        // Indexed representation (top bit set):
        // 0x88=200, 0x89=204, 0x8a=206, 0x8b=304, 0x8c=400, 0x8d=404, 0x8e=500
        if (first and 0x80 != 0) {
            return first == 0x88
        }

        // Literal representations with :status name index
        // HPACK static table indices 8-14 all have name ":status" (RFC 7541 Appendix A)
        val nameIndex: Int = when {
            first and 0xF0 == 0x00 -> first and 0x0F   // without indexing (0000 NNNN)
            first and 0xF0 == 0x10 -> first and 0x0F   // never indexed    (0001 NNNN)
            first and 0xC0 == 0x40 -> first and 0x3F   // incremental indexing (01NN NNNN)
            else -> return false
        }

        if (nameIndex !in 8..14 || offset + 1 >= headerBlock.size) return false

        val valueMeta = headerBlock[offset + 1].toInt() and 0xFF
        val isHuffman = (valueMeta and 0x80) != 0
        val valueLen = valueMeta and 0x7F
        if (valueLen <= 0 || offset + 2 + valueLen > headerBlock.size) return false

        val valueStart = offset + 2

        if (!isHuffman) {
            return valueLen == 3 &&
                headerBlock[valueStart].toInt().toChar() == '2' &&
                headerBlock[valueStart + 1].toInt().toChar() == '0' &&
                headerBlock[valueStart + 2].toInt().toChar() == '0'
        }

        // Huffman-decode digits (RFC 7541 Appendix B):
        //   '0'=0x00(5 bits), '1'=0x01(5), '2'=0x02(5)
        //   '3'=0x19(6),      '4'=0x1a(6), '5'=0x1b(6), '6'=0x1c(6),
        //   '7'=0x1d(6),      '8'=0x1e(6), '9'=0x1f(6)
        return huffmanDecodeStatusDigits(headerBlock, valueStart, valueLen) == "200"
    }

    /**
     * Decodes a Huffman-encoded byte sequence that contains only ASCII digits
     * (used for HTTP/2 status codes). Returns the decoded string, or empty if
     * any non-digit code is encountered.
     */
    private fun huffmanDecodeStatusDigits(data: ByteArray, start: Int, len: Int): String {
        val sb = StringBuilder()
        var bits: Long = 0
        var numBits = 0
        for (i in 0 until len) {
            bits = (bits shl 8) or (data[start + i].toLong() and 0xFFL)
            numBits += 8
        }
        while (numBits >= 5) {
            val top5 = ((bits ushr (numBits - 5)) and 0x1FL).toInt()
            // 5-bit codes: '0'=0x00, '1'=0x01, '2'=0x02
            if (top5 in 0x00..0x02) {
                sb.append(('0'.code + top5).toChar())
                numBits -= 5
                continue
            }
            if (numBits < 6) break
            val top6 = ((bits ushr (numBits - 6)) and 0x3FL).toInt()
            // 6-bit codes: '3'=0x19 ... '9'=0x1F
            if (top6 in 0x19..0x1F) {
                sb.append(('0'.code + (top6 - 0x19) + 3).toChar())
                numBits -= 6
                continue
            }
            break
        }
        return sb.toString()
    }

    /**
     * Performs HTTP/2 connection setup: sends preface + SETTINGS + WINDOW_UPDATE,
     * exchanges settings with server, sends HEADERS for the stream-one POST.
     */
    private suspend fun performH2Setup() {
        var initData = ByteArray(0)

        initData += H2_PREFACE

        // Client SETTINGS: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=4MB, MAX_HEADER_LIST_SIZE=10MB
        val settingsPayload = byteArrayOf(
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04,
            ((H2_STREAM_WINDOW_SIZE shr 24) and 0xFF).toByte(),
            ((H2_STREAM_WINDOW_SIZE shr 16) and 0xFF).toByte(),
            ((H2_STREAM_WINDOW_SIZE shr 8) and 0xFF).toByte(),
            (H2_STREAM_WINDOW_SIZE and 0xFF).toByte(),
            0x00, 0x06, 0x00.toByte(), 0xA0.toByte(), 0x00, 0x00
        )
        initData += buildH2Frame(H2_FRAME_SETTINGS, 0, 0u, settingsPayload)

        // Connection-level WINDOW_UPDATE: 1<<30 raw increment
        val windowIncrement = H2_CONN_WINDOW_SIZE
        val wuPayload = byteArrayOf(
            ((windowIncrement shr 24) and 0xFF).toByte(),
            ((windowIncrement shr 16) and 0xFF).toByte(),
            ((windowIncrement shr 8) and 0xFF).toByte(),
            (windowIncrement and 0xFF).toByte()
        )
        initData += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 0u, wuPayload)

        // HEADERS sent immediately, without waiting for server SETTINGS.
        if (mode == XHttpMode.STREAM_ONE) {
            val headerBlock = encodeH2RequestHeaders(method = "POST", includeMeta = false)
            initData += buildH2Frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1u, headerBlock)
        } else {
            // stream-up / packet-up: stream 1 is the download GET
            val headerBlock = encodeH2RequestHeaders(method = "GET", includeMeta = true)
            initData += buildH2Frame(H2_FRAME_HEADERS,
                (H2_FLAG_END_HEADERS.toInt() or H2_FLAG_END_STREAM.toInt()).toByte(),
                1u, headerBlock)
        }

        if (mode == XHttpMode.STREAM_UP) {
            val uploadHeaders = encodeH2UploadHeaders(seq = null)
            initData += buildH2Frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, h2UploadStreamId, uploadHeaders)
        }

        downloadSend(initData)

        readH2SetupFrames()
    }

    /**
     * Reads frames until the server's SETTINGS is received and ACKed.
     * Does NOT wait for the 200 OK response HEADERS — that is handled later by receiveH2Data.
     * Without this, CDNs that buffer the response until the backend produces body data
     * (which requires the POST sent after setup completes) would deadlock the handshake.
     */
    private suspend fun readH2SetupFrames() {
        var resumeAfter = false
        while (true) {
            val frame = readH2Frame()

            when (frame.type) {
                H2_FRAME_SETTINGS -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) != 0) {
                        continue
                    } else {
                        parseH2Settings(frame.payload)
                        val ack = buildH2Frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0u, byteArrayOf())
                        try { downloadSend(ack) } catch (_: Exception) {}
                        if (resumeAfter) drainH2FlowResumptions()
                        return
                    }
                }
                H2_FRAME_HEADERS -> {
                    val isDownload = frame.streamId == 0u || frame.streamId == 1u
                    if (isDownload && checkH2ResponseStatus(frame.payload)) {
                        lock.withLock { h2ResponseReceived = true }
                    }
                    if (resumeAfter) drainH2FlowResumptions()
                    return
                }
                H2_FRAME_WINDOW_UPDATE -> {
                    applyH2WindowUpdate(frame)
                    resumeAfter = true
                    continue
                }
                H2_FRAME_PING -> {
                    val pong = buildH2Frame(H2_FRAME_PING, H2_FLAG_ACK, 0u, frame.payload)
                    try { downloadSend(pong) } catch (_: Exception) {}
                    continue
                }
                H2_FRAME_GOAWAY -> {
                    throw XHttpError.SetupFailed("Server sent GOAWAY during setup")
                }
                H2_FRAME_DATA -> {
                    // Early DATA before we saw HEADERS — buffer it
                    lock.withLock {
                        appendToH2DataBuffer(frame.payload)
                    }
                    continue
                }
                else -> {
                    continue
                }
            }
        }
    }

    /**
     * Applies a WINDOW_UPDATE frame to the appropriate window:
     * - Stream ID 0 increments the connection-level window.
     * - Stream IDs registered in [h2PacketStreamWindows] update their per-stream window.
     * - Other stream IDs update the (single) active stream-level window.
     *
     * Caller is responsible for calling [drainH2FlowResumptions] afterwards if any
     * blocked sends should retry.
     */
    private fun applyH2WindowUpdate(frame: H2Frame) {
        if (frame.payload.size < 4) return
        val increment = (((frame.payload[0].toInt() and 0xFF) shl 24) or
                ((frame.payload[1].toInt() and 0xFF) shl 16) or
                ((frame.payload[2].toInt() and 0xFF) shl 8) or
                (frame.payload[3].toInt() and 0xFF)) and 0x7FFFFFFF
        lock.withLock {
            when {
                frame.streamId == 0u -> h2PeerConnectionWindow += increment
                h2PacketStreamWindows.containsKey(frame.streamId) -> {
                    h2PacketStreamWindows[frame.streamId] =
                        (h2PacketStreamWindows[frame.streamId] ?: 0) + increment
                }
                else -> h2PeerStreamSendWindow += increment
            }
        }
    }

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
                0x04 -> { // INITIAL_WINDOW_SIZE (RFC 7540 §6.9.2: affects stream windows only)
                    lock.withLock {
                        val delta = value - h2PeerInitialWindowSize
                        h2PeerInitialWindowSize = value
                        h2PeerStreamSendWindow += delta
                    }
                }
                0x05 -> { // MAX_FRAME_SIZE
                    lock.withLock { h2MaxFrameSize = value }
                }
            }
        }
    }

    /**
     * Suspends the caller until at least one outstanding flow-control resumption fires
     * (or the connection closes).
     */
    private suspend fun awaitH2FlowResumption() {
        suspendCancellableCoroutine<Unit> { cont ->
            val added: Boolean = lock.withLock {
                if (h2StreamClosed || !_isConnected) {
                    false
                } else {
                    h2FlowResumptions.add(cont)
                    true
                }
            }
            if (!added) {
                if (cont.isActive) cont.resumeWithException(XHttpError.ConnectionClosed)
                return@suspendCancellableCoroutine
            }
            cont.invokeOnCancellation {
                lock.withLock { h2FlowResumptions.remove(cont) }
            }
        }
    }

    /** Resumes all pending flow-control waiters after a WINDOW_UPDATE. */
    private fun drainH2FlowResumptions() {
        val waiters: List<CancellableContinuation<Unit>> = lock.withLock {
            val list = h2FlowResumptions.toList()
            h2FlowResumptions.clear()
            list
        }
        for (cont in waiters) {
            if (cont.isActive) cont.resume(Unit)
        }
    }

    /**
     * Sends data as HTTP/2 DATA frame(s) on the given stream, respecting peer flow control.
     * Batches as many frames as the window allows into a single transport write,
     * suspending if the window is exhausted.
     */
    private suspend fun sendH2Data(data: ByteArray, streamId: UInt = 1u) {
        var offset = 0
        while (offset < data.size) {
            val (nextOffset, frames) = lock.withLock {
                if (h2StreamClosed) throw XHttpError.ConnectionClosed
                val window = minOf(h2PeerConnectionWindow, h2PeerStreamSendWindow)
                if (window <= 0) return@withLock Pair(offset, ByteArray(0))

                val maxSize = h2MaxFrameSize
                var currentOffset = offset
                var windowRemaining = window
                var framesBuf = ByteArray(0)
                while (currentOffset < data.size) {
                    val remaining = data.size - currentOffset
                    val chunkSize = minOf(remaining, minOf(maxSize, windowRemaining))
                    if (chunkSize <= 0) break
                    val chunk = data.copyOfRange(currentOffset, currentOffset + chunkSize)
                    framesBuf += buildH2Frame(H2_FRAME_DATA, 0, streamId, chunk)
                    currentOffset += chunkSize
                    windowRemaining -= chunkSize
                }
                val totalSent = window - windowRemaining
                h2PeerConnectionWindow -= totalSent
                h2PeerStreamSendWindow -= totalSent
                Pair(currentOffset, framesBuf)
            }

            if (frames.isEmpty()) {
                // Window is empty — wait for WINDOW_UPDATE
                awaitH2FlowResumption()
                continue
            }
            try {
                downloadSend(frames)
            } catch (e: Throwable) {
                lock.withLock { h2StreamClosed = true }
                throw e
            }
            offset = nextOffset
        }
    }

    /**
     * Sends data as a packet-up H2 upload: opens a new HTTP/2 stream with HEADERS + DATA + END_STREAM.
     *
     * Each packet-up upload uses a unique stream ID. Each new stream starts with the
     * peer's INITIAL_WINDOW_SIZE for its own stream window; only the connection window
     * is shared.
     */
    private suspend fun sendH2PacketUp(data: ByteArray, seq: Long) {
        val streamId: UInt
        val initialFrames: ByteArray
        var startOffset: Int
        var perStreamRemaining: Int

        lock.withLock {
            if (h2StreamClosed) throw XHttpError.ConnectionClosed
            streamId = h2NextPacketStreamId
            h2NextPacketStreamId += 2u
            val maxSize = h2MaxFrameSize
            // Each new stream starts with h2PeerInitialWindowSize.
            val streamWindow = h2PeerInitialWindowSize

            val headerBlock = encodeH2UploadHeaders(seq, contentLength = data.size)
            val headerFlags: Byte = if (data.isEmpty()) {
                (H2_FLAG_END_HEADERS.toInt() or H2_FLAG_END_STREAM.toInt()).toByte()
            } else {
                H2_FLAG_END_HEADERS
            }
            var outbound = buildH2Frame(H2_FRAME_HEADERS, headerFlags, streamId, headerBlock)

            if (data.isEmpty()) {
                initialFrames = outbound
                startOffset = 0
                perStreamRemaining = streamWindow
            } else {
                // Batch DATA frames with HEADERS into a single write when window allows
                val window = minOf(h2PeerConnectionWindow, streamWindow)
                var currentOffset = 0
                var windowRemaining = window
                while (currentOffset < data.size) {
                    val remaining = data.size - currentOffset
                    val chunkSize = minOf(remaining, minOf(maxSize, windowRemaining))
                    if (chunkSize <= 0) break
                    val isLast = (currentOffset + chunkSize) >= data.size
                    val flags: Byte = if (isLast) H2_FLAG_END_STREAM else 0
                    val chunk = data.copyOfRange(currentOffset, currentOffset + chunkSize)
                    outbound += buildH2Frame(H2_FRAME_DATA, flags, streamId, chunk)
                    currentOffset += chunkSize
                    windowRemaining -= chunkSize
                }
                val totalSent = window - windowRemaining
                h2PeerConnectionWindow -= totalSent
                perStreamRemaining = streamWindow - totalSent
                startOffset = currentOffset
                initialFrames = outbound
            }
        }

        try {
            downloadSend(initialFrames)
        } catch (e: Throwable) {
            lock.withLock { h2StreamClosed = true }
            throw e
        }

        if (startOffset < data.size) {
            // Remaining data needs more window — continue via sendH2PacketUpData
            sendH2PacketUpData(data, streamId, startOffset, perStreamRemaining)
        }
    }

    /**
     * Sends remaining DATA frames for a packet-up upload stream, with END_STREAM on
     * the last frame. Tracks the per-stream remaining window in
     * [h2PacketStreamWindows] when blocked, so stream-level WINDOW_UPDATE can refill it.
     */
    private suspend fun sendH2PacketUpData(
        data: ByteArray,
        streamId: UInt,
        offset: Int,
        initialStreamWindow: Int
    ) {
        var currentOffset = offset
        var streamWindow = initialStreamWindow

        while (currentOffset < data.size) {
            val (nextOffset, frames, newStreamWindow) = lock.withLock {
                if (h2StreamClosed) throw XHttpError.ConnectionClosed

                // Use window updated by WINDOW_UPDATE if this stream was previously blocked.
                val effectiveStreamWindow = h2PacketStreamWindows.remove(streamId) ?: streamWindow
                val window = minOf(h2PeerConnectionWindow, effectiveStreamWindow)

                if (window <= 0) {
                    h2PacketStreamWindows[streamId] = effectiveStreamWindow
                    return@withLock Triple(currentOffset, ByteArray(0), effectiveStreamWindow)
                }

                val maxSize = h2MaxFrameSize
                var off = currentOffset
                var windowRemaining = window
                var framesBuf = ByteArray(0)
                while (off < data.size) {
                    val remaining = data.size - off
                    val chunkSize = minOf(remaining, minOf(maxSize, windowRemaining))
                    if (chunkSize <= 0) break
                    val isLast = (off + chunkSize) >= data.size
                    val flags: Byte = if (isLast) H2_FLAG_END_STREAM else 0
                    val chunk = data.copyOfRange(off, off + chunkSize)
                    framesBuf += buildH2Frame(H2_FRAME_DATA, flags, streamId, chunk)
                    off += chunkSize
                    windowRemaining -= chunkSize
                }
                val totalSent = window - windowRemaining
                h2PeerConnectionWindow -= totalSent
                Triple(off, framesBuf, effectiveStreamWindow - totalSent)
            }

            if (frames.isEmpty()) {
                awaitH2FlowResumption()
                continue
            }

            try {
                downloadSend(frames)
            } catch (e: Throwable) {
                lock.withLock { h2StreamClosed = true }
                throw e
            }
            currentOffset = nextOffset
            streamWindow = newStreamWindow
        }
    }

    /**
     * Receives data from HTTP/2 DATA frames on the download stream (stream 1).
     * Frames for other streams (upload responses) are silently consumed.
     *
     * Sends batched WINDOW_UPDATE frames at the 50% threshold. Only sends stream-level
     * WINDOW_UPDATE for the download stream; upload streams may already be closed, and
     * sending WINDOW_UPDATE for a closed stream triggers RST_STREAM (STREAM_CLOSED)
     * from the server.
     */
    private suspend fun receiveH2Data(): ByteArray? {
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

        while (true) {
            val frame: H2Frame
            try {
                frame = readH2Frame()
            } catch (e: Exception) {
                return null
            }

            val isDownloadStream = frame.streamId == 0u || frame.streamId == 1u

            when (frame.type) {
                H2_FRAME_DATA -> {
                    if (frame.payload.isNotEmpty()) {
                        // Batch WINDOW_UPDATEs: accumulate consumed bytes and send when
                        // >= 50% of window is consumed.
                        val (connInc, streamInc) = lock.withLock {
                            h2ConnectionReceiveConsumed += frame.payload.size
                            if (isDownloadStream) {
                                h2StreamReceiveConsumed += frame.payload.size
                            }
                            val threshold = h2LocalWindowSize / 2
                            val ci = if (h2ConnectionReceiveConsumed >= threshold) {
                                val v = h2ConnectionReceiveConsumed
                                h2ConnectionReceiveConsumed = 0
                                v
                            } else 0
                            val si = if (isDownloadStream && h2StreamReceiveConsumed >= threshold) {
                                val v = h2StreamReceiveConsumed
                                h2StreamReceiveConsumed = 0
                                v
                            } else 0
                            Pair(ci, si)
                        }

                        if (connInc > 0 || streamInc > 0) {
                            var updates = ByteArray(0)
                            if (connInc > 0) {
                                val p = byteArrayOf(
                                    ((connInc shr 24) and 0xFF).toByte(),
                                    ((connInc shr 16) and 0xFF).toByte(),
                                    ((connInc shr 8) and 0xFF).toByte(),
                                    (connInc and 0xFF).toByte()
                                )
                                updates += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 0u, p)
                            }
                            if (streamInc > 0) {
                                val p = byteArrayOf(
                                    ((streamInc shr 24) and 0xFF).toByte(),
                                    ((streamInc shr 16) and 0xFF).toByte(),
                                    ((streamInc shr 8) and 0xFF).toByte(),
                                    (streamInc and 0xFF).toByte()
                                )
                                updates += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, frame.streamId, p)
                            }
                            try { downloadSend(updates) } catch (_: Exception) {}
                        }
                    }

                    if (isDownloadStream) {
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
                    } else {
                        // Upload stream response data — ignore
                        continue
                    }
                }
                H2_FRAME_HEADERS -> {
                    if (isDownloadStream) {
                        if ((frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0) {
                            lock.withLock { h2StreamClosed = true }
                            return null
                        } else if (!h2ResponseReceived) {
                            if (checkH2ResponseStatus(frame.payload)) {
                                lock.withLock { h2ResponseReceived = true }
                            }
                            continue
                        } else {
                            continue
                        }
                    } else {
                        // Upload stream response — ignore regardless of status. The POST
                        // data was already delivered; a non-200 reply (e.g. 500 from CDN)
                        // should not tear down the download.
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
                    applyH2WindowUpdate(frame)
                    drainH2FlowResumptions()
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
                    // Only close on download stream RST_STREAM (stream 1).
                    // Upload stream RST_STREAMs can be ignored.
                    if (isDownloadStream) {
                        lock.withLock { h2StreamClosed = true }
                        return null
                    }
                    // Drop any tracked window for this stream — it can't accept more data.
                    lock.withLock { h2PacketStreamWindows.remove(frame.streamId) }
                    continue
                }
                else -> {
                    continue
                }
            }
        }
    }

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
        if (h2ReadBufferLen + data.size > h2MaxReadBufferSize) {
            h2ReadBufferLen = 0
            throw IOException("H2 read buffer overflow (>${h2MaxReadBufferSize} bytes)")
        }
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

/**
 * Stateful chunked transfer encoding decoder (HTTP/1.1 RFC 7230 S4.1).
 *
 * Handles partial reads: data can be fed incrementally and chunks extracted
 * as they become complete.
 */
class ChunkedTransferDecoder {
    private var buffer = ByteArray(0)
    private var bufferLen = 0
    private var _isFinished = false

    val isFinished: Boolean get() = _isFinished

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
     * Returns the chunk payload (without framing), null if not enough data is available
     * yet, or null when a zero-length terminator chunk is found (EOF).
     */
    fun nextChunk(): ByteArray? {
        if (_isFinished) return null

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

        val dataStart = crlfIdx + 2
        val needed = dataStart + chunkSize.toInt() + 2 // chunk data + \r\n
        if (bufferLen < needed) {
            return null
        }

        val chunkData = buffer.copyOfRange(dataStart, dataStart + chunkSize.toInt())

        val remaining = bufferLen - needed
        if (remaining > 0) {
            System.arraycopy(buffer, needed, buffer, 0, remaining)
        }
        bufferLen = remaining

        return chunkData
    }

    private fun findCRLF(buf: ByteArray, len: Int, startFrom: Int): Int {
        for (i in startFrom until len - 1) {
            if (buf[i] == 0x0D.toByte() && buf[i + 1] == 0x0A.toByte()) {
                return i
            }
        }
        return -1
    }
}

/** Chunked transfer encoding encoder (HTTP/1.1 RFC 7230 S4.1). */
object ChunkedTransferEncoder {

    /** Encodes data as a single chunked-encoded chunk: `{hex-size}\r\n{data}\r\n`. */
    fun encode(data: ByteArray): ByteArray {
        val sizeStr = data.size.toString(16)
        val sizeBytes = sizeStr.toByteArray(Charsets.UTF_8)
        val result = ByteArray(sizeBytes.size + 2 + data.size + 2)
        var offset = 0
        System.arraycopy(sizeBytes, 0, result, offset, sizeBytes.size)
        offset += sizeBytes.size
        result[offset++] = 0x0D
        result[offset++] = 0x0A
        System.arraycopy(data, 0, result, offset, data.size)
        offset += data.size
        result[offset++] = 0x0D
        result[offset] = 0x0A
        return result
    }

    /** Encodes the terminal zero-length chunk: `0\r\n\r\n`. */
    fun encodeTerminator(): ByteArray {
        return byteArrayOf(0x30, 0x0D, 0x0A, 0x0D, 0x0A)
    }
}

sealed class XHttpError(message: String) : Exception(message) {
    class SetupFailed(reason: String) : XHttpError("XHTTP setup failed: $reason")
    class HttpError(reason: String) : XHttpError("XHTTP HTTP error: $reason")
    object ConnectionClosed : XHttpError("XHTTP connection closed")
}
