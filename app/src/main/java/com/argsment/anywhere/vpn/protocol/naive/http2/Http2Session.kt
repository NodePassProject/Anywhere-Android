package com.argsment.anywhere.vpn.protocol.naive.http2

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsTransport
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream

private val logger = AnywhereLogger("HTTP2Session")

/**
 * One TLS connection with multiple concurrent CONNECT streams. Owns the persistent
 * read loop that routes frames to per-stream [Http2Stream] instances, the 128 MB
 * connection receive window, and serializes writes through a [Mutex]. The first
 * caller to [ensureReady] performs the handshake; concurrent callers queue on
 * [CompletableDeferred].
 */
class Http2Session(
    private val configuration: NaiveConfiguration,
    private val scope: CoroutineScope,
    private val tunnel: ProxyConnection? = null,
    var onClose: (() -> Unit)? = null
) {
    companion object {
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        private val CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
        private const val MAX_RECEIVE_BUFFER_SIZE = 2_097_152
        private const val MAX_CONCURRENT_STREAMS = 100
    }

    enum class State { IDLE, CONNECTING, READY, CLOSED }

    @Volatile
    private var state = State.IDLE

    @Volatile
    private var goawayReceived = false
    private var goawayLastStreamID = Int.MAX_VALUE

    private var transport: NaiveTlsTransport? = null
    private val receiveBuffer = Http2Buffer()

    private val streams = mutableMapOf<Int, Http2Stream>()
    private var nextStreamID = 1
    private val streamsLock = Any()

    private var connectionSendWindow = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE
    private var connectionRecvConsumed = 0
    private val flowLock = Any()
    private var connectionWindowAwaiter: CompletableDeferred<Unit>? = null

    /** The server's SETTINGS_INITIAL_WINDOW_SIZE, used as the initial send window for new streams. */
    var serverInitialWindowSize = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE
        private set

    val hpackDecoder = HpackDecoder()

    private val writeMutex = Mutex()

    private var connecting = false
    private val pendingReady = mutableListOf<CompletableDeferred<Unit>>()

    val hasCapacity: Boolean
        get() = state == State.READY && !goawayReceived &&
            synchronized(streamsLock) { streams.size < MAX_CONCURRENT_STREAMS }

    val isClosed: Boolean get() = state == State.CLOSED

    suspend fun acquireStream(destination: String): Http2Stream {
        ensureReady()

        if (state != State.READY) throw Http2Error.NotReady()
        if (goawayReceived) throw Http2Error.Goaway()

        return synchronized(streamsLock) {
            val streamID = nextStreamID
            nextStreamID += 2
            val stream = Http2Stream(streamID, this, destination)
            streams[streamID] = stream
            stream
        }
    }

    /**
     * Atomically checks capacity and reserves a stream slot. Returns null if the
     * session is at capacity, going-away, or closed. Used by [Http2SessionPool] so
     * concurrent acquisitions cannot exceed [MAX_CONCURRENT_STREAMS]. Mirrors iOS
     * `HTTP2Session.tryReserveStream()`.
     */
    fun tryReserveStream(destination: String): Http2Stream? {
        if (state != State.READY || goawayReceived) return null
        return synchronized(streamsLock) {
            if (streams.size >= MAX_CONCURRENT_STREAMS) return@synchronized null
            val streamID = nextStreamID
            nextStreamID += 2
            val stream = Http2Stream(streamID, this, destination)
            streams[streamID] = stream
            stream
        }
    }

    fun removeStream(streamID: Int) {
        synchronized(streamsLock) { streams.remove(streamID) }
        if (goawayReceived && synchronized(streamsLock) { streams.isEmpty() }) {
            close()
        }
    }

    /**
     * Acks [bytes] consumed from [streamID]'s data channel by the application.
     * Updates per-stream and connection-level recv counters and emits WINDOW_UPDATE
     * when half the window has been drained. Mirrors iOS
     * `HTTP2Stream.acknowledgeConsumedData(count:)`. Called by [Http2Stream.receiveData].
     */
    fun acknowledgeConsumedData(streamID: Int, bytes: Int) {
        if (bytes <= 0) return
        val connInc: Int?
        synchronized(flowLock) {
            connectionRecvConsumed += bytes
            connInc = if (connectionRecvConsumed >= Http2FlowControl.NAIVE_SESSION_MAX_RECV_WINDOW / 2) {
                val v = connectionRecvConsumed
                connectionRecvConsumed = 0
                v
            } else null
        }
        if (connInc != null) {
            scope.launch { sendWindowUpdate(0, connInc) }
        }
        val stream = synchronized(streamsLock) { streams[streamID] }
        stream?.flowControl?.consumeRecv(bytes)?.let { streamInc ->
            scope.launch { sendWindowUpdate(streamID, streamInc) }
        }
    }

    /**
     * Sends RST_STREAM with the given error code. Used when a stream is closed
     * by the client before the server closes it, so the server can reclaim the
     * stream slot. Mirrors iOS `HTTP2Stream.close()` sending CANCEL.
     */
    fun sendReset(streamID: Int, errorCode: Int) {
        scope.launch { sendFrameRaw(Http2Framer.rstStreamFrame(streamID, errorCode)) }
    }

    private suspend fun ensureReady() {
        if (state == State.READY) return
        if (state == State.CLOSED) throw Http2Error.ConnectionFailed("Session closed")

        if (connecting) {
            val deferred = CompletableDeferred<Unit>()
            pendingReady.add(deferred)
            deferred.await()
            return
        }

        connecting = true

        try {
            state = State.CONNECTING

            val t = NaiveTlsTransport(
                host = configuration.proxyHost,
                port = configuration.proxyPort,
                sni = configuration.effectiveSNI,
                alpn = listOf("h2"),
                tunnel = tunnel
            )
            transport = t
            t.connect()

            sendConnectionPreface(t)
            processHandshake(t)

            state = State.READY
            connecting = false

            scope.launch { readLoop() }

            val pending = pendingReady.toList()
            pendingReady.clear()
            for (deferred in pending) {
                deferred.complete(Unit)
            }
        } catch (e: Exception) {
            state = State.CLOSED
            connecting = false
            val pending = pendingReady.toList()
            pendingReady.clear()
            for (deferred in pending) {
                deferred.completeExceptionally(e)
            }
            onClose?.invoke()
            throw e
        }
    }

    private suspend fun sendConnectionPreface(t: NaiveTlsTransport) {
        val buf = ByteArrayOutputStream()
        buf.write(CONNECTION_PREFACE)

        val settings = Http2Framer.settingsFrame(listOf(
            0x1 to 65536,
            0x2 to 0,
            0x3 to MAX_CONCURRENT_STREAMS,
            0x4 to Http2FlowControl.NAIVE_INITIAL_WINDOW_SIZE,
            0x5 to 16384,
            0x6 to 262144,
        ))
        buf.write(Http2Framer.serialize(settings))

        val windowUpdate = Http2Framer.windowUpdateFrame(
            streamID = 0,
            increment = Http2FlowControl.CONNECTION_WINDOW_UPDATE_INCREMENT
        )
        buf.write(Http2Framer.serialize(windowUpdate))

        t.send(buf.toByteArray())
    }

    /** Processes frames until server SETTINGS is received and ACK'd; CONNECT is per-stream. */
    private suspend fun processHandshake(t: NaiveTlsTransport) {
        while (true) {
            val frame = Http2Framer.deserialize(receiveBuffer)
            if (frame == null) {
                readFromTransport(t)
                continue
            }

            when (frame.type) {
                Http2FrameType.SETTINGS -> {
                    if (frame.hasFlag(Http2FrameFlags.ACK)) continue
                    handleServerSettings(frame)
                    sendFrameRaw(Http2Framer.settingsAckFrame())
                    return
                }

                Http2FrameType.WINDOW_UPDATE -> {
                    Http2Framer.parseWindowUpdate(frame.payload)?.let { inc ->
                        if (frame.streamID == 0) connectionSendWindow += inc
                    }
                }

                Http2FrameType.PING -> {
                    if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                        sendFrameRaw(Http2Framer.pingAckFrame(frame.payload))
                    }
                }

                Http2FrameType.GOAWAY -> {
                    val parsed = Http2Framer.parseGoaway(frame.payload)
                    logger.warning("GOAWAY during handshake: ${parsed?.lastStreamID}, ${parsed?.errorCode}")
                    throw Http2Error.Goaway()
                }

                else -> {}
            }
        }
    }

    private suspend fun readLoop() {
        val t = transport ?: return
        try {
            while (state != State.CLOSED) {
                val frame = Http2Framer.deserialize(receiveBuffer)
                if (frame == null) {
                    readFromTransport(t)
                    continue
                }
                routeFrame(frame)
            }
        } catch (e: Exception) {
            if (state != State.CLOSED) {
                logger.error("Read loop error: ${e.message}")
                closeWithError(e)
            }
        }
    }

    private fun routeFrame(frame: Http2Frame) {
        when (frame.type) {
            Http2FrameType.DATA -> {
                if (frame.streamID == 0) return
                val stream = synchronized(streamsLock) { streams[frame.streamID] } ?: return

                // WINDOW_UPDATE deferred to consume time; see [acknowledgeConsumedData]
                // (mirrors iOS HTTP2Stream.acknowledgeConsumedData semantics).
                if (frame.payload.isNotEmpty()) {
                    stream.deliverData(frame.payload)
                }

                if (frame.hasFlag(Http2FrameFlags.END_STREAM)) {
                    // END_STREAM is a clean half-close from the server, not a reset.
                    stream.deliverEndStream()
                    synchronized(streamsLock) { streams.remove(frame.streamID) }
                }
            }

            Http2FrameType.HEADERS -> {
                if (frame.streamID == 0) return
                val stream = synchronized(streamsLock) { streams[frame.streamID] } ?: return
                val headers = hpackDecoder.decode(frame.payload)
                if (headers != null) {
                    stream.deliverHeaders(headers)
                } else {
                    stream.deliverError(Http2Error.ProtocolError("Failed to decode headers"))
                }
            }

            Http2FrameType.RST_STREAM -> {
                if (frame.streamID == 0) return
                val stream = synchronized(streamsLock) { streams[frame.streamID] }
                if (stream != null) {
                    stream.deliverReset()
                    synchronized(streamsLock) { streams.remove(frame.streamID) }
                }
            }

            Http2FrameType.SETTINGS -> {
                if (frame.hasFlag(Http2FrameFlags.ACK)) return
                handleServerSettings(frame)
                scope.launch { sendFrameRaw(Http2Framer.settingsAckFrame()) }
            }

            Http2FrameType.PING -> {
                if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                    scope.launch { sendFrameRaw(Http2Framer.pingAckFrame(frame.payload)) }
                }
            }

            Http2FrameType.WINDOW_UPDATE -> {
                Http2Framer.parseWindowUpdate(frame.payload)?.let { inc ->
                    if (frame.streamID == 0) {
                        synchronized(flowLock) {
                            connectionSendWindow += inc
                            // Wake any sender suspended on connection-level flow control.
                            connectionWindowAwaiter?.complete(Unit)
                            connectionWindowAwaiter = null
                        }
                    } else {
                        synchronized(streamsLock) { streams[frame.streamID] }
                            ?.deliverWindowUpdate(inc)
                    }
                }
            }

            Http2FrameType.GOAWAY -> {
                val parsed = Http2Framer.parseGoaway(frame.payload)
                goawayReceived = true
                if (parsed != null) {
                    goawayLastStreamID = parsed.lastStreamID
                    logger.warning("GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")

                    val affected = synchronized(streamsLock) {
                        streams.filter { it.key > parsed.lastStreamID }
                    }
                    for ((sid, stream) in affected) {
                        stream.deliverGoaway()
                        synchronized(streamsLock) { streams.remove(sid) }
                    }
                }

                if (synchronized(streamsLock) { streams.isEmpty() }) {
                    close()
                }
            }
        }
    }

    suspend fun sendConnectRequest(streamID: Int, destination: String) {
        val extraHeaders = mutableListOf<Pair<String, String>>()

        configuration.basicAuth?.let { auth ->
            extraHeaders.add("proxy-authorization" to "Basic $auth")
        }
        extraHeaders.add("user-agent" to USER_AGENT)
        extraHeaders.addAll(NaivePaddingNegotiator.requestHeaders())

        val headerBlock = HpackEncoder.encodeConnectRequest(
            authority = destination,
            extraHeaders = extraHeaders
        )
        val headersFrame = Http2Framer.headersFrame(
            streamID = streamID,
            headerBlock = headerBlock,
            endStream = false
        )

        writeMutex.withLock {
            transport?.send(Http2Framer.serialize(headersFrame))
                ?: throw Http2Error.ConnectionFailed("Transport closed")
        }
    }

    suspend fun sendData(streamID: Int, data: ByteArray, streamFlowControl: Http2StreamFlowControl) {
        val maxPayload = Http2Framer.MAX_DATA_PAYLOAD
        var currentOffset = 0

        while (currentOffset < data.size) {
            val remaining = data.size - currentOffset
            val maxAllowed = minOf(connectionSendWindow, streamFlowControl.sendWindow)
            val chunkSize = minOf(remaining, minOf(maxPayload, maxAllowed))
            if (chunkSize <= 0) {
                // Flow-control blocked. Suspend until a WINDOW_UPDATE arrives
                // for the exhausted scope (connection or stream). Mirrors iOS
                // HTTP2Session.swift:451-455 / HTTP2Connection.swift:427-433
                // — iOS schedules a 50ms retry; we use awaiters for precision.
                if (state == State.CLOSED) throw Http2Error.ConnectionFailed("Session closed")
                if (connectionSendWindow <= 0) {
                    val awaiter = synchronized(flowLock) {
                        if (connectionSendWindow > 0) null
                        else (connectionWindowAwaiter ?: CompletableDeferred<Unit>().also {
                            connectionWindowAwaiter = it
                        })
                    }
                    awaiter?.await()
                } else {
                    streamFlowControl.awaitWindow()
                }
                continue
            }

            connectionSendWindow -= chunkSize
            streamFlowControl.consumeSend(chunkSize)

            val chunk = data.copyOfRange(currentOffset, currentOffset + chunkSize)
            val frame = Http2Framer.dataFrame(streamID = streamID, payload = chunk)

            writeMutex.withLock {
                transport?.send(Http2Framer.serialize(frame))
                    ?: throw Http2Error.ConnectionFailed("Transport closed")
            }

            currentOffset += chunkSize
        }
    }

    private fun handleServerSettings(frame: Http2Frame) {
        val settings = Http2Framer.parseSettings(frame.payload)
        for ((id, value) in settings) {
            when (id) {
                0x4 -> { // SETTINGS_INITIAL_WINDOW_SIZE
                    val delta = value - serverInitialWindowSize
                    serverInitialWindowSize = value
                    // RFC 7540 §6.9.2: shift every existing stream's send window by delta.
                    for (stream in streams.values) {
                        stream.adjustSendWindow(delta)
                    }
                }
            }
        }
    }

    private suspend fun sendWindowUpdate(streamID: Int, increment: Int) {
        try {
            sendFrameRaw(Http2Framer.windowUpdateFrame(streamID = streamID, increment = increment))
        } catch (e: Exception) {
            logger.warning("Failed to send WINDOW_UPDATE: ${e.message}")
        }
    }

    private suspend fun sendFrameRaw(frame: Http2Frame) {
        writeMutex.withLock {
            try {
                transport?.send(Http2Framer.serialize(frame))
            } catch (e: Exception) {
                logger.warning("Failed to send frame: ${e.message}")
            }
        }
    }

    private suspend fun readFromTransport(t: NaiveTlsTransport) {
        val data = t.receive()
        if (data == null || data.isEmpty()) {
            throw Http2Error.ConnectionFailed("Connection closed")
        }
        receiveBuffer.append(data)
        if (receiveBuffer.available > MAX_RECEIVE_BUFFER_SIZE) {
            receiveBuffer.clear()
            throw Http2Error.ConnectionFailed("Receive buffer exceeded $MAX_RECEIVE_BUFFER_SIZE bytes")
        }
    }

    private fun closeWithError(error: Exception) {
        if (state == State.CLOSED) return
        state = State.CLOSED

        val allStreams = synchronized(streamsLock) {
            val snapshot = streams.values.toList()
            streams.clear()
            snapshot
        }
        for (stream in allStreams) {
            stream.deliverError(error)
        }

        synchronized(flowLock) {
            connectionWindowAwaiter?.completeExceptionally(error)
            connectionWindowAwaiter = null
        }

        transport?.cancel()
        transport = null
        onClose?.invoke()
    }

    fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED

        val allStreams = synchronized(streamsLock) {
            val snapshot = streams.values.toList()
            streams.clear()
            snapshot
        }
        for (stream in allStreams) {
            stream.deliverError(Http2Error.ConnectionFailed("Session closed"))
        }

        synchronized(flowLock) {
            connectionWindowAwaiter?.completeExceptionally(
                Http2Error.ConnectionFailed("Session closed")
            )
            connectionWindowAwaiter = null
        }

        transport?.cancel()
        transport = null
        hpackDecoder.reset()
        onClose?.invoke()
    }
}
