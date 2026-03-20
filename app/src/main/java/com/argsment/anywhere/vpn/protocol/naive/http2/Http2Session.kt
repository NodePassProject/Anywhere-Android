package com.argsment.anywhere.vpn.protocol.naive.http2

import android.util.Log
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsTransport
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream

private const val TAG = "Http2Session"

/**
 * Manages one TLS connection with multiple concurrent CONNECT streams.
 *
 * Handles:
 * - Connection preface and SETTINGS exchange (identical to [Http2Connection])
 * - Persistent read loop that routes frames to per-stream [Http2Stream] instances
 * - Connection-level flow control (128 MB receive window)
 * - Write serialization via [Mutex]
 * - GOAWAY handling with graceful stream draining
 *
 * The first caller to [ensureReady] performs the TLS+HTTP/2 handshake; concurrent
 * callers queue on [CompletableDeferred] (same pattern as MuxClient).
 */
class Http2Session(
    private val configuration: NaiveConfiguration,
    private val scope: CoroutineScope,
    private val tunnel: VlessConnection? = null,
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

    // -- Transport --

    private var transport: NaiveTlsTransport? = null
    private val receiveBuffer = Http2Buffer()

    // -- Streams --

    private val streams = mutableMapOf<Int, Http2Stream>()
    private var nextStreamID = 1

    // -- Flow Control (connection level) --

    private var connectionSendWindow = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE
    private var connectionRecvConsumed = 0

    /** The server's SETTINGS_INITIAL_WINDOW_SIZE (for new streams). */
    var serverInitialWindowSize = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE
        private set

    // -- HPACK --

    val hpackDecoder = HpackDecoder()

    // -- Write Serialization --

    private val writeMutex = Mutex()

    // -- Connection Setup (ensureReady pattern) --

    private var connecting = false
    private val pendingReady = mutableListOf<CompletableDeferred<Unit>>()

    val hasCapacity: Boolean
        get() = state == State.READY && !goawayReceived && streams.size < MAX_CONCURRENT_STREAMS

    val isClosed: Boolean get() = state == State.CLOSED

    // =========================================================================
    // Stream Management
    // =========================================================================

    /**
     * Acquires a new [Http2Stream] on this session.
     * Ensures the session is ready (handshake complete) before allocating the stream.
     */
    suspend fun acquireStream(destination: String): Http2Stream {
        ensureReady()

        if (state != State.READY) throw Http2Error.NotReady()
        if (goawayReceived) throw Http2Error.Goaway()

        val streamID = nextStreamID
        nextStreamID += 2

        val stream = Http2Stream(streamID, this, destination)
        streams[streamID] = stream
        return stream
    }

    fun removeStream(streamID: Int) {
        streams.remove(streamID)
        if (goawayReceived && streams.isEmpty()) {
            close()
        }
    }

    // =========================================================================
    // Connection Setup
    // =========================================================================

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

            // Start persistent read loop
            scope.launch { readLoop() }

            // Complete all pending callers
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

    /**
     * Processes frames during handshake until server SETTINGS is received and ACK'd.
     * Does NOT send CONNECT — that's per-stream.
     */
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
                    return // Handshake complete
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
                    Log.w(TAG, "GOAWAY during handshake: ${parsed?.lastStreamID}, ${parsed?.errorCode}")
                    throw Http2Error.Goaway()
                }

                else -> {}
            }
        }
    }

    // =========================================================================
    // Persistent Read Loop
    // =========================================================================

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
                Log.e(TAG, "Read loop error: ${e.message}")
                closeWithError(e)
            }
        }
    }

    private fun routeFrame(frame: Http2Frame) {
        when (frame.type) {
            Http2FrameType.DATA -> {
                if (frame.streamID == 0) return
                val stream = streams[frame.streamID] ?: return

                if (frame.payload.isNotEmpty()) {
                    // Connection-level receive flow control
                    connectionRecvConsumed += frame.payload.size
                    if (connectionRecvConsumed >= Http2FlowControl.NAIVE_SESSION_MAX_RECV_WINDOW / 2) {
                        val connInc = connectionRecvConsumed
                        connectionRecvConsumed = 0
                        scope.launch { sendWindowUpdate(0, connInc) }
                    }

                    // Stream-level receive flow control
                    val streamInc = stream.flowControl.consumeRecv(frame.payload.size)
                    if (streamInc != null) {
                        scope.launch { sendWindowUpdate(frame.streamID, streamInc) }
                    }

                    stream.deliverData(frame.payload)
                }

                if (frame.hasFlag(Http2FrameFlags.END_STREAM)) {
                    stream.deliverReset()
                    streams.remove(frame.streamID)
                }
            }

            Http2FrameType.HEADERS -> {
                if (frame.streamID == 0) return
                val stream = streams[frame.streamID] ?: return
                val headers = hpackDecoder.decode(frame.payload)
                if (headers != null) {
                    stream.deliverHeaders(headers)
                } else {
                    stream.deliverError(Http2Error.ProtocolError("Failed to decode headers"))
                }
            }

            Http2FrameType.RST_STREAM -> {
                if (frame.streamID == 0) return
                val stream = streams[frame.streamID]
                if (stream != null) {
                    stream.deliverReset()
                    streams.remove(frame.streamID)
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
                        connectionSendWindow += inc
                    } else {
                        streams[frame.streamID]?.deliverWindowUpdate(inc)
                    }
                }
            }

            Http2FrameType.GOAWAY -> {
                val parsed = Http2Framer.parseGoaway(frame.payload)
                goawayReceived = true
                if (parsed != null) {
                    goawayLastStreamID = parsed.lastStreamID
                    Log.w(TAG, "GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")

                    // Error streams with ID > lastStreamID
                    val affected = streams.filter { it.key > parsed.lastStreamID }
                    for ((sid, stream) in affected) {
                        stream.deliverGoaway()
                        streams.remove(sid)
                    }
                }

                if (streams.isEmpty()) {
                    close()
                }
            }
        }
    }

    // =========================================================================
    // Write Operations (called by Http2Stream)
    // =========================================================================

    /**
     * Sends a CONNECT request for [streamID] with auth + UA + padding headers.
     */
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

    /**
     * Sends DATA frames for [streamID], respecting both connection and stream flow control.
     */
    suspend fun sendData(streamID: Int, data: ByteArray, streamFlowControl: Http2StreamFlowControl) {
        val maxPayload = Http2Framer.MAX_DATA_PAYLOAD
        var currentOffset = 0

        while (currentOffset < data.size) {
            val remaining = data.size - currentOffset
            val maxAllowed = minOf(connectionSendWindow, streamFlowControl.sendWindow)
            val chunkSize = minOf(remaining, minOf(maxPayload, maxAllowed))
            if (chunkSize <= 0) {
                throw Http2Error.ProtocolError("Flow control blocked on stream $streamID")
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

    // =========================================================================
    // Internal
    // =========================================================================

    private fun handleServerSettings(frame: Http2Frame) {
        val settings = Http2Framer.parseSettings(frame.payload)
        for ((id, value) in settings) {
            when (id) {
                0x4 -> { // SETTINGS_INITIAL_WINDOW_SIZE
                    val delta = value - serverInitialWindowSize
                    serverInitialWindowSize = value
                    // Adjust all existing streams (RFC 7540 §6.9.2)
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
            Log.w(TAG, "Failed to send WINDOW_UPDATE: ${e.message}")
        }
    }

    private suspend fun sendFrameRaw(frame: Http2Frame) {
        writeMutex.withLock {
            try {
                transport?.send(Http2Framer.serialize(frame))
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send frame: ${e.message}")
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

        val allStreams = streams.values.toList()
        streams.clear()
        for (stream in allStreams) {
            stream.deliverError(error)
        }

        transport?.cancel()
        transport = null
        onClose?.invoke()
    }

    fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED

        val allStreams = streams.values.toList()
        streams.clear()
        for (stream in allStreams) {
            stream.deliverError(Http2Error.ConnectionFailed("Session closed"))
        }

        transport?.cancel()
        transport = null
        hpackDecoder.reset()
        onClose?.invoke()
    }
}
