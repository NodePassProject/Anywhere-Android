package com.argsment.anywhere.vpn.protocol.naive.http2

import android.util.Log
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsTransport
import java.io.IOException

private const val TAG = "Http2"

// -- Error --

sealed class Http2Error(message: String) : IOException(message) {
    class NotReady : Http2Error("HTTP/2 connection not ready")
    class ConnectionFailed(msg: String) : Http2Error("HTTP/2 connection failed: $msg")
    class ProtocolError(msg: String) : Http2Error("HTTP/2 protocol error: $msg")
    class TunnelFailed(statusCode: String) : Http2Error("HTTP/2 CONNECT tunnel failed with status $statusCode")
    class AuthenticationRequired : Http2Error("HTTP/2 proxy authentication required (407)")
    class Goaway : Http2Error("HTTP/2 GOAWAY received")
    class StreamReset(sid: Int) : Http2Error("HTTP/2 stream $sid reset")
}

/**
 * HTTP/2 session manager for a single CONNECT tunnel through a NaiveProxy server.
 *
 * Handles the full HTTP/2 lifecycle:
 * 1. Send connection preface and SETTINGS
 * 2. Exchange SETTINGS with the server
 * 3. Open a CONNECT tunnel on stream 1 with padding negotiation
 * 4. Bidirectional DATA relay through the tunnel
 *
 * Flow control uses NaiveProxy's window sizes (64 MB stream, 128 MB connection).
 */
class Http2Connection(
    private val transport: NaiveTlsTransport,
    private val configuration: NaiveConfiguration,
    /** The target `host:port` for the CONNECT tunnel. */
    private val destination: String
) {
    companion object {
        /** Chrome-like User-Agent for the CONNECT request. */
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

        /** The HTTP/2 connection preface (RFC 7540 §3.5). */
        private val CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

        /** Maximum receive buffer size (2 MB). Protects against unbounded growth. */
        private const val MAX_RECEIVE_BUFFER_SIZE = 2_097_152
    }

    // -- State --

    enum class State {
        IDLE,
        CONNECTING,
        /** Connection preface + SETTINGS sent, waiting for server SETTINGS. */
        PREFACE_SENT,
        /** SETTINGS exchanged, ready to send CONNECT. */
        READY,
        /** CONNECT request sent, waiting for response. */
        TUNNEL_PENDING,
        /** Tunnel established, data can flow. */
        TUNNEL_OPEN,
        CLOSED
    }

    private var state = State.IDLE
    private var flowControl = Http2FlowControl()
    private var receiveBuffer = Http2Buffer()

    /** The padding type negotiated with the server during CONNECT. */
    var negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE
        private set

    /** Whether the tunnel is open and ready for data transfer. */
    val isConnected: Boolean get() = state == State.TUNNEL_OPEN

    // -- Open Tunnel --

    /**
     * Establishes the HTTP/2 connection and opens a CONNECT tunnel.
     *
     * Performs the full setup sequence:
     * 1. TLS connection to the proxy server
     * 2. HTTP/2 connection preface and SETTINGS exchange
     * 3. Connection-level WINDOW_UPDATE (expand to 128 MB)
     * 4. CONNECT request with padding negotiation headers
     * 5. Receives and validates the 200 OK response
     */
    suspend fun openTunnel() {
        if (state != State.IDLE) throw Http2Error.ProtocolError("Invalid state for openTunnel")
        state = State.CONNECTING

        try {
            transport.connect()
            sendConnectionPreface()
            processHandshake()
        } catch (e: Exception) {
            state = State.CLOSED
            throw e
        }
    }

    // -- Data Transfer --

    /**
     * Sends data through the CONNECT tunnel as HTTP/2 DATA frames.
     *
     * Data is split into frames of at most 16,384 bytes (the HTTP/2 default
     * SETTINGS_MAX_FRAME_SIZE). Respects both connection and stream send windows.
     */
    suspend fun sendData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        sendDataFrames(data, 0)
    }

    /**
     * Receives the next chunk of data from the CONNECT tunnel.
     *
     * Reads and processes HTTP/2 frames until a DATA frame for stream 1 is found.
     * Control frames (PING, WINDOW_UPDATE, SETTINGS) are handled transparently.
     */
    suspend fun receiveData(): ByteArray? {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        return readNextDataFrame()
    }

    /** Closes the HTTP/2 connection. */
    fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        transport.cancel()
    }

    // -- Connection Preface --

    /** Sends the connection preface, initial SETTINGS, and connection-level WINDOW_UPDATE. */
    private suspend fun sendConnectionPreface() {
        val buf = java.io.ByteArrayOutputStream()

        // Connection preface (24 bytes)
        buf.write(CONNECTION_PREFACE)

        // SETTINGS matching Chrome/NaiveProxy defaults
        val settings = Http2Framer.settingsFrame(listOf(
            0x1 to 65536,     // HEADER_TABLE_SIZE
            0x2 to 0,         // ENABLE_PUSH (disabled for CONNECT)
            0x3 to 100,       // MAX_CONCURRENT_STREAMS
            0x4 to Http2FlowControl.NAIVE_INITIAL_WINDOW_SIZE, // INITIAL_WINDOW_SIZE = 64 MB
            0x5 to 16384,     // MAX_FRAME_SIZE
            0x6 to 262144,    // MAX_HEADER_LIST_SIZE
        ))
        buf.write(Http2Framer.serialize(settings))

        // WINDOW_UPDATE on stream 0: expand connection receive window to 128 MB
        val windowUpdate = Http2Framer.windowUpdateFrame(
            streamID = 0,
            increment = Http2FlowControl.CONNECTION_WINDOW_UPDATE_INCREMENT
        )
        buf.write(Http2Framer.serialize(windowUpdate))

        transport.send(buf.toByteArray())
        state = State.PREFACE_SENT
    }

    // -- Handshake Processing --

    /**
     * Processes HTTP/2 frames during the handshake phase (SETTINGS exchange → CONNECT).
     *
     * Reads frames from the receive buffer, handles control frames, and advances
     * through the state machine: prefaceSent → ready → tunnelPending → tunnelOpen.
     */
    private suspend fun processHandshake() {
        while (true) {
            val frame = Http2Framer.deserialize(receiveBuffer)
            if (frame == null) {
                // Need more data from transport
                readFromTransport()
                continue
            }

            when (frame.type) {
                Http2FrameType.SETTINGS -> {
                    if (frame.hasFlag(Http2FrameFlags.ACK)) continue // Server ACK'd our SETTINGS
                    handleServerSettings(frame)
                    sendFrame(Http2Framer.settingsAckFrame())

                    if (state == State.PREFACE_SENT) {
                        state = State.READY
                        sendConnectRequest()
                        // Continue processing — response may already be buffered
                        continue
                    }
                }

                Http2FrameType.HEADERS -> {
                    if (state == State.TUNNEL_PENDING && frame.streamID == 1) {
                        handleConnectResponse(frame)
                        return
                    }
                }

                Http2FrameType.WINDOW_UPDATE -> {
                    Http2Framer.parseWindowUpdate(frame.payload)?.let { inc ->
                        flowControl.applyWindowUpdate(frame.streamID, inc)
                    }
                }

                Http2FrameType.PING -> {
                    if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                        sendFrame(Http2Framer.pingAckFrame(frame.payload))
                    }
                }

                Http2FrameType.GOAWAY -> {
                    state = State.CLOSED
                    val parsed = Http2Framer.parseGoaway(frame.payload)
                    if (parsed != null) {
                        Log.w(TAG, "GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")
                    }
                    throw Http2Error.Goaway()
                }

                Http2FrameType.RST_STREAM -> {
                    if (frame.streamID == 1 && state == State.TUNNEL_PENDING) {
                        state = State.CLOSED
                        val errorCode = Http2Framer.parseRstStream(frame.payload)
                        if (errorCode != null) {
                            Log.e(TAG, "Stream 1 reset during CONNECT: errorCode=$errorCode")
                        }
                        throw Http2Error.StreamReset(frame.streamID)
                    }
                }

                else -> {} // Skip unknown frame types (RFC 7540 §4.1)
            }
        }
    }

    // -- CONNECT Request --

    /** Sends the HTTP/2 CONNECT request on stream 1 with padding negotiation headers. */
    private suspend fun sendConnectRequest() {
        val extraHeaders = mutableListOf<Pair<String, String>>()

        // Proxy-Authorization (Basic auth)
        configuration.basicAuth?.let { auth ->
            extraHeaders.add("proxy-authorization" to "Basic $auth")
        }

        // User-Agent (required by some NaiveProxy servers for probe resistance)
        extraHeaders.add("user-agent" to USER_AGENT)

        // Padding negotiation headers
        extraHeaders.addAll(NaivePaddingNegotiator.requestHeaders())

        val headerBlock = HpackEncoder.encodeConnectRequest(
            authority = destination,
            extraHeaders = extraHeaders
        )
        val headersFrame = Http2Framer.headersFrame(
            streamID = 1,
            headerBlock = headerBlock,
            endStream = false
        )

        state = State.TUNNEL_PENDING
        transport.send(Http2Framer.serialize(headersFrame))
    }

    // -- CONNECT Response --

    /** Handles the server's CONNECT response HEADERS frame. */
    private fun handleConnectResponse(frame: Http2Frame) {
        val headers = HpackEncoder.decodeHeaders(frame.payload)
        if (headers == null) {
            state = State.CLOSED
            throw Http2Error.ProtocolError("Failed to decode CONNECT response headers")
        }

        val statusHeader = headers.firstOrNull { it.first == ":status" }
        if (statusHeader == null) {
            state = State.CLOSED
            throw Http2Error.ProtocolError("Missing :status in CONNECT response")
        }

        val status = statusHeader.second
        when (status) {
            "200" -> {
                negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers)
                state = State.TUNNEL_OPEN
            }
            "407" -> {
                state = State.CLOSED
                Log.e(TAG, "Proxy authentication required (407)")
                throw Http2Error.AuthenticationRequired()
            }
            else -> {
                state = State.CLOSED
                Log.e(TAG, "CONNECT failed with status $status")
                throw Http2Error.TunnelFailed(status)
            }
        }
    }

    // -- Server Settings --

    /** Processes a SETTINGS frame from the server, applying relevant parameters. */
    private fun handleServerSettings(frame: Http2Frame) {
        val settings = Http2Framer.parseSettings(frame.payload)
        for ((id, value) in settings) {
            when (id) {
                0x4 -> // SETTINGS_INITIAL_WINDOW_SIZE
                    flowControl.applySettings(value)
            }
        }
    }

    // -- Data Frame Send --

    /**
     * Sends data as one or more HTTP/2 DATA frames on stream 1.
     *
     * Splits at SETTINGS_MAX_FRAME_SIZE (16,384 bytes) and respects flow control.
     */
    private suspend fun sendDataFrames(data: ByteArray, offset: Int) {
        if (offset >= data.size) return

        val maxPayload = Http2Framer.MAX_DATA_PAYLOAD
        var currentOffset = offset
        val framesBuf = java.io.ByteArrayOutputStream()

        while (currentOffset < data.size) {
            val remaining = data.size - currentOffset
            val chunkSize = minOf(remaining, minOf(maxPayload, flowControl.maxSendBytes))
            if (chunkSize <= 0) break
            if (!flowControl.consumeSendWindow(chunkSize)) break

            val chunk = data.copyOfRange(currentOffset, currentOffset + chunkSize)
            val frame = Http2Framer.dataFrame(streamID = 1, payload = chunk)
            framesBuf.write(Http2Framer.serialize(frame))
            currentOffset += chunkSize
        }

        if (framesBuf.size() == 0) {
            Log.w(TAG, "Send blocked by flow control")
            throw Http2Error.ProtocolError("Flow control blocked")
        }

        transport.send(framesBuf.toByteArray())

        if (currentOffset < data.size) {
            sendDataFrames(data, currentOffset)
        }
    }

    // -- Data Frame Receive --

    /**
     * Reads HTTP/2 frames until a DATA frame for stream 1 is found.
     *
     * Control frames (PING, WINDOW_UPDATE, SETTINGS) are handled transparently.
     * GOAWAY and RST_STREAM terminate the connection.
     */
    private suspend fun readNextDataFrame(): ByteArray? {
        while (true) {
            val frame = Http2Framer.deserialize(receiveBuffer)
            if (frame == null) {
                // Need more data from transport
                readFromTransport()
                continue
            }

            when (frame.type) {
                Http2FrameType.DATA -> {
                    if (frame.streamID != 1) continue

                    // Flow control: track received bytes and send WINDOW_UPDATE when needed
                    if (frame.payload.isNotEmpty()) {
                        val increments = flowControl.consumeRecvWindow(frame.payload.size)
                        increments.connectionIncrement?.let { connInc ->
                            sendFrame(Http2Framer.windowUpdateFrame(streamID = 0, increment = connInc))
                        }
                        increments.streamIncrement?.let { streamInc ->
                            sendFrame(Http2Framer.windowUpdateFrame(streamID = 1, increment = streamInc))
                        }
                    }

                    if (frame.hasFlag(Http2FrameFlags.END_STREAM)) {
                        state = State.CLOSED
                        return if (frame.payload.isNotEmpty()) frame.payload else null
                    }

                    if (frame.payload.isNotEmpty()) {
                        return frame.payload
                    }
                    // Empty DATA frame (no END_STREAM) — keep reading
                }

                Http2FrameType.PING -> {
                    if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                        sendFrame(Http2Framer.pingAckFrame(frame.payload))
                    }
                }

                Http2FrameType.WINDOW_UPDATE -> {
                    Http2Framer.parseWindowUpdate(frame.payload)?.let { inc ->
                        flowControl.applyWindowUpdate(frame.streamID, inc)
                    }
                }

                Http2FrameType.SETTINGS -> {
                    if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                        handleServerSettings(frame)
                        sendFrame(Http2Framer.settingsAckFrame())
                    }
                }

                Http2FrameType.GOAWAY -> {
                    state = State.CLOSED
                    val parsed = Http2Framer.parseGoaway(frame.payload)
                    if (parsed != null) {
                        Log.w(TAG, "GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")
                    }
                    throw Http2Error.Goaway()
                }

                Http2FrameType.RST_STREAM -> {
                    if (frame.streamID == 1) {
                        state = State.CLOSED
                        throw Http2Error.StreamReset(frame.streamID)
                    }
                }

                else -> {} // Skip unknown frame types (RFC 7540 §4.1)
            }
        }
    }

    // -- Transport I/O --

    /** Reads data from the transport and appends to the receive buffer. */
    private suspend fun readFromTransport() {
        val data = transport.receive()
        if (data == null || data.isEmpty()) {
            throw Http2Error.ConnectionFailed("Connection closed")
        }
        receiveBuffer.append(data)
        if (receiveBuffer.available > MAX_RECEIVE_BUFFER_SIZE) {
            receiveBuffer.clear()
            state = State.CLOSED
            transport.cancel()
            throw Http2Error.ConnectionFailed("Receive buffer exceeded $MAX_RECEIVE_BUFFER_SIZE bytes")
        }
    }

    /** Sends a single control frame (fire-and-forget). */
    private suspend fun sendFrame(frame: Http2Frame) {
        try {
            transport.send(Http2Framer.serialize(frame))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to send frame: ${e.message}")
        }
    }
}
