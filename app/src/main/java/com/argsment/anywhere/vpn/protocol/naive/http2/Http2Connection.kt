package com.argsment.anywhere.vpn.protocol.naive.http2

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTlsTransport
import java.io.IOException

private val logger = AnywhereLogger("HTTP2")

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
 * HTTP/2 connection that opens a single CONNECT tunnel on stream 1 through a NaiveProxy
 * server. Flow control uses NaiveProxy's window sizes (64 MB stream, 128 MB connection).
 */
class Http2Connection(
    private val transport: NaiveTlsTransport,
    private val configuration: NaiveConfiguration,
    /** The target `host:port` for the CONNECT tunnel. */
    private val destination: String
) {
    companion object {
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

        /** RFC 7540 §3.5 connection preface. */
        private val CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

        /** Cap on receive buffer growth (2 MB). */
        private const val MAX_RECEIVE_BUFFER_SIZE = 2_097_152
    }

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

    var negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE
        private set

    val isConnected: Boolean get() = state == State.TUNNEL_OPEN

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

    suspend fun sendData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        sendDataFrames(data, 0)
    }

    suspend fun receiveData(): ByteArray? {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        return readNextDataFrame()
    }

    fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Connection closed"))
        transport.cancel()
    }

    private suspend fun sendConnectionPreface() {
        val buf = java.io.ByteArrayOutputStream()
        buf.write(CONNECTION_PREFACE)

        val settings = Http2Framer.settingsFrame(listOf(
            0x1 to 65536,     // HEADER_TABLE_SIZE
            0x2 to 0,         // ENABLE_PUSH (disabled for CONNECT)
            0x3 to 100,       // MAX_CONCURRENT_STREAMS
            0x4 to Http2FlowControl.NAIVE_INITIAL_WINDOW_SIZE, // INITIAL_WINDOW_SIZE = 64 MB
            0x5 to 16384,     // MAX_FRAME_SIZE
            0x6 to 262144,    // MAX_HEADER_LIST_SIZE
        ))
        buf.write(Http2Framer.serialize(settings))

        // Expand connection receive window from default 65,535 to 128 MB.
        val windowUpdate = Http2Framer.windowUpdateFrame(
            streamID = 0,
            increment = Http2FlowControl.CONNECTION_WINDOW_UPDATE_INCREMENT
        )
        buf.write(Http2Framer.serialize(windowUpdate))

        transport.send(buf.toByteArray())
        state = State.PREFACE_SENT
    }

    private suspend fun processHandshake() {
        while (true) {
            val frame = Http2Framer.deserialize(receiveBuffer)
            if (frame == null) {
                readFromTransport()
                continue
            }

            when (frame.type) {
                Http2FrameType.SETTINGS -> {
                    if (frame.hasFlag(Http2FrameFlags.ACK)) continue
                    handleServerSettings(frame)
                    sendFrame(Http2Framer.settingsAckFrame())

                    if (state == State.PREFACE_SENT) {
                        state = State.READY
                        sendConnectRequest()
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
                        logger.warning("GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")
                    }
                    throw Http2Error.Goaway()
                }

                Http2FrameType.RST_STREAM -> {
                    if (frame.streamID == 1 && state == State.TUNNEL_PENDING) {
                        state = State.CLOSED
                        val errorCode = Http2Framer.parseRstStream(frame.payload)
                        if (errorCode != null) {
                            logger.error("Stream 1 reset during CONNECT: errorCode=$errorCode")
                        }
                        throw Http2Error.StreamReset(frame.streamID)
                    }
                }

                else -> {} // Unknown frame types skipped per RFC 7540 §4.1
            }
        }
    }

    private suspend fun sendConnectRequest() {
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
            streamID = 1,
            headerBlock = headerBlock,
            endStream = false
        )

        state = State.TUNNEL_PENDING
        transport.send(Http2Framer.serialize(headersFrame))
    }

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
                logger.error("Proxy authentication required (407)")
                throw Http2Error.AuthenticationRequired()
            }
            else -> {
                state = State.CLOSED
                logger.error("CONNECT failed with status $status")
                throw Http2Error.TunnelFailed(status)
            }
        }
    }

    private fun handleServerSettings(frame: Http2Frame) {
        val settings = Http2Framer.parseSettings(frame.payload)
        for ((id, value) in settings) {
            when (id) {
                0x4 -> // SETTINGS_INITIAL_WINDOW_SIZE
                    flowControl.applySettings(value)
            }
        }
    }

    /** Splits data at SETTINGS_MAX_FRAME_SIZE (16,384 bytes) and respects flow control. */
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
            // Flow control blocked. Suspend until WINDOW_UPDATE arrives instead
            // of throwing — mirrors iOS HTTP2Connection.swift:427-433.
            if (state == State.CLOSED) throw Http2Error.ConnectionFailed("Connection closed")
            flowControl.awaitWindow()
            sendDataFrames(data, currentOffset)
            return
        }

        transport.send(framesBuf.toByteArray())

        if (currentOffset < data.size) {
            sendDataFrames(data, currentOffset)
        }
    }

    /** Reads frames until a DATA frame for stream 1 arrives, handling control frames inline. */
    private suspend fun readNextDataFrame(): ByteArray? {
        while (true) {
            val frame = Http2Framer.deserialize(receiveBuffer)
            if (frame == null) {
                readFromTransport()
                continue
            }

            when (frame.type) {
                Http2FrameType.DATA -> {
                    if (frame.streamID != 1) continue

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
                        logger.warning("GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")
                    }
                    throw Http2Error.Goaway()
                }

                Http2FrameType.RST_STREAM -> {
                    if (frame.streamID == 1) {
                        state = State.CLOSED
                        throw Http2Error.StreamReset(frame.streamID)
                    }
                }

                else -> {} // Unknown frame types skipped per RFC 7540 §4.1
            }
        }
    }

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

    private suspend fun sendFrame(frame: Http2Frame) {
        try {
            transport.send(Http2Framer.serialize(frame))
        } catch (e: Exception) {
            logger.warning("Failed to send frame: ${e.message}")
        }
    }
}
