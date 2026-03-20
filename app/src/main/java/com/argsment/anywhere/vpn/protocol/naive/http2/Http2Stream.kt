package com.argsment.anywhere.vpn.protocol.naive.http2

import android.util.Log
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTunnel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel

private const val TAG = "Http2Stream"

/**
 * A single HTTP/2 CONNECT tunnel stream, multiplexed on an [Http2Session].
 *
 * Implements [NaiveTunnel] so it can be used directly by [NaiveProxyConnection]
 * without an [Http2Tunnel] wrapper.
 *
 * Lifecycle: IDLE → TUNNEL_PENDING → TUNNEL_OPEN → CLOSED
 */
class Http2Stream(
    val streamID: Int,
    private val session: Http2Session,
    private val destination: String
) : NaiveTunnel {

    enum class State { IDLE, TUNNEL_PENDING, TUNNEL_OPEN, CLOSED }

    @Volatile
    private var state = State.IDLE

    /** Per-stream flow control (send window + receive tracking). */
    val flowControl = Http2StreamFlowControl(session.serverInitialWindowSize)

    /** Data channel — session's read loop sends DATA payloads here. */
    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /** Completes when the CONNECT response arrives. */
    private val tunnelReady = CompletableDeferred<Unit>()

    override var negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE
        private set

    override val isConnected: Boolean get() = state == State.TUNNEL_OPEN

    // -- Tunnel Lifecycle --

    /**
     * Opens a CONNECT tunnel on this stream.
     * Sends the CONNECT request via the session, then suspends until the server responds.
     */
    override suspend fun openTunnel() {
        if (state != State.IDLE) throw Http2Error.ProtocolError("Stream $streamID: invalid state for openTunnel")
        state = State.TUNNEL_PENDING

        try {
            session.sendConnectRequest(streamID, destination)
            tunnelReady.await()
        } catch (e: Exception) {
            state = State.CLOSED
            session.removeStream(streamID)
            throw e
        }
    }

    // -- Data Transfer --

    override suspend fun sendData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        session.sendData(streamID, data, flowControl)
    }

    override suspend fun receiveData(): ByteArray? {
        if (state == State.CLOSED) return null
        return try {
            dataChannel.receive()
        } catch (e: Exception) {
            null
        }
    }

    override fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        dataChannel.close()
        session.removeStream(streamID)
    }

    // -- Session Callbacks (called from session's read loop) --

    /**
     * Delivers a HEADERS frame (CONNECT response) to this stream.
     * Completes [tunnelReady] on 200, or fails it on error status.
     */
    fun deliverHeaders(headers: List<Pair<String, String>>) {
        val statusHeader = headers.firstOrNull { it.first == ":status" }
        if (statusHeader == null) {
            state = State.CLOSED
            tunnelReady.completeExceptionally(
                Http2Error.ProtocolError("Stream $streamID: missing :status")
            )
            return
        }

        when (statusHeader.second) {
            "200" -> {
                negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers)
                state = State.TUNNEL_OPEN
                tunnelReady.complete(Unit)
            }
            "407" -> {
                state = State.CLOSED
                tunnelReady.completeExceptionally(Http2Error.AuthenticationRequired())
            }
            else -> {
                state = State.CLOSED
                tunnelReady.completeExceptionally(Http2Error.TunnelFailed(statusHeader.second))
            }
        }
    }

    /** Delivers a DATA payload to this stream's data channel. */
    fun deliverData(data: ByteArray) {
        if (state == State.CLOSED) return
        dataChannel.trySend(data)
    }

    /** Applies a WINDOW_UPDATE for this stream. */
    fun deliverWindowUpdate(increment: Int) {
        flowControl.applyWindowUpdate(increment)
    }

    /** Handles RST_STREAM for this stream. */
    fun deliverReset() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()

        if (!wasOpen) {
            tunnelReady.completeExceptionally(Http2Error.StreamReset(streamID))
        }
    }

    /** Handles GOAWAY affecting this stream. */
    fun deliverGoaway() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()

        if (!wasOpen) {
            tunnelReady.completeExceptionally(Http2Error.Goaway())
        }
    }

    /** Handles a transport-level error. */
    fun deliverError(error: Exception) {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()

        if (!wasOpen) {
            tunnelReady.completeExceptionally(error)
        }
    }

    /** Adjusts the send window when SETTINGS_INITIAL_WINDOW_SIZE changes (RFC 7540 §6.9.2). */
    fun adjustSendWindow(delta: Int) {
        flowControl.adjustSendWindow(delta)
    }
}
