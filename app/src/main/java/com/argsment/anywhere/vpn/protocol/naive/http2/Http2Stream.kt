package com.argsment.anywhere.vpn.protocol.naive.http2

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTunnel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel

private val logger = AnywhereLogger("HTTP2Stream")

/**
 * A single HTTP/2 CONNECT tunnel stream multiplexed on an [Http2Session].
 * Lifecycle: IDLE → TUNNEL_PENDING → TUNNEL_OPEN → CLOSED.
 */
class Http2Stream(
    val streamID: Int,
    private val session: Http2Session,
    private val destination: String
) : NaiveTunnel {

    enum class State { IDLE, TUNNEL_PENDING, TUNNEL_OPEN, CLOSED }

    @Volatile
    private var state = State.IDLE

    val flowControl = Http2StreamFlowControl(session.serverInitialWindowSize)

    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    private val tunnelReady = CompletableDeferred<Unit>()

    override var negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE
        private set

    override val isConnected: Boolean get() = state == State.TUNNEL_OPEN

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

    override suspend fun sendData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        session.sendData(streamID, data, flowControl)
    }

    override suspend fun receiveData(): ByteArray? {
        if (state == State.CLOSED) return null
        val data = try {
            dataChannel.receive()
        } catch (e: Exception) {
            return null
        }
        // Defer WINDOW_UPDATE to consume time so back-pressure is preserved
        // through the channel — mirrors iOS HTTP2Stream.acknowledgeConsumedData.
        if (data.isNotEmpty()) {
            session.acknowledgeConsumedData(streamID, data.size)
        }
        return data
    }

    override fun close() {
        if (state == State.CLOSED) return
        val priorState = state
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Stream closed"))
        // Send RST_STREAM(CANCEL) so the server reclaims the slot when we
        // close while the stream is still open. Mirrors iOS HTTP2Stream.close
        // (HTTP2Stream.swift:160-184).
        if (priorState == State.TUNNEL_PENDING || priorState == State.TUNNEL_OPEN) {
            session.sendReset(streamID, Http2Framer.ErrorCode.CANCEL)
        }
        session.removeStream(streamID)
    }

    /** Completes [tunnelReady] on a 200 CONNECT response, fails it on error status. */
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

    fun deliverData(data: ByteArray) {
        if (state == State.CLOSED) return
        dataChannel.trySend(data)
    }

    fun deliverWindowUpdate(increment: Int) {
        flowControl.applyWindowUpdate(increment)
    }

    fun deliverReset() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.StreamReset(streamID))

        if (!wasOpen) {
            tunnelReady.completeExceptionally(Http2Error.StreamReset(streamID))
        }
    }

    /** Server END_STREAM = clean half-close. Closes data channel without throwing. */
    fun deliverEndStream() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Stream END_STREAM"))
    }

    fun deliverGoaway() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.Goaway())

        if (!wasOpen) {
            tunnelReady.completeExceptionally(Http2Error.Goaway())
        }
    }

    fun deliverError(error: Exception) {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(error)

        if (!wasOpen) {
            tunnelReady.completeExceptionally(error)
        }
    }

    /** RFC 7540 §6.9.2: adjusts send window when SETTINGS_INITIAL_WINDOW_SIZE changes. */
    fun adjustSendWindow(delta: Int) {
        flowControl.adjustSendWindow(delta)
    }
}
