package com.argsment.anywhere.vpn.protocol.naive.http2

/**
 * Tracks HTTP/2 send and receive flow-control windows for a single connection + stream.
 *
 * Window sizing matches NaiveProxy's bandwidth-delay product calculation:
 * - `kMaxBandwidthMBps = 125`, `kTypicalRttSecond = 0.256`
 * - `kMaxBdpMB = 32 MB`, `kTypicalWindow = 64 MB` (2× BDP)
 * - Session max receive window = 128 MB (2× stream window)
 */
class Http2FlowControl {

    companion object {
        /** HTTP/2 default initial window size (RFC 7540 §6.9.2). */
        const val DEFAULT_INITIAL_WINDOW_SIZE = 65_535

        /** NaiveProxy's stream initial window size (64 MB). */
        const val NAIVE_INITIAL_WINDOW_SIZE = 67_108_864

        /** NaiveProxy's session (connection) max receive window (128 MB). */
        const val NAIVE_SESSION_MAX_RECV_WINDOW = 134_217_728

        /** WINDOW_UPDATE increment to send on stream 0 after SETTINGS exchange.
         * Expands connection receive window from 65,535 to 128 MB. */
        val CONNECTION_WINDOW_UPDATE_INCREMENT: Int =
            NAIVE_SESSION_MAX_RECV_WINDOW - DEFAULT_INITIAL_WINDOW_SIZE
    }

    // -- Send Windows (limited by remote peer's settings) --

    /** How many bytes we can send on the connection. */
    var connectionSendWindow: Int = DEFAULT_INITIAL_WINDOW_SIZE
        private set

    /** How many bytes we can send on stream 1. */
    var streamSendWindow: Int = DEFAULT_INITIAL_WINDOW_SIZE
        private set

    // -- Receive Windows (limited by our settings) --

    /** Bytes received but not yet acknowledged via WINDOW_UPDATE (connection level). */
    private var connectionRecvConsumed: Int = 0

    /** Bytes received but not yet acknowledged via WINDOW_UPDATE (stream level). */
    private var streamRecvConsumed: Int = 0

    /** The receive window size we advertised for streams. */
    private var streamRecvWindowSize: Int = NAIVE_INITIAL_WINDOW_SIZE

    /** The receive window size for the connection (after our WINDOW_UPDATE). */
    private var connectionRecvWindowSize: Int = NAIVE_SESSION_MAX_RECV_WINDOW

    // -- Send --

    /**
     * Checks if we can send [bytes] and consumes from both connection and stream send windows.
     *
     * Returns true if the send is allowed; false if it would exceed a window.
     */
    fun consumeSendWindow(bytes: Int): Boolean {
        if (connectionSendWindow < bytes || streamSendWindow < bytes) return false
        connectionSendWindow -= bytes
        streamSendWindow -= bytes
        return true
    }

    /** Returns the maximum number of bytes we can send right now. */
    val maxSendBytes: Int get() = minOf(connectionSendWindow, streamSendWindow)

    // -- Receive --

    /**
     * Records that [bytes] of DATA have been received.
     *
     * Returns WINDOW_UPDATE increments to send: (connectionIncrement, streamIncrement).
     * Either may be null if no update is needed yet.
     */
    fun consumeRecvWindow(bytes: Int): RecvWindowResult {
        connectionRecvConsumed += bytes
        streamRecvConsumed += bytes

        var connInc: Int? = null
        var streamInc: Int? = null

        // Send WINDOW_UPDATE when >= 50% of window has been consumed
        if (connectionRecvConsumed >= connectionRecvWindowSize / 2) {
            connInc = connectionRecvConsumed
            connectionRecvConsumed = 0
        }
        if (streamRecvConsumed >= streamRecvWindowSize / 2) {
            streamInc = streamRecvConsumed
            streamRecvConsumed = 0
        }

        return RecvWindowResult(connInc, streamInc)
    }

    data class RecvWindowResult(
        val connectionIncrement: Int?,
        val streamIncrement: Int?
    )

    // -- Remote Updates --

    /** Applies a WINDOW_UPDATE received from the server. */
    fun applyWindowUpdate(streamID: Int, increment: Int) {
        if (streamID == 0) {
            connectionSendWindow += increment
        } else {
            streamSendWindow += increment
        }
    }

    /**
     * Applies the server's SETTINGS_INITIAL_WINDOW_SIZE.
     *
     * Adjusts our stream send window by the difference between the new and old values
     * (RFC 7540 §6.9.2).
     */
    fun applySettings(initialWindowSize: Int) {
        val delta = initialWindowSize - DEFAULT_INITIAL_WINDOW_SIZE
        streamSendWindow += delta
    }
}
