package com.argsment.anywhere.vpn.protocol.naive.http2

/**
 * Per-stream HTTP/2 flow control. Issues WINDOW_UPDATE at 50% of the 64 MB receive window.
 */
class Http2StreamFlowControl(initialSendWindow: Int = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE) {

    var sendWindow: Int = initialSendWindow
        private set

    private var recvConsumed: Int = 0
    private val recvWindowSize: Int = Http2FlowControl.NAIVE_INITIAL_WINDOW_SIZE

    private val windowLock = Any()
    private var windowAwaiter: kotlinx.coroutines.CompletableDeferred<Unit>? = null

    fun consumeSend(bytes: Int): Boolean {
        if (sendWindow < bytes) return false
        sendWindow -= bytes
        return true
    }

    fun applyWindowUpdate(increment: Int) {
        synchronized(windowLock) {
            sendWindow += increment
            windowAwaiter?.complete(Unit)
            windowAwaiter = null
        }
    }

    /**
     * Suspends until the send window opens (WINDOW_UPDATE arrives or stream closes).
     * Mirrors iOS HTTP2Session's flow-control wait pattern.
     */
    suspend fun awaitWindow() {
        val awaiter = synchronized(windowLock) {
            if (sendWindow > 0) return
            windowAwaiter ?: kotlinx.coroutines.CompletableDeferred<Unit>().also {
                windowAwaiter = it
            }
        }
        awaiter.await()
    }

    /** Wakes any sender suspended on [awaitWindow] with the given exception. */
    fun cancelAwaiters(error: Throwable) {
        synchronized(windowLock) {
            windowAwaiter?.completeExceptionally(error)
            windowAwaiter = null
        }
    }

    /** RFC 7540 §6.9.2: adjust send window by delta when SETTINGS_INITIAL_WINDOW_SIZE changes. */
    fun adjustSendWindow(delta: Int) {
        synchronized(windowLock) {
            sendWindow += delta
            if (sendWindow > 0) {
                windowAwaiter?.complete(Unit)
                windowAwaiter = null
            }
        }
    }

    /** Returns WINDOW_UPDATE increment when half the receive window has been consumed. */
    fun consumeRecv(bytes: Int): Int? {
        recvConsumed += bytes
        if (recvConsumed >= recvWindowSize / 2) {
            val increment = recvConsumed
            recvConsumed = 0
            return increment
        }
        return null
    }
}

/**
 * HTTP/2 connection + stream flow control. Window sizing follows NaiveProxy's BDP
 * calculation: 64 MB stream window, 128 MB connection window.
 */
class Http2FlowControl {

    companion object {
        /** RFC 7540 §6.9.2 default. */
        const val DEFAULT_INITIAL_WINDOW_SIZE = 65_535

        const val NAIVE_INITIAL_WINDOW_SIZE = 67_108_864
        const val NAIVE_SESSION_MAX_RECV_WINDOW = 134_217_728

        /** Increment for the post-SETTINGS WINDOW_UPDATE on stream 0 (raises 65,535 → 128 MB). */
        val CONNECTION_WINDOW_UPDATE_INCREMENT: Int =
            NAIVE_SESSION_MAX_RECV_WINDOW - DEFAULT_INITIAL_WINDOW_SIZE
    }

    var connectionSendWindow: Int = DEFAULT_INITIAL_WINDOW_SIZE
        private set

    var streamSendWindow: Int = DEFAULT_INITIAL_WINDOW_SIZE
        private set

    private var connectionRecvConsumed: Int = 0
    private var streamRecvConsumed: Int = 0
    private var streamRecvWindowSize: Int = NAIVE_INITIAL_WINDOW_SIZE
    private var connectionRecvWindowSize: Int = NAIVE_SESSION_MAX_RECV_WINDOW

    fun consumeSendWindow(bytes: Int): Boolean {
        if (connectionSendWindow < bytes || streamSendWindow < bytes) return false
        connectionSendWindow -= bytes
        streamSendWindow -= bytes
        return true
    }

    val maxSendBytes: Int get() = minOf(connectionSendWindow, streamSendWindow)

    /** Returns WINDOW_UPDATE increments (connection, stream); either may be null if not yet due. */
    fun consumeRecvWindow(bytes: Int): RecvWindowResult {
        connectionRecvConsumed += bytes
        streamRecvConsumed += bytes

        var connInc: Int? = null
        var streamInc: Int? = null

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

    private val windowLock = Any()
    private var windowAwaiter: kotlinx.coroutines.CompletableDeferred<Unit>? = null

    fun applyWindowUpdate(streamID: Int, increment: Int) {
        synchronized(windowLock) {
            if (streamID == 0) {
                connectionSendWindow += increment
            } else {
                streamSendWindow += increment
            }
            if (maxSendBytes > 0) {
                windowAwaiter?.complete(Unit)
                windowAwaiter = null
            }
        }
    }

    /** Suspends until both connection and stream send windows have headroom. */
    suspend fun awaitWindow() {
        val awaiter = synchronized(windowLock) {
            if (maxSendBytes > 0) return
            windowAwaiter ?: kotlinx.coroutines.CompletableDeferred<Unit>().also {
                windowAwaiter = it
            }
        }
        awaiter.await()
    }

    fun cancelAwaiters(error: Throwable) {
        synchronized(windowLock) {
            windowAwaiter?.completeExceptionally(error)
            windowAwaiter = null
        }
    }

    /** RFC 7540 §6.9.2: shifts stream send window by delta from default. */
    fun applySettings(initialWindowSize: Int) {
        synchronized(windowLock) {
            val delta = initialWindowSize - DEFAULT_INITIAL_WINDOW_SIZE
            streamSendWindow += delta
            if (maxSendBytes > 0) {
                windowAwaiter?.complete(Unit)
                windowAwaiter = null
            }
        }
    }
}
