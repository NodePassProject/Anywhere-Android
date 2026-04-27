package com.argsment.anywhere.vpn.protocol.mux

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.ProxyError

private val logger = AnywhereLogger("MuxSession")

/**
 * Individual mux session: send (Keep frame), close (End frame), and demuxer
 * delivery callbacks.
 */
class MuxSession(
    val sessionID: Int,           // UInt16 range
    val network: MuxNetwork,
    val targetHost: String,
    val targetPort: Int,          // UInt16 range
    private val client: MuxClient,
    private val globalID: ByteArray? = null
) {
    @Volatile
    var closed: Boolean = false
        private set

    var dataHandler: ((ByteArray) -> Unit)? = null

    var closeHandler: (() -> Unit)? = null

    // For XUDP, the first send must include a New frame with the data payload
    // and GlobalID — defer the New frame until first data arrives.
    private var firstFrameSent: Boolean = (globalID == null)

    /**
     * Sends data through the mux connection as a Keep frame with payload.
     * For XUDP, the first call sends a New frame with the data and GlobalID.
     */
    suspend fun send(data: ByteArray) {
        if (closed) throw ProxyError.ConnectionFailed("Mux session closed")

        val isFirst = !firstFrameSent
        val frame = if (isFirst) {
            firstFrameSent = true
            encodeNewFrameWithData(data)
        } else {
            encodeKeepFrame(data)
        }
        try {
            client.writeFrame(frame)
        } catch (e: Exception) {
            // Reset firstFrameSent on failure so retry sends New frame.
            if (isFirst) firstFrameSent = false
            throw e
        }
    }

    /**
     * Non-suspending send: the closed check and frame encoding happen on the
     * calling thread (lwipExecutor) to prevent races with closeAll(). Used for
     * buffered payloads during initial connection setup.
     */
    fun sendAsync(data: ByteArray) {
        if (closed) return

        val frame = if (!firstFrameSent) {
            firstFrameSent = true
            encodeNewFrameWithData(data)
        } else {
            encodeKeepFrame(data)
        }
        client.writeFrameAsync(frame)
    }

    private fun encodeNewFrameWithData(data: ByteArray): ByteArray {
        val metadata = MuxFrameMetadata(
            sessionID = sessionID,
            status = MuxSessionStatus.NEW,
            option = MuxOption.DATA,
            network = network,
            targetHost = targetHost,
            targetPort = targetPort,
            globalID = globalID
        )
        return encodeMuxFrame(metadata = metadata, payload = data)
    }

    private fun encodeKeepFrame(data: ByteArray): ByteArray {
        var metadata = MuxFrameMetadata(
            sessionID = sessionID,
            status = MuxSessionStatus.KEEP,
            option = MuxOption.DATA
        )
        // UDP Keep frames carry the address.
        if (network == MuxNetwork.UDP) {
            metadata = metadata.copy(
                network = network,
                targetHost = targetHost,
                targetPort = targetPort
            )
        }
        return encodeMuxFrame(metadata = metadata, payload = data)
    }

    /** Closes this session by sending an End frame. */
    fun close() {
        if (closed) return
        closed = true

        val metadata = MuxFrameMetadata(
            sessionID = sessionID,
            status = MuxSessionStatus.END,
            option = 0
        )
        val frame = encodeMuxFrame(metadata = metadata, payload = null)
        client.writeFrameAsync(frame)
        client.removeSession(sessionID)

        closeHandler?.invoke()
    }

    fun deliverData(data: ByteArray) {
        if (closed) return
        dataHandler?.invoke(data)
    }

    /**
     * Delivers a server-initiated close to this session. The server already
     * sent the End frame, and `MuxClient.handleReceivedData` removed the
     * session from its map before invoking this — there is no peer to ack to.
     * Mirrors iOS MuxSession.swift:117-121.
     */
    fun deliverClose() {
        if (closed) return
        closed = true
        closeHandler?.invoke()
    }
}
