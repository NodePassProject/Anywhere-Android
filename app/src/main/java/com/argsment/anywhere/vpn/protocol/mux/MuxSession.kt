package com.argsment.anywhere.vpn.protocol.mux

import android.util.Log
import com.argsment.anywhere.data.model.ProxyError

private const val TAG = "MuxSession"

/**
 * Individual mux session with send (Keep frame) and close (End frame).
 * Data/close delivery from demuxer.
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

    /** Called by MuxClient when demuxed data arrives for this session. */
    var dataHandler: ((ByteArray) -> Unit)? = null

    /** Called by MuxClient when the session is closed (End frame received or connection error). */
    var closeHandler: (() -> Unit)? = null

    // For XUDP: the first send must include a New frame with the data payload and GlobalID.
    // Matching iOS behavior which defers the New frame until first data arrives.
    private var firstFrameSent: Boolean = (globalID == null)

    /**
     * Sends data through the mux connection as a Keep frame with payload.
     * For XUDP, the first call sends a New frame with the data and GlobalID.
     */
    suspend fun send(data: ByteArray) {
        if (closed) throw ProxyError.ConnectionFailed("Mux session closed")

        val frame = if (!firstFrameSent) {
            firstFrameSent = true
            encodeNewFrameWithData(data)
        } else {
            encodeKeepFrame(data)
        }
        client.writeFrame(frame)
    }

    /**
     * Non-suspending send that checks closed synchronously and enqueues the write.
     * Matches the iOS callback-based send pattern: the closed check and frame encoding
     * happen on the calling thread (lwipExecutor), preventing races with closeAll().
     * Used for buffered payloads during initial connection setup.
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

    /**
     * Encodes a New frame with data payload and GlobalID for XUDP first-frame deferral.
     */
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
        // For UDP Keep frames, include address (matching Xray-core writer.go)
        if (network == MuxNetwork.UDP) {
            metadata = metadata.copy(
                network = network,
                targetHost = targetHost,
                targetPort = targetPort
            )
        }
        return encodeMuxFrame(metadata = metadata, payload = data)
    }

    /**
     * Closes this session by sending an End frame.
     */
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

    // =========================================================================
    // Called by MuxClient (demux)
    // =========================================================================

    /**
     * Delivers demuxed data to this session.
     */
    fun deliverData(data: ByteArray) {
        if (closed) return
        dataHandler?.invoke(data)
    }

    /**
     * Delivers a close event to this session.
     */
    fun deliverClose() {
        if (closed) return
        closed = true
        closeHandler?.invoke()
    }
}
