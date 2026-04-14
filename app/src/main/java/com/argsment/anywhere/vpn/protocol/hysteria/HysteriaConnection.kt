package com.argsment.anywhere.vpn.protocol.hysteria

import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.trySendBlocking
import java.io.ByteArrayOutputStream

private val logger = AnywhereLogger("Hysteria-Conn")

/**
 * One Hysteria v2 TCP request stream. Direct port of iOS
 * `HysteriaConnection.swift`, adapted to Android's [VlessConnection]
 * coroutine API.
 *
 * Owns one bidi QUIC stream opened from [HysteriaSession]; sends a single
 * TCP request frame at open time, parses the leading TCP response, and then
 * forwards raw payload bytes between the proxy stream and the local app.
 */
class HysteriaConnection(
    private val session: HysteriaSession,
    private val destination: String
) : VlessConnection() {

    enum class State { IDLE, OPENING, HANDSHAKING, READY, CLOSED }

    @Volatile private var state: State = State.IDLE
    @Volatile private var streamId: Long = -1L

    /** Buffer holding raw stream bytes we haven't yet parsed or delivered. */
    private val receiveBuffer = ByteArrayOutputStream()
    @Volatile private var responseParsed = false

    /** One-element-at-a-time channel feeding waiting [receiveRaw] callers. */
    private val receiveChannel = Channel<ByteArray?>(capacity = Channel.UNLIMITED)
    private val openDeferred = CompletableDeferred<Unit>()

    /** Bytes received from QUIC that haven't been ACKed (extendStreamOffset). */
    private var pendingQuicBytes = 0

    private val lock = Any()

    override val isConnected: Boolean get() = state == State.READY
    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    /** Opens the stream and performs the Hysteria TCP request handshake.
     *  Suspends until the server returns status OK or fails. */
    suspend fun open() {
        if (state != State.IDLE) throw HysteriaError.NotReady
        state = State.OPENING
        try {
            streamId = session.openTcpStream(this)
        } catch (e: Throwable) {
            fail(e)
            throw e
        }
        state = State.HANDSHAKING
        val frame = HysteriaProtocol.encodeTcpRequest(destination)
        session.writeStream(streamId, frame)
        openDeferred.await()
    }

    /** Called by [HysteriaSession] when the server pushes data on our stream. */
    fun handleStreamData(data: ByteArray, fin: Boolean) {
        synchronized(lock) {
            if (data.isNotEmpty()) {
                pendingQuicBytes += data.size
                receiveBuffer.write(data)
            }
            if (!responseParsed) {
                tryParseResponse()
                if (!responseParsed) {
                    if (fin) fail(HysteriaError.ConnectionFailed("Stream closed before response"))
                    return
                }
            }

            if (receiveBuffer.size() > 0) {
                val payload = receiveBuffer.toByteArray()
                receiveBuffer.reset()
                ackConsumedBytes()
                receiveChannel.trySendBlocking(payload)
            }

            if (fin) {
                state = State.CLOSED
                receiveChannel.trySendBlocking(null)
                receiveChannel.close()
            }
        }
    }

    private fun tryParseResponse() {
        val buf = receiveBuffer.toByteArray()
        val parsed = HysteriaProtocol.parseTcpResponse(buf) ?: return
        responseParsed = true
        // Drop the consumed prefix from the receive buffer.
        receiveBuffer.reset()
        if (buf.size > parsed.consumed) {
            receiveBuffer.write(buf, parsed.consumed, buf.size - parsed.consumed)
        }
        // Flow-control credit is returned lazily when the app calls receive.

        if (parsed.status != HysteriaProtocol.TCP_RESPONSE_STATUS_OK) {
            fail(HysteriaError.TunnelFailed(parsed.message))
            return
        }
        state = State.READY
        if (!openDeferred.isCompleted) openDeferred.complete(Unit)
    }

    private fun ackConsumedBytes() {
        val count = pendingQuicBytes
        if (count <= 0) return
        pendingQuicBytes = 0
        session.extendStreamOffset(streamId, count)
    }

    fun handleSessionError(error: Throwable) = fail(error)

    private fun fail(error: Throwable) {
        synchronized(lock) {
            if (state == State.CLOSED) return
            state = State.CLOSED
        }
        if (!openDeferred.isCompleted) openDeferred.completeExceptionally(error)
        receiveChannel.close(error)
    }

    // -- VlessConnection API --

    override suspend fun sendRaw(data: ByteArray) {
        if (state != State.READY) {
            throw if (state == State.CLOSED) HysteriaError.StreamClosed else HysteriaError.NotReady
        }
        session.writeStream(streamId, data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (state != State.READY) return
        session.writeStream(streamId, data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (state == State.CLOSED) {
            // Drain any remaining buffered payload first.
            val maybe = receiveChannel.tryReceive().getOrNull()
            return maybe
        }
        return try { receiveChannel.receive() } catch (_: Throwable) { null }
    }

    override fun cancel() {
        synchronized(lock) {
            if (state == State.CLOSED) return
            state = State.CLOSED
        }
        if (streamId >= 0) {
            session.shutdownStream(streamId)
            session.releaseTcpStream(streamId)
        }
        if (!openDeferred.isCompleted) openDeferred.completeExceptionally(HysteriaError.StreamClosed)
        receiveChannel.close()
    }
}
