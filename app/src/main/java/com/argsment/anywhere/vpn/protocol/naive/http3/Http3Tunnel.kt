package com.argsment.anywhere.vpn.protocol.naive.http3

import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTunnel
import com.argsment.anywhere.vpn.quic.QuicConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import java.io.ByteArrayOutputStream

private val logger = AnywhereLogger("HTTP3")

/**
 * One HTTP/3 session = one QUIC connection. Owns the control stream (for
 * SETTINGS exchange) and the set of request-stream tunnels.
 *
 * Mirrors `HTTP3Session.swift` — simplified: control stream initiated,
 * per-tunnel bidi streams carry CONNECT + DATA. Peer SETTINGS parsed; strict
 * enforcement of MAX_FIELD_SECTION_SIZE against the request headers.
 */
class Http3Session(
    private val host: String,
    private val port: Int,
    serverName: String? = null
) {
    private val quic = QuicConnection(host = host, port = port, serverName = serverName,
                                      alpn = listOf("h3"), datagramsEnabled = false)

    /** Stream ID → Tunnel for request streams. */
    private val tunnels = java.util.concurrent.ConcurrentHashMap<Long, Http3Tunnel>()

    /** Peer SETTINGS values once observed on the server's control stream. */
    @Volatile var peerSettings: Map<Long, Long> = emptyMap()
        private set

    @Volatile private var controlStreamId: Long = -1L
    @Volatile private var peerControlStreamId: Long = -1L

    /** Unparsed tail on peer control stream. */
    private val controlBuffer = ByteArrayOutputStream()

    private val ready = CompletableDeferred<Unit>()

    suspend fun connect() {
        quic.streamDataHandler = ::onStreamData
        quic.connectionClosedHandler = { err ->
            // Fail all tunnels
            tunnels.values.forEach { it.onConnectionClosed(err) }
            tunnels.clear()
            if (!ready.isCompleted) ready.completeExceptionally(err)
        }
        quic.connect()

        // Open client control stream (uni) and send SETTINGS.
        val sid = quic.openUniStream()
            ?: throw Http3Error("Failed to open control stream")
        controlStreamId = sid
        val settingsPayload = ByteArrayOutputStream()
        // Stream type = 0x00 (control)
        settingsPayload.write(Http3Framer.encodeVarInt(0x00))
        settingsPayload.write(Http3Framer.clientSettingsFrame())
        quic.writeStream(sid, settingsPayload.toByteArray(), fin = false)
        ready.complete(Unit)
    }

    suspend fun awaitReady() = ready.await()

    /** Open a bidi stream for a CONNECT request. */
    fun openRequestStream(tunnel: Http3Tunnel): Long? {
        val sid = quic.openBidiStream() ?: return null
        tunnels[sid] = tunnel
        return sid
    }

    fun writeStream(streamId: Long, data: ByteArray) {
        quic.writeStream(streamId, data, fin = false)
    }

    fun shutdownStream(streamId: Long) {
        tunnels.remove(streamId)
        quic.shutdownStream(streamId)
    }

    fun extendStreamOffset(streamId: Long, count: Int) {
        quic.extendStreamOffset(streamId, count)
    }

    fun close() {
        quic.close()
        tunnels.clear()
    }

    /** Enforce peer's MAX_FIELD_SECTION_SIZE (per RFC 9114 §4.2.2). */
    fun isWithinPeerFieldSectionLimit(headers: List<Pair<String, String>>): Boolean {
        val limit = peerSettings[Http3SettingsId.MAX_FIELD_SECTION_SIZE] ?: return true
        // Estimated cost: sum over headers of (len(name) + len(value) + 32).
        val sum = headers.sumOf { 32L + it.first.length + it.second.length }
        return sum <= limit
    }

    // -- QUIC stream data handling --

    private fun onStreamData(streamId: Long, data: ByteArray, fin: Boolean) {
        // Peer-initiated unidirectional streams start at id 3,7,11,... (server uni)
        // On first byte they carry the stream type; type 0x00 is the peer's control
        // stream.
        if (streamId and 0x02L != 0L && streamId and 0x01L != 0L) {
            // server-initiated unidirectional — treat as control if we haven't seen it yet
            handlePeerControlStream(streamId, data, fin)
            return
        }
        // Bidi request stream or something we don't track — dispatch to tunnel
        tunnels[streamId]?.onStreamData(data, fin)
    }

    private fun handlePeerControlStream(streamId: Long, data: ByteArray, fin: Boolean) {
        controlBuffer.write(data)
        val buf = controlBuffer.toByteArray()
        var pos = 0
        if (peerControlStreamId < 0) {
            // First byte is the stream type varint.
            val (type, typeLen) = Http3Framer.decodeVarInt(buf, 0) ?: return
            if (type != 0x00L) {
                // Not a control stream — ignore (push/qpack streams go here too).
                controlBuffer.reset()
                return
            }
            peerControlStreamId = streamId
            pos = typeLen
        }
        while (pos < buf.size) {
            val parsed = Http3Framer.parseFrame(buf, pos) ?: break
            val (frame, total) = parsed
            pos += total
            if (frame.type == Http3FrameType.SETTINGS) parseSettings(frame.payload)
            // GOAWAY, MAX_PUSH_ID: ignored in this port.
        }
        // Retain tail
        val tail = buf.copyOfRange(pos, buf.size)
        controlBuffer.reset()
        if (tail.isNotEmpty()) controlBuffer.write(tail)
    }

    private fun parseSettings(payload: ByteArray) {
        val map = mutableMapOf<Long, Long>()
        var pos = 0
        while (pos < payload.size) {
            val (id, idLen) = Http3Framer.decodeVarInt(payload, pos) ?: break
            pos += idLen
            val (v, vLen) = Http3Framer.decodeVarInt(payload, pos) ?: break
            pos += vLen
            map[id] = v
        }
        peerSettings = map
    }
}

/**
 * One HTTP/3 tunnel over a QUIC bidi stream. Mirrors the NaiveTunnel contract
 * used by the HTTP/1.1 and HTTP/2 variants.
 */
class Http3Tunnel(
    private val session: Http3Session,
    private val configuration: NaiveConfiguration,
    private val destination: String
) : NaiveTunnel {

    enum class State { IDLE, CONNECT_SENT, OPEN, CLOSED }

    @Volatile private var state: State = State.IDLE
    private var streamId: Long = -1
    private val recvChan = Channel<ByteArray?>(Channel.UNLIMITED)
    private val connectReady = CompletableDeferred<Unit>()
    private val frameBuf = ByteArrayOutputStream()
    @Volatile private var headersReceived = false

    override val isConnected: Boolean get() = state == State.OPEN
    override val negotiatedPaddingType: NaivePaddingNegotiator.PaddingType =
        NaivePaddingNegotiator.PaddingType.NONE

    override suspend fun openTunnel() {
        session.awaitReady()
        val sid = session.openRequestStream(this) ?: throw Http3Error("Failed to open QUIC stream")
        streamId = sid

        val extras = buildList {
            add("user-agent" to "Chrome/128.0.0.0")
            configuration.basicAuth?.let { add("proxy-authorization" to "Basic $it") }
        }
        val headers = buildList<Pair<String, String>> {
            add(":method" to "CONNECT")
            add(":authority" to destination)
            addAll(extras)
        }
        if (!session.isWithinPeerFieldSectionLimit(headers)) {
            fail(Http3Error("Request headers exceed peer MAX_FIELD_SECTION_SIZE"))
            return
        }

        val block = QpackEncoder.encodeConnectHeaders(
            authority = destination,
            extraHeaders = extras
        )
        val frame = Http3Framer.headersFrame(block)
        state = State.CONNECT_SENT
        session.writeStream(streamId, frame)
        connectReady.await()
    }

    override suspend fun sendData(data: ByteArray) {
        if (state != State.OPEN) throw Http3Error("Stream not open")
        val frame = Http3Framer.dataFrame(data)
        session.writeStream(streamId, frame)
    }

    override suspend fun receiveData(): ByteArray? {
        val data = recvChan.receive()
        if (data != null) session.extendStreamOffset(streamId, data.size)
        return data
    }

    override fun close() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        session.shutdownStream(streamId)
        recvChan.trySend(null)
        recvChan.close()
    }

    fun onStreamData(data: ByteArray, fin: Boolean) {
        if (state == State.CLOSED) return
        frameBuf.write(data)
        parseFrames()
        if (fin) {
            recvChan.trySend(null)
            recvChan.close()
            state = State.CLOSED
        }
    }

    fun onConnectionClosed(err: Throwable) {
        if (!connectReady.isCompleted) connectReady.completeExceptionally(err)
        state = State.CLOSED
        recvChan.trySend(null)
        recvChan.close(err)
    }

    private fun parseFrames() {
        val data = frameBuf.toByteArray()
        var pos = 0
        while (pos < data.size) {
            val parsed = Http3Framer.parseFrame(data, pos) ?: break
            val (frame, total) = parsed
            pos += total
            when (frame.type) {
                Http3FrameType.HEADERS -> {
                    if (!headersReceived) {
                        val headers = QpackEncoder.decodeHeaders(frame.payload)
                        val status = headers?.firstOrNull { it.first == ":status" }?.second
                        if (status == "200") {
                            headersReceived = true
                            state = State.OPEN
                            if (!connectReady.isCompleted) connectReady.complete(Unit)
                        } else {
                            fail(Http3Error("CONNECT rejected: status=$status"))
                            return
                        }
                    }
                    // Trailers — ignore
                }
                Http3FrameType.DATA -> {
                    recvChan.trySend(frame.payload.copyOf())
                }
            }
        }
        // Keep tail
        val tail = data.copyOfRange(pos, data.size)
        frameBuf.reset()
        if (tail.isNotEmpty()) frameBuf.write(tail)
    }

    private fun fail(err: Throwable) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        if (!connectReady.isCompleted) connectReady.completeExceptionally(err)
        recvChan.trySend(null)
        recvChan.close(err)
    }
}

class Http3Error(m: String) : java.io.IOException(m)
