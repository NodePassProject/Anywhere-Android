package com.argsment.anywhere.vpn.protocol.naive.http3

import com.argsment.anywhere.vpn.protocol.naive.NaiveConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaivePaddingNegotiator
import com.argsment.anywhere.vpn.protocol.naive.NaiveTunnel
import com.argsment.anywhere.vpn.quic.QuicConnection
import com.argsment.anywhere.vpn.quic.QuicTuning
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private val logger = AnywhereLogger("HTTP3")

/**
 * One HTTP/3 session = one QUIC connection. Owns the control stream (for
 * SETTINGS exchange) and the set of request-stream tunnels.
 *
 * Mirrors `HTTP3Session.swift`. Exposes pool-visible state (via a
 * [ReentrantLock]) so [Http3SessionPool] can reserve stream slots and
 * evict closed / blocked sessions without contending with the QUIC
 * receive path. GOAWAY, SETTINGS validation, and duplicate-control-stream
 * enforcement all follow RFC 9114.
 */
class Http3Session(
    private val host: String,
    private val port: Int,
    serverName: String? = null
) {

    enum class SessionState { IDLE, CONNECTING, READY, DRAINING, CLOSED }

    private val quic = QuicConnection(
        host = host, port = port, serverName = serverName,
        alpn = listOf("h3"), datagramsEnabled = false,
        tuning = QuicTuning.naive
    )

    /** Stream ID → Tunnel for request streams. */
    private val tunnels = ConcurrentHashMap<Long, Http3Tunnel>()

    /** Peer SETTINGS values once observed on the server's control stream. */
    @Volatile var peerSettings: Map<Long, Long> = emptyMap()
        private set

    @Volatile var peerMaxFieldSectionSize: Long = Long.MAX_VALUE
        private set
    @Volatile var peerSupportsExtendedConnect: Boolean = false
        private set
    @Volatile var peerSupportsH3Datagram: Boolean = false
        private set

    @Volatile private var controlStreamId: Long = -1L
    @Volatile private var peerControlStreamId: Long = -1L

    /** Unparsed tail on peer control stream. */
    private val controlBuffer = ByteArrayOutputStream()

    /** Server-initiated unidirectional streams whose type byte is still buffered. */
    private val pendingServerStreams = ConcurrentHashMap<Long, ByteArrayOutputStream>()

    /** True once the server's SETTINGS frame has been parsed. */
    @Volatile private var serverSettingsReceived = false

    private val ready = CompletableDeferred<Unit>()

    /**
     * Current session lifecycle state. Read/written under [poolLock]
     * for the multi-field transitions (DRAINING → CLOSED), but most
     * single reads use the @Volatile field directly.
     */
    @Volatile var state: SessionState = SessionState.IDLE
        private set

    // ---------------- Pool-visible state ----------------

    private val poolLock = ReentrantLock()

    /** Pool eviction callback. Invoked after the session's resources are released. */
    @Volatile var onClose: (() -> Unit)? = null

    @Volatile var poolIsClosed: Boolean = false
        private set

    /**
     * True when the QUIC peer won't accept more streams — either
     * STREAM_ID_BLOCKED or GOAWAY-driven drain.
     */
    @Volatile var poolIsStreamBlocked: Boolean = false
        private set

    private var poolStreamCount: Int = 0
    private var reservedStreams: Int = 0

    private val maxConcurrentStreams = 100

    /** Thread-safe snapshot of live+reserved streams. */
    val hasActiveStreams: Boolean
        get() = poolLock.withLock { poolStreamCount > 0 || reservedStreams > 0 }

    /** Thread-safe snapshot of reserved+active stream count. */
    val currentStreamLoad: Int
        get() = poolLock.withLock { poolStreamCount + reservedStreams }

    // ---------------------------------------------------------------

    /**
     * Atomically reserve a stream slot, respecting [maxConcurrentStreams]
     * and session state.
     */
    fun tryReserveStream(): Boolean = poolLock.withLock {
        if (poolIsClosed || poolIsStreamBlocked) return@withLock false
        if (poolStreamCount + reservedStreams >= maxConcurrentStreams) return@withLock false
        reservedStreams += 1
        true
    }

    /**
     * Pool overflow path: reserve a slot bypassing [maxConcurrentStreams].
     * Used only when every session in the pool is saturated and the pool
     * has hit its hard cap.
     */
    fun forceReserveStream(): Boolean = poolLock.withLock {
        if (poolIsClosed || poolIsStreamBlocked) return@withLock false
        reservedStreams += 1
        true
    }

    // ---------------- Connect ----------------

    suspend fun connect() {
        val canStart = poolLock.withLock {
            when (state) {
                SessionState.IDLE -> { state = SessionState.CONNECTING; true }
                SessionState.CONNECTING -> false
                else -> false
            }
        }
        if (!canStart) {
            // Already connecting / ready / failed — just await the latch.
            ready.await()
            return
        }

        quic.streamDataHandler = ::onStreamData
        quic.connectionClosedHandler = { err ->
            failSession(err)
        }

        try {
            quic.connect()
        } catch (t: Throwable) {
            failSession(t)
            throw t
        }

        // Open client control stream (uni) and send SETTINGS.
        val sid = quic.openUniStream()
            ?: run {
                val err = Http3Error("Failed to open control stream")
                failSession(err)
                throw err
            }
        controlStreamId = sid
        val settingsPayload = ByteArrayOutputStream()
        settingsPayload.write(Http3Framer.encodeVarInt(0x00))
        settingsPayload.write(Http3Framer.clientSettingsFrame())
        quic.writeStream(sid, settingsPayload.toByteArray(), fin = false)

        // QPACK encoder (type 0x02) and decoder (type 0x03) uni streams —
        // advertised for completeness even though we don't use the
        // dynamic table (QPACK_MAX_TABLE_CAPACITY = 0).
        quic.openUniStream()?.let { quic.writeStream(it, byteArrayOf(0x02), fin = false) }
        quic.openUniStream()?.let { quic.writeStream(it, byteArrayOf(0x03), fin = false) }

        poolLock.withLock { state = SessionState.READY }
        if (!ready.isCompleted) ready.complete(Unit)
    }

    suspend fun awaitReady() = ready.await()

    // ---------------- Stream ops (Tunnel-facing API — unchanged) ----------------

    /**
     * Open a bidi stream for a CONNECT request. Also consumes one
     * reserved-stream slot if the caller reserved via the pool.
     */
    fun openRequestStream(tunnel: Http3Tunnel): Long? {
        // Refuse new streams on drained/closed sessions.
        if (state == SessionState.DRAINING || state == SessionState.CLOSED) return null

        val sid = quic.openBidiStream()
        if (sid == null) {
            // QUIC peer is out of stream credits — flag so the pool
            // opens a new session next time.
            markStreamBlocked()
            return null
        }
        tunnels[sid] = tunnel
        poolLock.withLock {
            if (reservedStreams > 0) reservedStreams -= 1
            poolStreamCount += 1
        }
        return sid
    }

    fun writeStream(streamId: Long, data: ByteArray) {
        if (state == SessionState.CLOSED) return
        quic.writeStream(streamId, data, fin = false)
    }

    /** Caller-initiated stream teardown. */
    fun shutdownStream(streamId: Long) {
        removeStream(streamId)
        quic.shutdownStream(streamId)
    }

    /** Caller-initiated stream teardown with explicit application error code. */
    fun shutdownStream(streamId: Long, appErrorCode: Long) {
        removeStream(streamId)
        quic.shutdownStream(streamId, appErrorCode)
    }

    fun extendStreamOffset(streamId: Long, count: Int) {
        quic.extendStreamOffset(streamId, count)
    }

    fun close() {
        val alreadyClosed = poolLock.withLock {
            if (state == SessionState.CLOSED) true
            else { state = SessionState.CLOSED; poolIsClosed = true; poolStreamCount = 0; reservedStreams = 0; false }
        }
        if (alreadyClosed) return

        // Error out any in-flight tunnels and clear the table.
        val active = tunnels.values.toList()
        tunnels.clear()
        val err = Http3Error("Session closed")
        for (t in active) {
            try { t.onConnectionClosed(err) } catch (_: Throwable) {}
        }
        try { quic.close() } catch (_: Throwable) {}
        try { onClose?.invoke() } catch (_: Throwable) {}
    }

    /** Enforce peer's MAX_FIELD_SECTION_SIZE (per RFC 9114 §4.2.2). */
    fun isWithinPeerFieldSectionLimit(headers: List<Pair<String, String>>): Boolean {
        val limit = peerMaxFieldSectionSize
        if (limit == Long.MAX_VALUE) return true
        var total = 0L
        for (h in headers) {
            total += 32L + h.first.length + h.second.length
            if (total > limit) return false
        }
        return true
    }

    // ---------------- Stream-table bookkeeping ----------------

    /** Called by [Http3Tunnel] when its QUIC stream terminates. */
    fun removeStream(streamId: Long) {
        if (tunnels.remove(streamId) != null) {
            val drainedOut = poolLock.withLock {
                if (poolStreamCount > 0) poolStreamCount -= 1
                state == SessionState.DRAINING && tunnels.isEmpty()
            }
            if (drainedOut) close()
        }
    }

    /** Mark the session as unable to accept more streams. */
    fun markStreamBlocked() {
        poolLock.withLock {
            poolIsStreamBlocked = true
            if (reservedStreams > 0) reservedStreams -= 1
        }
    }

    // ---------------- QUIC stream data demux ----------------

    private fun onStreamData(streamId: Long, data: ByteArray, fin: Boolean) {
        tunnels[streamId]?.let { t ->
            t.onStreamData(data, fin)
            return
        }

        // Server-initiated unidirectional streams: (streamId & 0x03) == 0x03.
        val isServerUni = (streamId and 0x03L) == 0x03L
        if (!isServerUni || data.isEmpty()) return

        // Server-initiated data is consumed synchronously — extend flow
        // control immediately so connection credits aren't leaked.
        quic.extendStreamOffset(streamId, data.size)

        if (streamId == peerControlStreamId) {
            controlBuffer.write(data)
            processServerControlFrames()
            return
        }

        val buf = pendingServerStreams.getOrPut(streamId) { ByteArrayOutputStream() }
        buf.write(data)
        val bytes = buf.toByteArray()
        if (bytes.isEmpty()) return
        val streamType = bytes[0].toInt() and 0xFF
        when (streamType) {
            0x00 -> {
                // Control stream (RFC 9114 §6.2.1)
                if (peerControlStreamId >= 0) {
                    failSession(Http3Error("Duplicate server control stream"))
                    return
                }
                peerControlStreamId = streamId
                pendingServerStreams.remove(streamId)
                controlBuffer.reset()
                controlBuffer.write(bytes, 1, bytes.size - 1)
                processServerControlFrames()
            }
            0x01 -> {
                // Push stream — we never sent MAX_PUSH_ID so this is a protocol error.
                pendingServerStreams.remove(streamId)
                failSession(Http3Error("Server opened push stream without MAX_PUSH_ID"))
            }
            0x02, 0x03 -> {
                // QPACK encoder / decoder — with QPACK_MAX_TABLE_CAPACITY=0
                // there's nothing meaningful; drain silently. Drop the
                // buffer so we stop accumulating bytes.
                pendingServerStreams.remove(streamId)
            }
            else -> {
                // RFC 9114 §7.2.9 grease types are of the form 0x1f*N+0x21.
                if (!isReservedStreamType(streamType)) {
                    pendingServerStreams.remove(streamId)
                    quic.shutdownStream(streamId, Http3ErrorCode.STREAM_CREATION_ERROR)
                } else {
                    // Ignore grease bytes — drop the accumulated buffer.
                    pendingServerStreams.remove(streamId)
                }
            }
        }
    }

    private fun isReservedStreamType(t: Int): Boolean {
        // t >= 0x21 && (t - 0x21) % 0x1F == 0
        return t >= 0x21 && ((t - 0x21) % 0x1F == 0)
    }

    private fun processServerControlFrames() {
        while (true) {
            val buf = controlBuffer.toByteArray()
            if (buf.isEmpty()) return
            val parsed = Http3Framer.parseFrame(buf, 0) ?: return
            val (frame, consumed) = parsed

            // Shift the buffer past the consumed frame.
            controlBuffer.reset()
            if (consumed < buf.size) controlBuffer.write(buf, consumed, buf.size - consumed)

            if (!serverSettingsReceived) {
                if (frame.type != Http3FrameType.SETTINGS) {
                    failSession(Http3Error("First control-stream frame was not SETTINGS"))
                    return
                }
                serverSettingsReceived = true
                if (!parseSettings(frame.payload)) {
                    failSession(Http3Error("Malformed SETTINGS frame"))
                    return
                }
                continue
            }

            when (frame.type) {
                Http3FrameType.GOAWAY -> handleGoaway(frame.payload)
                Http3FrameType.SETTINGS -> {
                    failSession(Http3Error("Duplicate SETTINGS frame"))
                    return
                }
                Http3FrameType.DATA,
                Http3FrameType.HEADERS,
                Http3FrameType.PUSH_PROMISE -> {
                    failSession(Http3Error("Forbidden frame type ${frame.type} on control stream"))
                    return
                }
                else -> { /* unknown / grease — ignore */ }
            }
        }
    }

    /** Returns false if the SETTINGS payload is malformed. */
    private fun parseSettings(payload: ByteArray): Boolean {
        val map = mutableMapOf<Long, Long>()
        val seen = HashSet<Long>()
        var pos = 0
        while (pos < payload.size) {
            val id = Http3Framer.decodeVarInt(payload, pos) ?: return false
            pos += id.second
            val v = Http3Framer.decodeVarInt(payload, pos) ?: return false
            pos += v.second
            // RFC 9114 §7.2.4: duplicate identifiers are a settings error.
            if (!seen.add(id.first)) return false
            map[id.first] = v.first

            when (id.first) {
                Http3SettingsId.MAX_FIELD_SECTION_SIZE -> {
                    peerMaxFieldSectionSize = v.first
                }
                Http3SettingsId.ENABLE_CONNECT_PROTOCOL -> {
                    if (v.first != 0L && v.first != 1L) return false
                    peerSupportsExtendedConnect = (v.first == 1L)
                }
                Http3SettingsId.H3_DATAGRAM -> {
                    if (v.first != 0L && v.first != 1L) return false
                    peerSupportsH3Datagram = (v.first == 1L)
                }
                Http3SettingsId.QPACK_MAX_TABLE_CAPACITY,
                Http3SettingsId.QPACK_BLOCKED_STREAMS -> {
                    // We don't use the dynamic table; nothing to react to.
                }
                else -> { /* unknown / reserved — ignore */ }
            }
        }
        peerSettings = map
        return true
    }

    private fun handleGoaway(@Suppress("UNUSED_PARAMETER") payload: ByteArray) {
        val shouldClose = poolLock.withLock {
            if (state != SessionState.READY) return@withLock false
            state = SessionState.DRAINING
            poolIsStreamBlocked = true
            tunnels.isEmpty()
        }
        logger.info("HTTP/3 received GOAWAY, draining ${tunnels.size} active streams")
        if (shouldClose) close()
    }

    private fun failSession(err: Throwable) {
        val alreadyClosed = poolLock.withLock {
            if (state == SessionState.CLOSED) true
            else { state = SessionState.CLOSED; poolIsClosed = true; poolStreamCount = 0; reservedStreams = 0; false }
        }
        if (alreadyClosed) return

        if (!ready.isCompleted) ready.completeExceptionally(err)

        val active = tunnels.values.toList()
        tunnels.clear()
        for (t in active) {
            try { t.onConnectionClosed(err) } catch (_: Throwable) {}
        }
        try { quic.close() } catch (_: Throwable) {}
        try { onClose?.invoke() } catch (_: Throwable) {}
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
    // Each queued chunk carries its QUIC byte count so flow control is
    // extended when the chunk leaves the buffer — matches iOS
    // receiveQueue semantics (backpressure when the app is slow).
    private val recvChan = Channel<RecvChunk?>(Channel.UNLIMITED)
    private val connectReady = CompletableDeferred<Unit>()
    private val frameBuf = ByteArrayOutputStream()
    @Volatile private var headersReceived = false

    private data class RecvChunk(val data: ByteArray, val quicBytes: Int)

    override val isConnected: Boolean get() = state == State.OPEN
    override val negotiatedPaddingType: NaivePaddingNegotiator.PaddingType =
        NaivePaddingNegotiator.PaddingType.NONE

    override suspend fun openTunnel() {
        session.awaitReady()
        val sid = session.openRequestStream(this)
            ?: throw Http3Error("Failed to open QUIC stream")
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
        val chunk = recvChan.receive() ?: return null
        // Extend flow control in lockstep with the chunk leaving the
        // buffer — preserves "backpressure when the app is slow".
        if (chunk.quicBytes > 0) session.extendStreamOffset(streamId, chunk.quicBytes)
        return chunk.data
    }

    override fun close() {
        close(code = Http3ErrorCode.NO_ERROR)
    }

    fun close(code: Long) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        val shutdownCode = if (headersReceived) code else Http3ErrorCode.REQUEST_CANCELLED
        if (streamId >= 0) {
            session.shutdownStream(streamId, shutdownCode)
        }
        recvChan.trySend(null)
        recvChan.close()
    }

    fun onStreamData(data: ByteArray, fin: Boolean) {
        if (state == State.CLOSED) return
        if (data.isNotEmpty()) {
            frameBuf.write(data)
            parseFrames()
        }
        if (fin) {
            recvChan.trySend(null)
            recvChan.close()
            state = State.CLOSED
            session.removeStream(streamId)
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
        // Control frames (HEADERS, SETTINGS, GOAWAY) are consumed internally
        // and never reach the app — ack their QUIC bytes as a batch at the
        // end of this pass rather than per-frame.
        var controlBytes = 0
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
                    // Trailers — ignored.
                    controlBytes += total
                }
                Http3FrameType.DATA -> {
                    // Defer extendStreamOffset until the recvChan receiver
                    // consumes the chunk — see receiveData().
                    recvChan.trySend(RecvChunk(frame.payload.copyOf(), quicBytes = total))
                }
                else -> {
                    // SETTINGS/GOAWAY/etc. on a request stream are not valid
                    // but we drain the bytes to keep flow control moving.
                    controlBytes += total
                }
            }
        }
        if (controlBytes > 0 && streamId >= 0) {
            session.extendStreamOffset(streamId, controlBytes)
        }
        // Keep tail.
        val tail = data.copyOfRange(pos, data.size)
        frameBuf.reset()
        if (tail.isNotEmpty()) frameBuf.write(tail)
    }

    private fun fail(err: Throwable) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        if (streamId >= 0) {
            session.shutdownStream(streamId, Http3ErrorCode.REQUEST_CANCELLED)
        }
        if (!connectReady.isCompleted) connectReady.completeExceptionally(err)
        recvChan.trySend(null)
        recvChan.close(err)
    }
}

class Http3Error(m: String) : java.io.IOException(m)
