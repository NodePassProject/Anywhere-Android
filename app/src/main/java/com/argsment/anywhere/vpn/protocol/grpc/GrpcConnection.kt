package com.argsment.anywhere.vpn.protocol.grpc

import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.xhttp.TransportClosures
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private val logger = AnywhereLogger("GRPC")

/**
 * gRPC transport over HTTP/2. Mirrors iOS `GRPCConnection`.
 *
 * Opens a single bidirectional streaming RPC to `/<serviceName>/Tun` (or `/TunMulti`) and
 * tunnels raw bytes as `Hunk` protobuf messages framed with gRPC's 5-byte length prefix.
 *
 * Uses Android's pure-Kotlin HPACK / HTTP-2 framer (adapted from `XHttpConnection`'s
 * implementation) rather than pulling in a new HTTP/2 library.
 */
class GrpcConnection private constructor(
    private val configuration: GrpcConfiguration,
    private val authority: String,
    private val transportSend: suspend (ByteArray) -> Unit,
    private val transportReceive: suspend () -> ByteArray?,
    private val transportCancel: () -> Unit
) {
    // -- State --

    private val lock = ReentrantLock()
    private var _isConnected: Boolean = true

    /** Raw HTTP/2 byte buffer (accumulates transport reads until a full frame is parseable). */
    private var h2ReadBuffer = ByteArray(0)
    private var h2ReadBufferLen = 0

    /** gRPC message reassembly buffer (HTTP/2 DATA payloads -> length-prefixed gRPC frames). */
    private var grpcFrameBuffer = ByteArray(0)
    private var grpcFrameBufferLen = 0

    /** Decoded app-layer bytes ready for the caller. */
    private var decodedBuffer = ByteArray(0)
    private var decodedBufferLen = 0

    /** Whether the gRPC response HEADERS (status 200) have been validated. */
    private var h2ResponseReceived = false
    /** Whether the server has closed its side of the stream. */
    private var h2StreamClosed = false

    /** Peer's flow-control windows (bytes we can still send). */
    private var h2PeerConnectionWindow: Int = 65535
    private var h2PeerStreamSendWindow: Int = 65535
    private var h2PeerInitialWindowSize: Int = 65535

    /** Our local window sizes. */
    private var h2LocalWindowSize: Int = H2_STREAM_WINDOW_SIZE

    /** Maximum HTTP/2 frame payload size. */
    private var h2MaxFrameSize: Int = 16384

    /** Bytes received but not yet acknowledged via WINDOW_UPDATE. */
    private var h2ConnectionReceiveConsumed: Int = 0
    private var h2StreamReceiveConsumed: Int = 0

    /** Send-side continuations waiting for a WINDOW_UPDATE. */
    private val h2FlowResumptions: MutableList<CancellableContinuation<Unit>> = mutableListOf()

    /** Keepalive ping coroutine (null when idleTimeout == 0). */
    private var keepaliveJob: Job? = null
    private val keepaliveScope: CoroutineScope by lazy {
        CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    val isConnected: Boolean
        get() = lock.withLock { _isConnected }

    init {
        if (configuration.initialWindowsSize > 0) {
            h2LocalWindowSize = configuration.initialWindowsSize
        }
    }

    // -- Factory constructors --

    /** gRPC over a plain [NioSocket]. */
    constructor(
        socket: NioSocket,
        configuration: GrpcConfiguration,
        authority: String
    ) : this(
        configuration = configuration,
        authority = authority,
        transportSend = { data -> socket.send(data) },
        transportReceive = { socket.receive() },
        transportCancel = { socket.forceCancel() }
    )

    /** gRPC over a [TlsRecordConnection] (TLS or Reality). */
    constructor(
        tlsConnection: TlsRecordConnection,
        configuration: GrpcConfiguration,
        authority: String
    ) : this(
        configuration = configuration,
        authority = authority,
        transportSend = { data -> tlsConnection.send(data) },
        transportReceive = { tlsConnection.receive() },
        transportCancel = { tlsConnection.cancel() }
    )

    /** gRPC over a chained transport (proxy chain). */
    constructor(
        transport: Transport,
        configuration: GrpcConfiguration,
        authority: String
    ) : this(
        configuration = configuration,
        authority = authority,
        transportSend = { data -> transport.send(data) },
        transportReceive = { transport.receive() },
        transportCancel = { transport.forceCancel() }
    )

    /** gRPC over a generic [TransportClosures] (shared with XHTTP). */
    constructor(
        closures: TransportClosures,
        configuration: GrpcConfiguration,
        authority: String
    ) : this(
        configuration = configuration,
        authority = authority,
        transportSend = closures.send,
        transportReceive = closures.receive,
        transportCancel = closures.cancel
    )

    // =========================================================================
    // Setup
    // =========================================================================

    /**
     * Performs the HTTP/2 connection preface + SETTINGS exchange and opens the bidirectional
     * gRPC stream. HEADERS is sent eagerly without waiting for the server's SETTINGS.
     */
    suspend fun performSetup() {
        var initData = ByteArray(0)

        // HTTP/2 connection preface
        initData += H2_PREFACE

        // Client SETTINGS: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE=10MB
        val winSize = h2LocalWindowSize
        val settingsPayload = byteArrayOf(
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04,
            ((winSize shr 24) and 0xFF).toByte(),
            ((winSize shr 16) and 0xFF).toByte(),
            ((winSize shr 8) and 0xFF).toByte(),
            (winSize and 0xFF).toByte(),
            0x00, 0x06, 0x00.toByte(), 0xA0.toByte(), 0x00, 0x00
        )
        initData += buildH2Frame(H2_FRAME_SETTINGS, 0, 0u, settingsPayload)

        // Connection-level WINDOW_UPDATE (1 GB)
        val inc = H2_CONN_WINDOW_SIZE
        val wuPayload = byteArrayOf(
            ((inc shr 24) and 0xFF).toByte(),
            ((inc shr 16) and 0xFF).toByte(),
            ((inc shr 8) and 0xFF).toByte(),
            (inc and 0xFF).toByte()
        )
        initData += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 0u, wuPayload)

        // HEADERS for the bidirectional gRPC stream. END_STREAM intentionally not set —
        // the client keeps sending DATA frames for the lifetime of the tunnel.
        val headerBlock = encodeGrpcRequestHeaders()
        initData += buildH2Frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, STREAM_ID, headerBlock)

        try {
            transportSend(initData)
        } catch (e: Exception) {
            throw GrpcError.SetupFailed("H2 preface/HEADERS write failed: ${e.message}")
        }

        processInitialServerFrames()
    }

    /**
     * Reads frames until the server's SETTINGS is received and ACKed. Also handles
     * WINDOW_UPDATE and PING during setup, and absorbs an early response HEADERS if one
     * arrives before SETTINGS.
     */
    private suspend fun processInitialServerFrames() {
        while (true) {
            val frame = try {
                readH2Frame()
            } catch (e: GrpcError) {
                throw GrpcError.SetupFailed("H2 setup read failed: ${e.message}")
            } catch (e: Exception) {
                throw GrpcError.SetupFailed("H2 setup read failed: ${e.message}")
            }

            when (frame.type) {
                H2_FRAME_SETTINGS -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) == 0) {
                        parseH2Settings(frame.payload)
                        val ack = buildH2Frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0u, ByteArray(0))
                        runCatching { transportSend(ack) }
                        startKeepaliveIfNeeded()
                        return
                    }
                    // ACK for our own SETTINGS — keep reading for the server's.
                }

                H2_FRAME_HEADERS -> {
                    if (frame.streamId == STREAM_ID) {
                        val rejection = checkH2ResponseStatus(frame.payload)
                        if (rejection != null) {
                            throw GrpcError.SetupFailed("gRPC response rejected: $rejection")
                        }
                        // Trailers-only response with :status 200 — HTTP succeeded but
                        // the gRPC call itself failed.
                        if ((frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0) {
                            val grpcError = parseGrpcTrailer(frame.payload)
                            lock.withLock { h2StreamClosed = true }
                            if (grpcError != null) {
                                throw GrpcError.SetupFailed(grpcError.message ?: "gRPC trailer error")
                            }
                        }
                        lock.withLock { h2ResponseReceived = true }
                    }
                    startKeepaliveIfNeeded()
                    return
                }

                H2_FRAME_WINDOW_UPDATE -> {
                    handleWindowUpdate(frame)
                }

                H2_FRAME_PING -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) == 0) {
                        val pong = buildH2Frame(H2_FRAME_PING, H2_FLAG_ACK, 0u, frame.payload)
                        runCatching { transportSend(pong) }
                    }
                }

                H2_FRAME_GOAWAY -> {
                    throw GrpcError.SetupFailed(
                        "Server sent GOAWAY during setup (${describeGoaway(frame.payload)})"
                    )
                }

                H2_FRAME_RST_STREAM -> {
                    if (frame.streamId == STREAM_ID) {
                        throw GrpcError.SetupFailed(
                            "Server reset the stream during setup (${describeRstStream(frame.payload)})"
                        )
                    }
                }

                else -> {
                    // Ignore and keep reading.
                }
            }
        }
    }

    // =========================================================================
    // Public send / receive
    // =========================================================================

    /** Sends a raw byte chunk as one gRPC `Hunk` message. */
    suspend fun send(data: ByteArray) {
        val hunk = encodeHunk(data)
        val framed = wrapGrpcMessage(hunk)
        sendH2Data(framed)
    }

    /** Reads the next application payload, decoding gRPC / protobuf framing as needed. */
    suspend fun receive(): ByteArray? {
        lock.withLock {
            if (decodedBufferLen > 0) {
                val out = decodedBuffer.copyOfRange(0, decodedBufferLen)
                decodedBufferLen = 0
                decodedBuffer = ByteArray(0)
                return out
            }
            if (h2StreamClosed) return null
        }
        return readAndDecode()
    }

    fun cancel() {
        val waiters: List<CancellableContinuation<Unit>>
        lock.withLock {
            _isConnected = false
            h2StreamClosed = true
            h2ReadBuffer = ByteArray(0); h2ReadBufferLen = 0
            grpcFrameBuffer = ByteArray(0); grpcFrameBufferLen = 0
            decodedBuffer = ByteArray(0); decodedBufferLen = 0
            waiters = h2FlowResumptions.toList()
            h2FlowResumptions.clear()
        }
        keepaliveJob?.cancel()
        keepaliveJob = null
        runCatching { keepaliveScope.cancel() }
        for (c in waiters) {
            if (c.isActive) c.resumeWithException(GrpcError.ConnectionClosed())
        }
        transportCancel()
    }

    // =========================================================================
    // HTTP/2 frame I/O
    // =========================================================================

    private data class H2Frame(val type: Byte, val flags: Byte, val streamId: UInt, val payload: ByteArray)

    /** Builds an HTTP/2 frame per RFC 7540 §4.1. */
    private fun buildH2Frame(type: Byte, flags: Byte, streamId: UInt, payload: ByteArray): ByteArray {
        val frame = ByteArray(H2_FRAME_HEADER_SIZE + payload.size)
        val len = payload.size
        frame[0] = ((len shr 16) and 0xFF).toByte()
        frame[1] = ((len shr 8) and 0xFF).toByte()
        frame[2] = (len and 0xFF).toByte()
        frame[3] = type
        frame[4] = flags
        val sid = streamId.toInt() and 0x7FFFFFFF
        frame[5] = ((sid shr 24) and 0xFF).toByte()
        frame[6] = ((sid shr 16) and 0xFF).toByte()
        frame[7] = ((sid shr 8) and 0xFF).toByte()
        frame[8] = (sid and 0xFF).toByte()
        System.arraycopy(payload, 0, frame, H2_FRAME_HEADER_SIZE, payload.size)
        return frame
    }

    /** Parses one frame from [h2ReadBuffer] or returns null if incomplete. Must hold [lock]. */
    private fun parseH2FrameLocked(): H2Frame? {
        if (h2ReadBufferLen < H2_FRAME_HEADER_SIZE) return null
        val length = ((h2ReadBuffer[0].toInt() and 0xFF) shl 16) or
                ((h2ReadBuffer[1].toInt() and 0xFF) shl 8) or
                (h2ReadBuffer[2].toInt() and 0xFF)
        val type = h2ReadBuffer[3]
        val flags = h2ReadBuffer[4]
        val streamId = (((h2ReadBuffer[5].toInt() and 0xFF) shl 24) or
                ((h2ReadBuffer[6].toInt() and 0xFF) shl 16) or
                ((h2ReadBuffer[7].toInt() and 0xFF) shl 8) or
                (h2ReadBuffer[8].toInt() and 0xFF)).toUInt() and 0x7FFFFFFFu

        val totalSize = H2_FRAME_HEADER_SIZE + length
        if (h2ReadBufferLen < totalSize) return null

        val payload = h2ReadBuffer.copyOfRange(H2_FRAME_HEADER_SIZE, totalSize)
        val remaining = h2ReadBufferLen - totalSize
        if (remaining > 0) {
            System.arraycopy(h2ReadBuffer, totalSize, h2ReadBuffer, 0, remaining)
        }
        h2ReadBufferLen = remaining
        return H2Frame(type, flags, streamId, payload)
    }

    /** Reads transport data until at least one complete H2 frame is available, then returns it. */
    private suspend fun readH2Frame(): H2Frame {
        lock.withLock {
            parseH2FrameLocked()?.let { return it }
        }
        while (true) {
            val data = transportReceive() ?: throw GrpcError.ConnectionClosed()
            if (data.isEmpty()) throw GrpcError.ConnectionClosed()
            lock.withLock {
                appendToH2ReadBuffer(data)
                if (h2ReadBufferLen > MAX_H2_READ_BUFFER_SIZE) {
                    h2ReadBuffer = ByteArray(0)
                    h2ReadBufferLen = 0
                    throw GrpcError.ConnectionClosed()
                }
                parseH2FrameLocked()?.let { return it }
            }
        }
        @Suppress("UNREACHABLE_CODE")
        throw GrpcError.ConnectionClosed()
    }

    private fun appendToH2ReadBuffer(data: ByteArray) {
        val needed = h2ReadBufferLen + data.size
        if (needed > h2ReadBuffer.size) {
            val newCap = maxOf(needed, h2ReadBuffer.size * 2, 4096)
            h2ReadBuffer = h2ReadBuffer.copyOf(newCap)
        }
        System.arraycopy(data, 0, h2ReadBuffer, h2ReadBufferLen, data.size)
        h2ReadBufferLen += data.size
    }

    /** Parses a server SETTINGS payload and applies INITIAL_WINDOW_SIZE / MAX_FRAME_SIZE. */
    private fun parseH2Settings(payload: ByteArray) {
        var offset = 0
        while (offset + 6 <= payload.size) {
            val id = ((payload[offset].toInt() and 0xFF) shl 8) or
                    (payload[offset + 1].toInt() and 0xFF)
            val value = ((payload[offset + 2].toInt() and 0xFF) shl 24) or
                    ((payload[offset + 3].toInt() and 0xFF) shl 16) or
                    ((payload[offset + 4].toInt() and 0xFF) shl 8) or
                    (payload[offset + 5].toInt() and 0xFF)
            offset += 6
            when (id) {
                0x04 -> lock.withLock {
                    val delta = value - h2PeerInitialWindowSize
                    h2PeerInitialWindowSize = value
                    h2PeerStreamSendWindow += delta
                }
                0x05 -> lock.withLock { h2MaxFrameSize = value }
            }
        }
    }

    /** Updates our send-side view of the peer's flow-control windows. */
    private fun handleWindowUpdate(frame: H2Frame) {
        val increment = if (frame.payload.size >= 4) {
            (((frame.payload[0].toInt() and 0xFF) shl 24) or
                    ((frame.payload[1].toInt() and 0xFF) shl 16) or
                    ((frame.payload[2].toInt() and 0xFF) shl 8) or
                    (frame.payload[3].toInt() and 0xFF)) and 0x7FFFFFFF
        } else 0
        val waiters: List<CancellableContinuation<Unit>>
        lock.withLock {
            if (frame.streamId == 0u) {
                h2PeerConnectionWindow += increment
            } else if (frame.streamId == STREAM_ID) {
                h2PeerStreamSendWindow += increment
            }
            waiters = h2FlowResumptions.toList()
            h2FlowResumptions.clear()
        }
        for (c in waiters) {
            if (c.isActive) c.resume(Unit)
        }
    }

    // =========================================================================
    // HPACK encoding for request HEADERS
    // =========================================================================

    private fun encodeGrpcRequestHeaders(): ByteArray {
        val block = mutableListOf<Byte>()

        // Pseudo-header order required by RFC 7540 §8.1.2.1: :authority, :method, :path, :scheme.

        // :authority — literal w/ incremental indexing, static-table name index 1.
        val authBytes = hpackEncodeInteger(1, 6)
        authBytes[0] = (authBytes[0].toInt() or 0x40).toByte()
        block.addAll(authBytes.toList())
        block.addAll(hpackEncodeString(authority).toList())

        // :method POST — static-table entry 3.
        block.add(0x83.toByte())

        // :path — literal w/ incremental indexing, static-table name index 4.
        val path = configuration.resolvedPath()
        val pathBytes = hpackEncodeInteger(4, 6)
        pathBytes[0] = (pathBytes[0].toInt() or 0x40).toByte()
        block.addAll(pathBytes.toList())
        block.addAll(hpackEncodeString(path).toList())

        // :scheme https — static-table entry 7.
        block.add(0x87.toByte())

        // content-type: application/grpc — literal w/ incremental indexing, name index 31.
        val ctBytes = hpackEncodeInteger(31, 6)
        ctBytes[0] = (ctBytes[0].toInt() or 0x40).toByte()
        block.addAll(ctBytes.toList())
        block.addAll(hpackEncodeString("application/grpc").toList())

        // te: trailers — required by the gRPC protocol spec.
        block.add(0x40)
        block.addAll(hpackEncodeString("te").toList())
        block.addAll(hpackEncodeString("trailers").toList())

        // grpc-encoding: identity
        block.add(0x40)
        block.addAll(hpackEncodeString("grpc-encoding").toList())
        block.addAll(hpackEncodeString("identity").toList())

        // grpc-accept-encoding: identity
        block.add(0x40)
        block.addAll(hpackEncodeString("grpc-accept-encoding").toList())
        block.addAll(hpackEncodeString("identity").toList())

        // user-agent — literal w/ incremental indexing, static-table name index 58.
        val ua = configuration.userAgent.ifEmpty { DEFAULT_USER_AGENT }
        val uaBytes = hpackEncodeInteger(58, 6)
        uaBytes[0] = (uaBytes[0].toInt() or 0x40).toByte()
        block.addAll(uaBytes.toList())
        block.addAll(hpackEncodeString(ua).toList())

        return block.toByteArray()
    }

    private fun hpackEncodeInteger(value: Int, prefixBits: Int): ByteArray {
        val maxPrefix = (1 shl prefixBits) - 1
        if (value < maxPrefix) return byteArrayOf(value.toByte())
        val result = mutableListOf<Byte>(maxPrefix.toByte())
        var remaining = value - maxPrefix
        while (remaining >= 128) {
            result.add(((remaining and 0x7F) or 0x80).toByte())
            remaining = remaining shr 7
        }
        result.add(remaining.toByte())
        return result.toByteArray()
    }

    private fun hpackEncodeString(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val lenBytes = hpackEncodeInteger(bytes.size, 7)
        lenBytes[0] = (lenBytes[0].toInt() and 0x7F).toByte()
        return lenBytes + bytes
    }

    // =========================================================================
    // HPACK decoding for response :status
    // =========================================================================

    /** Returns `null` if :status is 200, or a short error string otherwise. */
    private fun checkH2ResponseStatus(headerBlock: ByteArray): String? {
        if (headerBlock.isEmpty()) return "empty header block"

        var offset = 0
        // Skip HPACK dynamic-table-size updates (prefix 001xxxxx)
        while (offset < headerBlock.size && (headerBlock[offset].toInt() and 0xE0) == 0x20) {
            val initial = headerBlock[offset].toInt() and 0x1F
            offset += 1
            if (initial == 0x1F) {
                while (offset < headerBlock.size && (headerBlock[offset].toInt() and 0x80) != 0) {
                    offset += 1
                }
                offset += 1
            }
        }
        if (offset >= headerBlock.size) return "empty header block (only table-size updates)"

        val first = headerBlock[offset].toInt() and 0xFF

        // Indexed representation (top bit set).
        if ((first and 0x80) != 0) {
            if (first == 0x88) return null
            return when (first) {
                0x89 -> "status 204"
                0x8a -> "status 206"
                0x8b -> "status 304"
                0x8c -> "status 400"
                0x8d -> "status 404"
                0x8e -> "status 500"
                else -> "status (indexed ${first and 0x7F})"
            }
        }

        // Literal :status — static table indices 8-14 all have name ":status".
        val nameIndex: Int = when {
            (first and 0xF0) == 0x00 -> first and 0x0F
            (first and 0xF0) == 0x10 -> first and 0x0F
            (first and 0xC0) == 0x40 -> first and 0x3F
            else -> return "unknown header representation"
        }

        if (nameIndex !in 8..14 || headerBlock.size - offset < 2) return "unknown :status header"

        val valueMeta = headerBlock[offset + 1].toInt() and 0xFF
        val isHuffman = (valueMeta and 0x80) != 0
        val valueLen = valueMeta and 0x7F
        val valueStart = offset + 2
        if (headerBlock.size < valueStart + valueLen || valueLen == 0) return "status (?)"

        val valueBytes = headerBlock.copyOfRange(valueStart, valueStart + valueLen)
        val status: String = if (!isHuffman) {
            String(valueBytes, Charsets.US_ASCII)
        } else {
            huffmanDecodeDigits(valueBytes)
        }
        return if (status == "200") null else "status $status"
    }

    /** Decodes a Huffman-encoded ASCII digit-only value (used for HTTP status codes). */
    private fun huffmanDecodeDigits(data: ByteArray): String {
        val sb = StringBuilder()
        var bits: Long = 0
        var numBits = 0
        for (b in data) {
            bits = (bits shl 8) or (b.toLong() and 0xFF)
            numBits += 8
        }
        while (numBits >= 5) {
            val top5 = ((bits shr (numBits - 5)) and 0x1F).toInt()
            if (top5 <= 0x02) {
                sb.append('0' + top5)
                numBits -= 5
                continue
            }
            if (numBits < 6) break
            val top6 = ((bits shr (numBits - 6)) and 0x3F).toInt()
            if (top6 in 0x19..0x1F) {
                val digit = top6 - 0x19 + 3
                sb.append('0' + digit)
                numBits -= 6
                continue
            }
            break
        }
        return sb.toString()
    }

    // =========================================================================
    // gRPC / protobuf framing
    // =========================================================================

    /** Encodes a `Hunk` protobuf message with `bytes data = 1`. */
    private fun encodeHunk(data: ByteArray): ByteArray {
        val varint = varintEncode(data.size.toLong())
        val out = ByteArray(1 + varint.size + data.size)
        out[0] = 0x0A  // (field 1 << 3) | wire type 2 (length-delimited)
        System.arraycopy(varint, 0, out, 1, varint.size)
        System.arraycopy(data, 0, out, 1 + varint.size, data.size)
        return out
    }

    /** Wraps a protobuf message in the 5-byte gRPC length prefix. */
    private fun wrapGrpcMessage(message: ByteArray): ByteArray {
        val out = ByteArray(5 + message.size)
        out[0] = 0x00 // no compression
        val len = message.size
        out[1] = ((len shr 24) and 0xFF).toByte()
        out[2] = ((len shr 16) and 0xFF).toByte()
        out[3] = ((len shr 8) and 0xFF).toByte()
        out[4] = (len and 0xFF).toByte()
        System.arraycopy(message, 0, out, 5, message.size)
        return out
    }

    private fun varintEncode(value: Long): ByteArray {
        val out = mutableListOf<Byte>()
        var v = value
        while (v >= 0x80L) {
            out.add(((v and 0x7FL) or 0x80L).toByte())
            v = v ushr 7
        }
        out.add(v.toByte())
        return out.toByteArray()
    }

    /** Returns (value, bytesConsumed) or null if truncated. */
    private fun varintDecode(data: ByteArray, start: Int): Pair<Long, Int>? {
        var value = 0L
        var shift = 0
        var offset = start
        while (offset < data.size) {
            val b = data[offset].toInt() and 0xFF
            value = value or ((b and 0x7F).toLong() shl shift)
            offset += 1
            if ((b and 0x80) == 0) return Pair(value, offset - start)
            shift += 7
            if (shift >= 64) return null
        }
        return null
    }

    /**
     * Decodes a `Hunk` / `MultiHunk` protobuf message into concatenated raw bytes. Both
     * messages define `data` as field 1 (wire type 2); a one-element MultiHunk is
     * wire-compatible with a single Hunk.
     */
    private fun decodeHunkPayload(message: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var offset = 0
        while (offset < message.size) {
            val (tag, tagConsumed) = varintDecode(message, offset)
                ?: throw GrpcError.InvalidResponse("truncated protobuf tag")
            offset += tagConsumed
            val fieldNumber = (tag ushr 3).toInt()
            val wireType = (tag and 0x07L).toInt()

            when (wireType) {
                2 -> {
                    val (length, lenConsumed) = varintDecode(message, offset)
                        ?: throw GrpcError.InvalidResponse("truncated protobuf length")
                    offset += lenConsumed
                    val lenInt = length.toInt()
                    if (offset + lenInt > message.size) {
                        throw GrpcError.InvalidResponse("truncated protobuf value")
                    }
                    if (fieldNumber == 1) {
                        out.write(message, offset, lenInt)
                    }
                    offset += lenInt
                }
                0 -> {
                    val (_, vConsumed) = varintDecode(message, offset)
                        ?: throw GrpcError.InvalidResponse("truncated varint field")
                    offset += vConsumed
                }
                5 -> {
                    if (offset + 4 > message.size) {
                        throw GrpcError.InvalidResponse("truncated fixed32 field")
                    }
                    offset += 4
                }
                1 -> {
                    if (offset + 8 > message.size) {
                        throw GrpcError.InvalidResponse("truncated fixed64 field")
                    }
                    offset += 8
                }
                else -> throw GrpcError.InvalidResponse("unknown protobuf wire type $wireType")
            }
        }
        return out.toByteArray()
    }

    // =========================================================================
    // HTTP/2 DATA send (respects flow control)
    // =========================================================================

    /**
     * Sends [data] as one or more HTTP/2 DATA frames on the gRPC stream, respecting peer
     * flow control. If the window fills, the remainder waits for a WINDOW_UPDATE.
     */
    private suspend fun sendH2Data(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val (nextOffset, frames) = lock.withLock {
                if (h2StreamClosed) throw GrpcError.ConnectionClosed()
                val window = minOf(h2PeerConnectionWindow, h2PeerStreamSendWindow)
                if (window <= 0) return@withLock Pair(offset, ByteArray(0))

                val maxSize = h2MaxFrameSize
                var cur = offset
                var windowRemaining = window
                var framesBuf = ByteArray(0)
                while (cur < data.size) {
                    val remaining = data.size - cur
                    val chunkSize = minOf(remaining, minOf(maxSize, windowRemaining))
                    if (chunkSize <= 0) break
                    val chunk = data.copyOfRange(cur, cur + chunkSize)
                    framesBuf += buildH2Frame(H2_FRAME_DATA, 0, STREAM_ID, chunk)
                    cur += chunkSize
                    windowRemaining -= chunkSize
                }
                val totalSent = window - windowRemaining
                h2PeerConnectionWindow -= totalSent
                h2PeerStreamSendWindow -= totalSent
                Pair(cur, framesBuf)
            }

            if (frames.isEmpty()) {
                awaitFlowResumption()
                continue
            }
            try {
                transportSend(frames)
            } catch (e: Throwable) {
                lock.withLock { h2StreamClosed = true }
                throw e
            }
            offset = nextOffset
        }
    }

    private suspend fun awaitFlowResumption() {
        suspendCancellableCoroutine<Unit> { cont ->
            val added = lock.withLock {
                if (h2StreamClosed || !_isConnected) false
                else {
                    h2FlowResumptions.add(cont)
                    true
                }
            }
            if (!added) {
                if (cont.isActive) cont.resumeWithException(GrpcError.ConnectionClosed())
                return@suspendCancellableCoroutine
            }
            cont.invokeOnCancellation {
                lock.withLock { h2FlowResumptions.remove(cont) }
            }
        }
    }

    // =========================================================================
    // Receive pipeline
    // =========================================================================

    /**
     * Pulls H2 frames until at least one application payload is ready, handling
     * SETTINGS, WINDOW_UPDATE, PING, GOAWAY, RST_STREAM, and trailer HEADERS inline.
     */
    private suspend fun readAndDecode(): ByteArray? {
        while (true) {
            val frame = readH2Frame()
            val isOurStream = frame.streamId == STREAM_ID

            when (frame.type) {
                H2_FRAME_DATA -> {
                    val payload = handleDataFrame(frame, isOurStream)
                    if (payload != null) return payload
                    if (lock.withLock { h2StreamClosed }) return null
                }

                H2_FRAME_HEADERS -> {
                    if (isOurStream) {
                        val endOfStream = (frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0
                        val needsValidate = lock.withLock { !h2ResponseReceived }
                        if (needsValidate) {
                            val rejection = checkH2ResponseStatus(frame.payload)
                            if (rejection != null) {
                                lock.withLock { h2StreamClosed = true }
                                throw GrpcError.InvalidResponse("gRPC response rejected: $rejection")
                            }
                            lock.withLock { h2ResponseReceived = true }
                        }
                        if (endOfStream) {
                            val grpcError = parseGrpcTrailer(frame.payload)
                            val leftover: ByteArray
                            lock.withLock {
                                h2StreamClosed = true
                                leftover = if (decodedBufferLen > 0)
                                    decodedBuffer.copyOfRange(0, decodedBufferLen)
                                else ByteArray(0)
                                decodedBuffer = ByteArray(0); decodedBufferLen = 0
                            }
                            if (grpcError != null) throw grpcError
                            return if (leftover.isEmpty()) null else leftover
                        }
                    }
                }

                H2_FRAME_SETTINGS -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) == 0) {
                        parseH2Settings(frame.payload)
                        val ack = buildH2Frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0u, ByteArray(0))
                        runCatching { transportSend(ack) }
                    }
                }

                H2_FRAME_WINDOW_UPDATE -> handleWindowUpdate(frame)

                H2_FRAME_PING -> {
                    if ((frame.flags.toInt() and H2_FLAG_ACK.toInt()) == 0) {
                        val pong = buildH2Frame(H2_FRAME_PING, H2_FLAG_ACK, 0u, frame.payload)
                        runCatching { transportSend(pong) }
                    }
                }

                H2_FRAME_GOAWAY -> {
                    val leftover: ByteArray
                    lock.withLock {
                        h2StreamClosed = true
                        leftover = if (decodedBufferLen > 0)
                            decodedBuffer.copyOfRange(0, decodedBufferLen)
                        else ByteArray(0)
                        decodedBuffer = ByteArray(0); decodedBufferLen = 0
                    }
                    return if (leftover.isEmpty()) null else leftover
                }

                H2_FRAME_RST_STREAM -> {
                    if (isOurStream) {
                        val leftover: ByteArray
                        lock.withLock {
                            h2StreamClosed = true
                            leftover = if (decodedBufferLen > 0)
                                decodedBuffer.copyOfRange(0, decodedBufferLen)
                            else ByteArray(0)
                            decodedBuffer = ByteArray(0); decodedBufferLen = 0
                        }
                        return if (leftover.isEmpty()) null else leftover
                    }
                }
            }
        }
    }

    /**
     * Appends an incoming DATA frame's payload to the gRPC reassembly buffer, extracts
     * all complete gRPC messages, decodes their Hunk payloads, and returns the resulting
     * bytes. Emits a WINDOW_UPDATE when half the local window has been consumed.
     */
    private suspend fun handleDataFrame(frame: H2Frame, isOurStream: Boolean): ByteArray? {
        val endOfStream = (frame.flags.toInt() and H2_FLAG_END_STREAM.toInt()) != 0

        emitWindowUpdatesIfNeeded(frame.payload.size, isOurStream)

        if (!isOurStream) return null

        val out = java.io.ByteArrayOutputStream()
        var streamClosed = false
        var decodeError: GrpcError? = null

        lock.withLock {
            if (frame.payload.isNotEmpty()) {
                appendToGrpcFrameBuffer(frame.payload)
                if (grpcFrameBufferLen > MAX_GRPC_FRAME_BUFFER_SIZE) {
                    grpcFrameBuffer = ByteArray(0); grpcFrameBufferLen = 0
                    decodeError = GrpcError.InvalidResponse("gRPC frame buffer overflow")
                }
            }

            if (decodeError == null) {
                while (grpcFrameBufferLen >= 5) {
                    val compressed = grpcFrameBuffer[0].toInt() and 0xFF
                    val length = ((grpcFrameBuffer[1].toInt() and 0xFF) shl 24) or
                            ((grpcFrameBuffer[2].toInt() and 0xFF) shl 16) or
                            ((grpcFrameBuffer[3].toInt() and 0xFF) shl 8) or
                            (grpcFrameBuffer[4].toInt() and 0xFF)
                    val total = 5 + length
                    if (grpcFrameBufferLen < total) break

                    val messageData = grpcFrameBuffer.copyOfRange(5, total)
                    val rem = grpcFrameBufferLen - total
                    if (rem > 0) {
                        System.arraycopy(grpcFrameBuffer, total, grpcFrameBuffer, 0, rem)
                    }
                    grpcFrameBufferLen = rem

                    if (compressed != 0) {
                        decodeError = GrpcError.CompressedMessageUnsupported()
                        break
                    }
                    try {
                        val payload = decodeHunkPayload(messageData)
                        if (payload.isNotEmpty()) out.write(payload)
                    } catch (e: GrpcError) {
                        decodeError = e
                        break
                    }
                }
            }

            if (endOfStream) {
                h2StreamClosed = true
                streamClosed = true
            }
        }

        decodeError?.let { throw it }

        val decoded = out.toByteArray()
        if (decoded.isEmpty()) {
            return if (streamClosed) null else null
        }
        return decoded
    }

    private fun appendToGrpcFrameBuffer(data: ByteArray) {
        val needed = grpcFrameBufferLen + data.size
        if (needed > grpcFrameBuffer.size) {
            val newCap = maxOf(needed, grpcFrameBuffer.size * 2, 4096)
            grpcFrameBuffer = grpcFrameBuffer.copyOf(newCap)
        }
        System.arraycopy(data, 0, grpcFrameBuffer, grpcFrameBufferLen, data.size)
        grpcFrameBufferLen += data.size
    }

    /** Emits connection- and stream-level WINDOW_UPDATE frames once half the local window
     *  has been consumed, to batch flow-control updates. */
    private suspend fun emitWindowUpdatesIfNeeded(receivedBytes: Int, onOurStream: Boolean) {
        if (receivedBytes <= 0) return

        val (connInc, streamInc) = lock.withLock {
            h2ConnectionReceiveConsumed += receivedBytes
            if (onOurStream) h2StreamReceiveConsumed += receivedBytes
            val threshold = h2LocalWindowSize / 2
            val cInc = if (h2ConnectionReceiveConsumed >= threshold) {
                val v = h2ConnectionReceiveConsumed
                h2ConnectionReceiveConsumed = 0
                v
            } else 0
            val sInc = if (onOurStream && h2StreamReceiveConsumed >= threshold) {
                val v = h2StreamReceiveConsumed
                h2StreamReceiveConsumed = 0
                v
            } else 0
            Pair(cInc, sInc)
        }

        var updates = ByteArray(0)
        if (connInc > 0) {
            val p = byteArrayOf(
                ((connInc shr 24) and 0xFF).toByte(),
                ((connInc shr 16) and 0xFF).toByte(),
                ((connInc shr 8) and 0xFF).toByte(),
                (connInc and 0xFF).toByte()
            )
            updates += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, 0u, p)
        }
        if (streamInc > 0) {
            val p = byteArrayOf(
                ((streamInc shr 24) and 0xFF).toByte(),
                ((streamInc shr 16) and 0xFF).toByte(),
                ((streamInc shr 8) and 0xFF).toByte(),
                (streamInc and 0xFF).toByte()
            )
            updates += buildH2Frame(H2_FRAME_WINDOW_UPDATE, 0, STREAM_ID, p)
        }
        if (updates.isNotEmpty()) {
            runCatching { transportSend(updates) }
        }
    }

    // =========================================================================
    // Keepalive
    // =========================================================================

    private fun startKeepaliveIfNeeded() {
        val interval = configuration.idleTimeout
        if (interval <= 0) return
        lock.withLock {
            if (keepaliveJob != null) return
            keepaliveJob = keepaliveScope.launch {
                while (true) {
                    delay(interval * 1000L)
                    val closed = lock.withLock { h2StreamClosed }
                    if (closed) return@launch
                    // 8-byte opaque PING payload.
                    val ping = buildH2Frame(
                        H2_FRAME_PING, 0, 0u,
                        byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0)
                    )
                    runCatching { transportSend(ping) }
                }
            }
        }
    }

    // =========================================================================
    // gRPC trailer + HPACK decoder (minimal)
    // =========================================================================

    /** Returns a [GrpcError.CallFailed] on non-OK grpc-status, or null otherwise. */
    private fun parseGrpcTrailer(payload: ByteArray): GrpcError? {
        val headers = decodeHpackHeaders(payload)
        val statusStr = headers["grpc-status"] ?: return null
        val status = statusStr.toIntOrNull() ?: return null
        if (status == 0) return null
        return GrpcError.CallFailed(status, grpcStatusName(status), headers["grpc-message"])
    }

    private fun grpcStatusName(code: Int): String = when (code) {
        0 -> "OK"
        1 -> "CANCELLED"
        2 -> "UNKNOWN"
        3 -> "INVALID_ARGUMENT"
        4 -> "DEADLINE_EXCEEDED"
        5 -> "NOT_FOUND"
        6 -> "ALREADY_EXISTS"
        7 -> "PERMISSION_DENIED"
        8 -> "RESOURCE_EXHAUSTED"
        9 -> "FAILED_PRECONDITION"
        10 -> "ABORTED"
        11 -> "OUT_OF_RANGE"
        12 -> "UNIMPLEMENTED"
        13 -> "INTERNAL"
        14 -> "UNAVAILABLE"
        15 -> "DATA_LOSS"
        16 -> "UNAUTHENTICATED"
        else -> "UNKNOWN($code)"
    }

    /**
     * Minimal HPACK decoder for server trailers. Handles indexed / literal with both
     * Huffman and plain string encodings. Enough of the static table is included to
     * resolve common trailer names; dynamic-table entries are decoded as "literal with
     * incremental indexing" but not stored.
     */
    private fun decodeHpackHeaders(payload: ByteArray): Map<String, String> {
        val headers = HashMap<String, String>()
        var offset = 0
        while (offset < payload.size) {
            val b = payload[offset].toInt() and 0xFF
            when {
                (b and 0x80) != 0 -> {
                    val (idx, consumed) = decodeHpackInteger(payload, offset, 7)
                    offset += consumed
                    val entry = staticTableEntry(idx)
                    if (entry != null && entry.second != null) {
                        headers[entry.first] = entry.second!!
                    }
                }
                (b and 0xC0) == 0x40 -> {
                    val (nameIdx, nameConsumed) = decodeHpackInteger(payload, offset, 6)
                    offset += nameConsumed
                    val name: String = if (nameIdx == 0) {
                        val r = decodeHpackString(payload, offset) ?: return headers
                        offset += r.second
                        r.first
                    } else {
                        staticTableEntry(nameIdx)?.first ?: ""
                    }
                    val v = decodeHpackString(payload, offset) ?: return headers
                    offset += v.second
                    if (name.isNotEmpty()) headers[name.lowercase()] = v.first
                }
                (b and 0xE0) == 0x20 -> {
                    val (_, consumed) = decodeHpackInteger(payload, offset, 5)
                    offset += consumed
                }
                (b and 0xF0) == 0x00 || (b and 0xF0) == 0x10 -> {
                    val (nameIdx, nameConsumed) = decodeHpackInteger(payload, offset, 4)
                    offset += nameConsumed
                    val name: String = if (nameIdx == 0) {
                        val r = decodeHpackString(payload, offset) ?: return headers
                        offset += r.second
                        r.first
                    } else {
                        staticTableEntry(nameIdx)?.first ?: ""
                    }
                    val v = decodeHpackString(payload, offset) ?: return headers
                    offset += v.second
                    if (name.isNotEmpty()) headers[name.lowercase()] = v.first
                }
                else -> return headers
            }
        }
        return headers
    }

    private fun decodeHpackInteger(data: ByteArray, start: Int, prefixBits: Int): Pair<Int, Int> {
        val maxPrefix = (1 shl prefixBits) - 1
        if (start >= data.size) return Pair(0, 0)
        val first = data[start].toInt() and maxPrefix
        if (first < maxPrefix) return Pair(first, 1)
        var value = maxPrefix
        var m = 0
        var offset = start + 1
        while (offset < data.size) {
            val b = data[offset].toInt() and 0xFF
            value += (b and 0x7F) shl m
            offset += 1
            m += 7
            if ((b and 0x80) == 0) return Pair(value, offset - start)
            if (m >= 64) return Pair(value, offset - start)
        }
        return Pair(value, offset - start)
    }

    private fun decodeHpackString(data: ByteArray, start: Int): Pair<String, Int>? {
        if (start >= data.size) return null
        val meta = data[start].toInt() and 0xFF
        val isHuffman = (meta and 0x80) != 0
        val (length, lenConsumed) = decodeHpackInteger(data, start, 7)
        val bytesStart = start + lenConsumed
        if (bytesStart + length > data.size) return null
        val bytes = data.copyOfRange(bytesStart, bytesStart + length)
        val s = if (isHuffman) huffmanDecode(bytes) ?: "" else String(bytes, Charsets.UTF_8)
        return Pair(s, lenConsumed + length)
    }

    private fun staticTableEntry(index: Int): Pair<String, String?>? = when (index) {
        1 -> Pair(":authority", null)
        2 -> Pair(":method", "GET")
        3 -> Pair(":method", "POST")
        4 -> Pair(":path", "/")
        5 -> Pair(":path", "/index.html")
        6 -> Pair(":scheme", "http")
        7 -> Pair(":scheme", "https")
        8 -> Pair(":status", "200")
        9 -> Pair(":status", "204")
        10 -> Pair(":status", "206")
        11 -> Pair(":status", "304")
        12 -> Pair(":status", "400")
        13 -> Pair(":status", "404")
        14 -> Pair(":status", "500")
        28 -> Pair("content-length", null)
        31 -> Pair("content-type", null)
        58 -> Pair("user-agent", null)
        else -> null
    }

    private fun huffmanDecode(data: ByteArray): String? {
        val out = java.io.ByteArrayOutputStream()
        var code: Long = 0
        var bits = 0
        for (byte in data) {
            code = (code shl 8) or (byte.toLong() and 0xFF)
            bits += 8
            while (bits >= 5) {
                var matched = false
                val maxLen = minOf(bits, 30)
                for (length in 5..maxLen) {
                    val candidate = (code ushr (bits - length)) and ((1L shl length) - 1)
                    val symbol = HUFFMAN_TABLE[HuffmanKey(candidate, length)]
                    if (symbol != null) {
                        if (symbol == 256) return String(out.toByteArray(), Charsets.UTF_8)
                        out.write(symbol and 0xFF)
                        bits -= length
                        matched = true
                        break
                    }
                }
                if (!matched) break
            }
        }
        if (bits > 0) {
            val trailing = code and ((1L shl bits) - 1)
            val allOnes = (1L shl bits) - 1
            if (trailing != allOnes) return null
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    // =========================================================================
    // Error payload descriptions
    // =========================================================================

    private fun describeGoaway(payload: ByteArray): String {
        if (payload.size < 8) return "truncated GOAWAY payload"
        val lastStreamId = ((payload[0].toInt() and 0xFF) shl 24) or
                ((payload[1].toInt() and 0xFF) shl 16) or
                ((payload[2].toInt() and 0xFF) shl 8) or
                (payload[3].toInt() and 0xFF)
        val errorCode = ((payload[4].toInt() and 0xFF) shl 24) or
                ((payload[5].toInt() and 0xFF) shl 16) or
                ((payload[6].toInt() and 0xFF) shl 8) or
                (payload[7].toInt() and 0xFF)
        val debug = if (payload.size > 8) {
            ", debug=" + String(
                payload.copyOfRange(8, payload.size),
                Charsets.UTF_8
            )
        } else ""
        return "${h2ErrorCodeName(errorCode)}, lastStreamId=${lastStreamId and 0x7FFFFFFF}$debug"
    }

    private fun describeRstStream(payload: ByteArray): String {
        if (payload.size < 4) return "truncated RST_STREAM payload"
        val code = ((payload[0].toInt() and 0xFF) shl 24) or
                ((payload[1].toInt() and 0xFF) shl 16) or
                ((payload[2].toInt() and 0xFF) shl 8) or
                (payload[3].toInt() and 0xFF)
        return h2ErrorCodeName(code)
    }

    private fun h2ErrorCodeName(code: Int): String = when (code) {
        0x00 -> "NO_ERROR"
        0x01 -> "PROTOCOL_ERROR"
        0x02 -> "INTERNAL_ERROR"
        0x03 -> "FLOW_CONTROL_ERROR"
        0x04 -> "SETTINGS_TIMEOUT"
        0x05 -> "STREAM_CLOSED"
        0x06 -> "FRAME_SIZE_ERROR"
        0x07 -> "REFUSED_STREAM"
        0x08 -> "CANCEL"
        0x09 -> "COMPRESSION_ERROR"
        0x0A -> "CONNECT_ERROR"
        0x0B -> "ENHANCE_YOUR_CALM"
        0x0C -> "INADEQUATE_SECURITY"
        0x0D -> "HTTP_1_1_REQUIRED"
        else -> "UNKNOWN($code)"
    }

    // =========================================================================
    // Constants + static tables
    // =========================================================================

    companion object {
        /** HTTP/2 connection preface (RFC 7540 §3.5). */
        private val H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.UTF_8)

        private const val H2_FRAME_HEADER_SIZE = 9

        private const val H2_FRAME_DATA: Byte = 0x00
        private const val H2_FRAME_HEADERS: Byte = 0x01
        private const val H2_FRAME_RST_STREAM: Byte = 0x03
        private const val H2_FRAME_SETTINGS: Byte = 0x04
        private const val H2_FRAME_PING: Byte = 0x06
        private const val H2_FRAME_GOAWAY: Byte = 0x07
        private const val H2_FRAME_WINDOW_UPDATE: Byte = 0x08

        private const val H2_FLAG_END_STREAM: Byte = 0x01
        private const val H2_FLAG_END_HEADERS: Byte = 0x04
        private const val H2_FLAG_ACK: Byte = 0x01

        /** Stream ID for the bidirectional gRPC call. RFC 7540 §5.1.1: clients use odd IDs,
         *  first client-initiated stream is always 1. */
        private val STREAM_ID: UInt = 1u

        private const val H2_STREAM_WINDOW_SIZE: Int = 4_194_304   // 4 MB
        private const val H2_CONN_WINDOW_SIZE: Int = 1_073_741_824 // 1 GB

        private const val MAX_H2_READ_BUFFER_SIZE: Int = 2_097_152     // 2 MB
        private const val MAX_GRPC_FRAME_BUFFER_SIZE: Int = 16_777_216 // 16 MB

        /** Default User-Agent for the gRPC request. Falls back to a Chrome UA so the
         *  traffic blends with normal H2 clients. */
        private val DEFAULT_USER_AGENT: String
            get() = com.argsment.anywhere.vpn.protocol.ProxyUserAgent.chrome

        // -- HPACK Huffman table (RFC 7541 Appendix B); only used when decoding trailers. --
        private data class HuffmanKey(val code: Long, val length: Int)

        private val HUFFMAN_TABLE: Map<HuffmanKey, Int> = buildMap {
            val entries = arrayOf(
                intArrayOf(0x1ff8, 13, 0), intArrayOf(0x7fffd8, 23, 1),
                intArrayOf(0xfffffe2, 28, 2), intArrayOf(0xfffffe3, 28, 3),
                intArrayOf(0xfffffe4, 28, 4), intArrayOf(0xfffffe5, 28, 5),
                intArrayOf(0xfffffe6, 28, 6), intArrayOf(0xfffffe7, 28, 7),
                intArrayOf(0xfffffe8, 28, 8), intArrayOf(0xffffea, 24, 9),
                intArrayOf(0x3ffffffc, 30, 10), intArrayOf(0xfffffe9, 28, 11),
                intArrayOf(0xfffffea, 28, 12), intArrayOf(0x3ffffffd, 30, 13),
                intArrayOf(0xfffffeb, 28, 14), intArrayOf(0xfffffec, 28, 15),
                intArrayOf(0xfffffed, 28, 16), intArrayOf(0xfffffee, 28, 17),
                intArrayOf(0xfffffef, 28, 18), intArrayOf(0xffffff0, 28, 19),
                intArrayOf(0xffffff1, 28, 20), intArrayOf(0xffffff2, 28, 21),
                intArrayOf(0x3ffffffe, 30, 22), intArrayOf(0xffffff3, 28, 23),
                intArrayOf(0xffffff4, 28, 24), intArrayOf(0xffffff5, 28, 25),
                intArrayOf(0xffffff6, 28, 26), intArrayOf(0xffffff7, 28, 27),
                intArrayOf(0xffffff8, 28, 28), intArrayOf(0xffffff9, 28, 29),
                intArrayOf(0xffffffa, 28, 30), intArrayOf(0xffffffb, 28, 31),
                intArrayOf(0x14, 6, 32), intArrayOf(0x3f8, 10, 33),
                intArrayOf(0x3f9, 10, 34), intArrayOf(0xffa, 12, 35),
                intArrayOf(0x1ff9, 13, 36), intArrayOf(0x15, 6, 37),
                intArrayOf(0xf8, 8, 38), intArrayOf(0x7fa, 11, 39),
                intArrayOf(0x3fa, 10, 40), intArrayOf(0x3fb, 10, 41),
                intArrayOf(0xf9, 8, 42), intArrayOf(0x7fb, 11, 43),
                intArrayOf(0xfa, 8, 44), intArrayOf(0x16, 6, 45),
                intArrayOf(0x17, 6, 46), intArrayOf(0x18, 6, 47),
                intArrayOf(0x0, 5, 48), intArrayOf(0x1, 5, 49),
                intArrayOf(0x2, 5, 50), intArrayOf(0x19, 6, 51),
                intArrayOf(0x1a, 6, 52), intArrayOf(0x1b, 6, 53),
                intArrayOf(0x1c, 6, 54), intArrayOf(0x1d, 6, 55),
                intArrayOf(0x1e, 6, 56), intArrayOf(0x1f, 6, 57),
                intArrayOf(0x5c, 7, 58), intArrayOf(0xfb, 8, 59),
                intArrayOf(0x7ffc, 15, 60), intArrayOf(0x20, 6, 61),
                intArrayOf(0xffb, 12, 62), intArrayOf(0x3fc, 10, 63),
                intArrayOf(0x1ffa, 13, 64), intArrayOf(0x21, 6, 65),
                intArrayOf(0x5d, 7, 66), intArrayOf(0x5e, 7, 67),
                intArrayOf(0x5f, 7, 68), intArrayOf(0x60, 7, 69),
                intArrayOf(0x61, 7, 70), intArrayOf(0x62, 7, 71),
                intArrayOf(0x63, 7, 72), intArrayOf(0x64, 7, 73),
                intArrayOf(0x65, 7, 74), intArrayOf(0x66, 7, 75),
                intArrayOf(0x67, 7, 76), intArrayOf(0x68, 7, 77),
                intArrayOf(0x69, 7, 78), intArrayOf(0x6a, 7, 79),
                intArrayOf(0x6b, 7, 80), intArrayOf(0x6c, 7, 81),
                intArrayOf(0x6d, 7, 82), intArrayOf(0x6e, 7, 83),
                intArrayOf(0x6f, 7, 84), intArrayOf(0x70, 7, 85),
                intArrayOf(0x71, 7, 86), intArrayOf(0x72, 7, 87),
                intArrayOf(0xfc, 8, 88), intArrayOf(0x73, 7, 89),
                intArrayOf(0xfd, 8, 90), intArrayOf(0x1ffb, 13, 91),
                intArrayOf(0x7fff0, 19, 92), intArrayOf(0x1ffc, 13, 93),
                intArrayOf(0x3ffc, 14, 94), intArrayOf(0x22, 6, 95),
                intArrayOf(0x7ffd, 15, 96), intArrayOf(0x3, 5, 97),
                intArrayOf(0x23, 6, 98), intArrayOf(0x4, 5, 99),
                intArrayOf(0x24, 6, 100), intArrayOf(0x5, 5, 101),
                intArrayOf(0x25, 6, 102), intArrayOf(0x26, 6, 103),
                intArrayOf(0x27, 6, 104), intArrayOf(0x6, 5, 105),
                intArrayOf(0x74, 7, 106), intArrayOf(0x75, 7, 107),
                intArrayOf(0x28, 6, 108), intArrayOf(0x29, 6, 109),
                intArrayOf(0x2a, 6, 110), intArrayOf(0x7, 5, 111),
                intArrayOf(0x2b, 6, 112), intArrayOf(0x76, 7, 113),
                intArrayOf(0x2c, 6, 114), intArrayOf(0x8, 5, 115),
                intArrayOf(0x9, 5, 116), intArrayOf(0x2d, 6, 117),
                intArrayOf(0x77, 7, 118), intArrayOf(0x78, 7, 119),
                intArrayOf(0x79, 7, 120), intArrayOf(0x7a, 7, 121),
                intArrayOf(0x7b, 7, 122), intArrayOf(0x7ffe, 15, 123),
                intArrayOf(0x7fc, 11, 124), intArrayOf(0x3ffd, 14, 125),
                intArrayOf(0x1ffd, 13, 126), intArrayOf(0xffffffc, 28, 127),
                intArrayOf(0x3fffffff, 30, 256)  // EOS
            )
            for (e in entries) {
                put(HuffmanKey(e[0].toLong() and 0xFFFFFFFFL, e[1]), e[2])
            }
        }
    }
}
