package com.argsment.anywhere.vpn.protocol.naive

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.naive.http11.Http11Connection
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2Connection
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import java.io.ByteArrayOutputStream
import kotlin.random.Random

private val logger = AnywhereLogger("NaiveProxy")

/**
 * Abstraction over the underlying HTTP connection used for a CONNECT tunnel.
 *
 * Implemented by [Http11Tunnel] and [Http2Tunnel].
 * [NaiveProxyConnection] uses this to send/receive data regardless of HTTP version.
 */
interface NaiveTunnel {
    val isConnected: Boolean
    val negotiatedPaddingType: NaivePaddingNegotiator.PaddingType
    suspend fun openTunnel()
    suspend fun sendData(data: ByteArray)
    suspend fun receiveData(): ByteArray?
    fun close()
}

/** Wraps [Http11Connection] as a [NaiveTunnel]. */
class Http11Tunnel(private val connection: Http11Connection) : NaiveTunnel {
    override val isConnected: Boolean get() = connection.isConnected
    override val negotiatedPaddingType get() = connection.negotiatedPaddingType
    override suspend fun openTunnel() = connection.openTunnel()
    override suspend fun sendData(data: ByteArray) = connection.sendData(data)
    override suspend fun receiveData(): ByteArray? = connection.receiveData()
    override fun close() = connection.close()
}

/** Wraps [Http2Connection] as a [NaiveTunnel]. */
class Http2Tunnel(private val connection: Http2Connection) : NaiveTunnel {
    override val isConnected: Boolean get() = connection.isConnected
    override val negotiatedPaddingType get() = connection.negotiatedPaddingType
    override suspend fun openTunnel() = connection.openTunnel()
    override suspend fun sendData(data: ByteArray) = connection.sendData(data)
    override suspend fun receiveData(): ByteArray? = connection.receiveData()
    override fun close() = connection.close()
}

/**
 * VlessConnection subclass that wraps a [NaiveTunnel] with NaiveProxy padding framing.
 *
 * Supports HTTP/1.1 and HTTP/2 tunnels through the [NaiveTunnel] protocol.
 * Applies NaivePaddingFramer on the first 8 reads and writes when the server negotiates
 * variant-1 padding. After 8 frames, data passes through unframed.
 *
 * For the "server" direction (client→server), payloads < 100 bytes get biased padding
 * [255-len, 255] and medium payloads (400–1024 bytes) are split into 200–300 byte chunks.
 * The "client" direction (server→client) uses uniform random padding [0, 255].
 */
class NaiveProxyConnection(
    private val tunnel: NaiveTunnel,
    private val paddingType: NaivePaddingNegotiator.PaddingType
) : VlessConnection() {

    init {
        responseHeaderReceived = true // No VLESS response header
    }

    private val paddingFramer = NaivePaddingFramer()

    override val isConnected: Boolean get() = tunnel.isConnected

    // -- Send --

    override suspend fun sendRaw(data: ByteArray) {
        if (paddingFramer.isWritePaddingActive && paddingType == NaivePaddingNegotiator.PaddingType.VARIANT1) {
            // Fragment medium payloads (400–1024 bytes) into 200–300 byte chunks
            if (data.size in 400..1024) {
                sendFragmented(data, 0)
                return
            }
            val paddingSize = generateSendPaddingSize(data.size)
            val framed = paddingFramer.write(data, paddingSize)
            tunnel.sendData(framed)
        } else {
            tunnel.sendData(data)
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        // NaiveProxy is fully suspend-based; fire-and-forget not supported.
        // This path should not be reached in normal operation.
        logger.warning("sendRawAsync called on NaiveProxyConnection, dropping ${data.size} bytes")
    }

    /** Fragments medium payloads into 200–300 byte chunks, each padded separately. */
    private suspend fun sendFragmented(data: ByteArray, offset: Int) {
        if (offset >= data.size) return

        // Stop fragmenting if we've exhausted padding frames
        if (!paddingFramer.isWritePaddingActive) {
            tunnel.sendData(data.copyOfRange(offset, data.size))
            return
        }

        val remaining = data.size - offset
        val chunkSize = if (remaining <= 300) remaining else Random.nextInt(200, 301)
        val chunk = data.copyOfRange(offset, offset + chunkSize)
        val paddingSize = generateSendPaddingSize(chunk.size)
        val framed = paddingFramer.write(chunk, paddingSize)

        tunnel.sendData(framed)
        sendFragmented(data, offset + chunkSize)
    }

    // -- Receive --

    override suspend fun receiveRaw(): ByteArray? {
        val data = tunnel.receiveData() ?: return null
        if (data.isEmpty()) return null

        if (paddingFramer.isReadPaddingActive && paddingType == NaivePaddingNegotiator.PaddingType.VARIANT1) {
            val output = ByteArrayOutputStream()
            val payloadBytes = paddingFramer.read(data, output)
            return if (payloadBytes > 0) {
                output.toByteArray()
            } else {
                // Pure-padding frame (0 payload bytes) — re-read
                receiveRaw()
            }
        } else {
            return data
        }
    }

    // -- Cancel --

    override fun cancel() {
        tunnel.close()
    }

    // -- Padding Size Generation --

    companion object {
        /**
         * Generates padding size for the send (client→server) direction.
         *
         * Small payloads (< 100 bytes) get biased padding [255-len, 255] to obscure size.
         * All other payloads get uniform random padding [0, 255].
         */
        fun generateSendPaddingSize(payloadSize: Int): Int {
            return if (payloadSize < 100) {
                Random.nextInt(255 - payloadSize, 256)
            } else {
                Random.nextInt(0, 256)
            }
        }
    }
}
