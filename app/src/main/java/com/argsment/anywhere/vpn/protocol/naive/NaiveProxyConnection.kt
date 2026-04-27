package com.argsment.anywhere.vpn.protocol.naive

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.naive.http11.Http11Connection
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2Connection
import java.io.ByteArrayOutputStream
import kotlin.random.Random

private val logger = AnywhereLogger("NaiveProxy")

/** Abstraction over the underlying HTTP connection used for a CONNECT tunnel. */
interface NaiveTunnel {
    val isConnected: Boolean
    val negotiatedPaddingType: NaivePaddingNegotiator.PaddingType
    suspend fun openTunnel()
    suspend fun sendData(data: ByteArray)
    suspend fun receiveData(): ByteArray?
    fun close()
}

class Http11Tunnel(private val connection: Http11Connection) : NaiveTunnel {
    override val isConnected: Boolean get() = connection.isConnected
    override val negotiatedPaddingType get() = connection.negotiatedPaddingType
    override suspend fun openTunnel() = connection.openTunnel()
    override suspend fun sendData(data: ByteArray) = connection.sendData(data)
    override suspend fun receiveData(): ByteArray? = connection.receiveData()
    override fun close() = connection.close()
}

class Http2Tunnel(private val connection: Http2Connection) : NaiveTunnel {
    override val isConnected: Boolean get() = connection.isConnected
    override val negotiatedPaddingType get() = connection.negotiatedPaddingType
    override suspend fun openTunnel() = connection.openTunnel()
    override suspend fun sendData(data: ByteArray) = connection.sendData(data)
    override suspend fun receiveData(): ByteArray? = connection.receiveData()
    override fun close() = connection.close()
}

/**
 * Wraps a [NaiveTunnel] with NaiveProxy padding framing on the first 8 reads/writes
 * when the server negotiates variant-1 padding; afterward data passes through unframed.
 *
 * Client→server: payloads < 100 bytes use biased padding [255-len, 255]; payloads of
 * 400–1024 bytes are split into 200–300 byte chunks. Server→client: uniform random
 * padding [0, 255].
 */
class NaiveProxyConnection(
    private val tunnel: NaiveTunnel,
    private val paddingType: NaivePaddingNegotiator.PaddingType
) : ProxyConnection() {

    private val paddingFramer = NaivePaddingFramer()

    override val isConnected: Boolean get() = tunnel.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (paddingFramer.isWritePaddingActive && paddingType == NaivePaddingNegotiator.PaddingType.VARIANT1) {
            if (data.size in 400..1024) {
                sendFragmented(data, 0)
                return
            }
            // Padding framer encodes payload length in a 16-bit field — payloads
            // larger than 65535 bytes would silently truncate the high byte and
            // desync the receiver. Cap and recursively send the remainder.
            if (data.size > MAX_PADDING_PAYLOAD) {
                sendRaw(data.copyOfRange(0, MAX_PADDING_PAYLOAD))
                sendRaw(data.copyOfRange(MAX_PADDING_PAYLOAD, data.size))
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
        // NaiveProxy is fully suspend-based; fire-and-forget is not supported.
        logger.warning("sendRawAsync called on NaiveProxyConnection, dropping ${data.size} bytes")
    }

    private suspend fun sendFragmented(data: ByteArray, offset: Int) {
        if (offset >= data.size) return

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

    override suspend fun receiveRaw(): ByteArray? {
        val data = tunnel.receiveData() ?: return null
        if (data.isEmpty()) return null

        if (paddingFramer.isReadPaddingActive && paddingType == NaivePaddingNegotiator.PaddingType.VARIANT1) {
            val output = ByteArrayOutputStream()
            val payloadBytes = paddingFramer.read(data, output)
            return if (payloadBytes > 0) {
                output.toByteArray()
            } else {
                // Pure-padding frame — re-read for actual payload
                receiveRaw()
            }
        } else {
            return data
        }
    }

    override fun cancel() {
        tunnel.close()
    }

    companion object {
        /** Max bytes per padded frame (16-bit length field in the framer header). */
        private const val MAX_PADDING_PAYLOAD = 65535

        /**
         * Send-direction padding size. Small payloads (< 100 bytes) get biased padding
         * [255-len, 255] to obscure size; larger payloads get uniform random [0, 255].
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
