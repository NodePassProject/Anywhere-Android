package com.argsment.anywhere.vpn.protocol.vless

import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.grpc.GrpcConnection
import com.argsment.anywhere.vpn.protocol.httpupgrade.HttpUpgradeConnection
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.websocket.WebSocketConnection
import com.argsment.anywhere.vpn.protocol.xhttp.XHttpConnection
import com.argsment.anywhere.vpn.util.NioSocket

/**
 * Base for VLESS connections; strips the 2-byte response header
 * (`version` + `addonsLength`) from the first stream bytes. Header bytes are
 * buffered across reads so transports that deliver fragmented headers
 * (WebSocket, XHTTP, HTTP/2) work correctly.
 */
abstract class VlessConnection : ProxyConnection() {

    var responseHeaderReceived = false
    private val responseHeaderLock = Any()
    private var pendingResponseHeaderBuffer: ByteArray = ByteArray(0)

    /**
     * Returns payload with any VLESS response header stripped. If the current
     * read contained only header bytes, recursively reads more rather than
     * returning early (otherwise the caller would see EOF).
     */
    suspend fun processResponseHeader(data: ByteArray): ByteArray? {
        var output: ByteArray? = null
        var shouldReceiveMore = false

        synchronized(responseHeaderLock) {
            if (responseHeaderReceived) {
                output = data
            } else {
                val combined = if (pendingResponseHeaderBuffer.isEmpty()) {
                    data
                } else {
                    pendingResponseHeaderBuffer + data
                }

                when {
                    combined.size < 2 -> {
                        pendingResponseHeaderBuffer = combined
                        shouldReceiveMore = true
                    }
                    combined[0] != VlessProtocol.VERSION -> {
                        // No VLESS response header — deliver all buffered bytes as payload.
                        responseHeaderReceived = true
                        output = combined
                        pendingResponseHeaderBuffer = ByteArray(0)
                    }
                    else -> {
                        val addonsLength = combined[1].toInt() and 0xFF
                        val headerLength = 2 + addonsLength
                        if (combined.size < headerLength) {
                            pendingResponseHeaderBuffer = combined
                            shouldReceiveMore = true
                        } else {
                            responseHeaderReceived = true
                            if (combined.size > headerLength) {
                                output = combined.copyOfRange(headerLength, combined.size)
                            } else {
                                shouldReceiveMore = true
                            }
                            pendingResponseHeaderBuffer = ByteArray(0)
                        }
                    }
                }
            }
        }

        return when {
            output != null -> output
            shouldReceiveMore -> receiveRaw()
            else -> data
        }
    }
}

/**
 * Wraps any [ProxyConnection] with VLESS UDP framing: outgoing payloads get a
 * 2-byte big-endian length prefix; the inbound side reassembles length-prefixed
 * packets from the inner connection. The inner connection handles transport
 * concerns (TLS, HTTP upgrade, gRPC, WebSocket) and response-header stripping.
 */
class VlessUdpConnection(private val inner: ProxyConnection) : ProxyConnection() {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override val isConnected: Boolean get() = inner.isConnected
    override val outerTlsVersion: TlsVersion? get() = inner.outerTlsVersion

    override suspend fun send(data: ByteArray) {
        super.send(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        super.sendAsync(UdpFraming.frame(data))
    }

    override suspend fun sendRaw(data: ByteArray) = inner.sendRaw(data)
    override fun sendRawAsync(data: ByteArray) = inner.sendRawAsync(data)

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = inner.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override suspend fun receiveRaw(): ByteArray? = inner.receiveRaw()

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        inner.cancel()
    }
}

open class VlessDirectConnection(val connection: Transport) : VlessConnection() {

    override val isConnected: Boolean
        get() = (connection as? NioSocket)?.state == NioSocket.State.READY || connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) {
        connection.send(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        connection.sendAsync(data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = connection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() {
        connection.forceCancel()
    }
}

open class VlessHttpUpgradeConnection(
    private val huConnection: HttpUpgradeConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = huConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = huConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = huConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = huConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = huConnection.cancel()
}

open class VlessXHttpConnection(
    private val xhttpConnection: XHttpConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = xhttpConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = xhttpConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = xhttpConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = xhttpConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = xhttpConnection.cancel()
}

open class VlessTlsConnection(
    private val tlsConnection: TlsRecordConnection
) : VlessConnection() {

    override val outerTlsVersion: TlsVersion?
        get() = if (tlsConnection.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12

    override val isConnected: Boolean
        get() = (tlsConnection.connection as? NioSocket)?.state == NioSocket.State.READY
            || tlsConnection.connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = tlsConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = tlsConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = tlsConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = tlsConnection.cancel()

    override suspend fun receiveDirectRaw(): ByteArray? = tlsConnection.receiveRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = tlsConnection.sendRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = tlsConnection.sendRawAsync(data)
}

open class VlessWebSocketConnection(
    private val wsConnection: WebSocketConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = wsConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = wsConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = wsConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = wsConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = wsConnection.cancel()
}

open class VlessRealityConnection(
    private val realityConnection: TlsRecordConnection
) : VlessConnection() {

    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = (realityConnection.connection as? NioSocket)?.state == NioSocket.State.READY
            || realityConnection.connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = realityConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = realityConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = realityConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = realityConnection.cancel()

    override suspend fun receiveDirectRaw(): ByteArray? = realityConnection.receiveRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = realityConnection.sendRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = realityConnection.sendRawAsync(data)
}

open class VlessGrpcConnection(
    private val grpcConnection: GrpcConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = grpcConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = grpcConnection.send(data)
    override fun sendRawAsync(data: ByteArray) {
        // gRPC's HTTP/2 send is suspending (flow-control); no non-blocking equivalent
        // exists. Route through the regular path on runBlocking and drop any error —
        // callers handle exceptions on the suspending paths.
        kotlinx.coroutines.runBlocking {
            runCatching { grpcConnection.send(data) }
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = grpcConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = grpcConnection.cancel()
}

sealed class RealityError(message: String) : Exception(message) {
    class DecryptionFailed(val rawData: ByteArray? = null) : RealityError("TLS record decryption failed")
    class HandshakeFailed(msg: String) : RealityError("TLS handshake failed: $msg")
    class InvalidResponse(msg: String) : RealityError("Invalid response: $msg")
    class AuthenticationFailed : RealityError("Reality server authentication failed")
}
