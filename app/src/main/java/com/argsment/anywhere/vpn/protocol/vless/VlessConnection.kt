package com.argsment.anywhere.vpn.protocol.vless

import android.util.Log
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.httpupgrade.HttpUpgradeConnection
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.websocket.WebSocketConnection
import com.argsment.anywhere.vpn.protocol.xhttp.XHttpConnection
import com.argsment.anywhere.vpn.util.NioSocket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "VlessConnection"

/**
 * TLS version constants matching TLS protocol version numbers.
 */
enum class TlsVersion(val value: Int) {
    TLS12(0x0303),
    TLS13(0x0304)
}

/**
 * Interface for all VLESS connection types.
 */
interface VlessConnectionProtocol {
    val isConnected: Boolean
    var responseHeaderReceived: Boolean

    suspend fun send(data: ByteArray)
    fun sendAsync(data: ByteArray)
    suspend fun receive(): ByteArray?
    suspend fun startReceiving(handler: suspend (ByteArray) -> Unit, errorHandler: suspend (Exception?) -> Unit)
    fun cancel()
}

/**
 * Abstract base class providing common VLESS connection functionality.
 *
 * Subclasses must override [isConnected], [sendRaw], [sendRawAsync],
 * [receiveRaw], and [cancel].
 */
abstract class VlessConnection : VlessConnectionProtocol {

    override var responseHeaderReceived = false
    private val responseHeaderLock = Any()

    /** The negotiated TLS version of the outer transport, if applicable. */
    open val outerTlsVersion: TlsVersion? get() = null

    // Traffic statistics
    private val _bytesSent = AtomicLong(0)
    private val _bytesReceived = AtomicLong(0)
    val bytesSent: Long get() = _bytesSent.get()
    val bytesReceived: Long get() = _bytesReceived.get()

    // Send
    override suspend fun send(data: ByteArray) {
        _bytesSent.addAndGet(data.size.toLong())
        sendRaw(data)
    }

    override fun sendAsync(data: ByteArray) {
        _bytesSent.addAndGet(data.size.toLong())
        sendRawAsync(data)
    }

    abstract suspend fun sendRaw(data: ByteArray)
    abstract fun sendRawAsync(data: ByteArray)

    // Receive
    override suspend fun receive(): ByteArray? {
        val data = receiveRaw()
        if (data != null && data.isNotEmpty()) {
            _bytesReceived.addAndGet(data.size.toLong())
        }
        return data
    }

    abstract suspend fun receiveRaw(): ByteArray?

    /** Receives raw data without transport decryption (for Vision direct copy mode). */
    open suspend fun receiveDirectRaw(): ByteArray? = receiveRaw()

    /** Sends raw data without transport encryption (for Vision direct copy mode). */
    open suspend fun sendDirectRaw(data: ByteArray) = sendRaw(data)
    open fun sendDirectRawAsync(data: ByteArray) = sendRawAsync(data)

    // Receive loop
    override suspend fun startReceiving(
        handler: suspend (ByteArray) -> Unit,
        errorHandler: suspend (Exception?) -> Unit
    ) {
        try {
            while (true) {
                val data = receive()
                if (data != null && data.isNotEmpty()) {
                    handler(data)
                } else {
                    errorHandler(null)
                    break
                }
            }
        } catch (e: Exception) {
            errorHandler(e)
        }
    }

    // Response header processing
    /**
     * Processes the VLESS response header on first receive.
     * Strips the 2-byte response header and returns the remaining payload.
     */
    suspend fun processResponseHeader(data: ByteArray): ByteArray? {
        val needsHeaderProcessing: Boolean
        synchronized(responseHeaderLock) {
            needsHeaderProcessing = !responseHeaderReceived
            if (needsHeaderProcessing) {
                responseHeaderReceived = true
            }
        }

        if (needsHeaderProcessing) {
            val headerLength = VlessProtocol.decodeResponseHeader(data)
            if (headerLength > 0 && data.size > headerLength) {
                return data.copyOfRange(headerLength, data.size)
            } else if (headerLength > 0) {
                return receive()
            }
        }

        return data
    }
}

// =============================================================================
// VlessDirectConnection
// =============================================================================

/**
 * VLESS connection over a direct NioSocket transport.
 */
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

// =============================================================================
// VlessDirectUdpConnection
// =============================================================================

/**
 * VLESS UDP connection over a direct NioSocket with length-prefixed packets.
 */
class VlessDirectUdpConnection(connection: Transport) : VlessDirectConnection(connection) {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override suspend fun send(data: ByteArray) {
        super.send(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        super.sendAsync(UdpFraming.frame(data))
    }

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = super.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        super.cancel()
    }
}

// =============================================================================
// VlessHttpUpgradeConnection
// =============================================================================

/**
 * VLESS connection over an HttpUpgradeConnection transport.
 */
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

/**
 * VLESS UDP connection over HttpUpgradeConnection with length-prefixed packets.
 */
class VlessHttpUpgradeUdpConnection(
    huConnection: HttpUpgradeConnection
) : VlessHttpUpgradeConnection(huConnection) {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override suspend fun send(data: ByteArray) {
        sendRaw(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        sendRawAsync(UdpFraming.frame(data))
    }

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = super.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        super.cancel()
    }
}

// =============================================================================
// VlessXHttpConnection
// =============================================================================

/**
 * VLESS connection over an XHttpConnection transport.
 */
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

/**
 * VLESS UDP connection over XHttpConnection with length-prefixed packets.
 */
class VlessXHttpUdpConnection(
    xhttpConnection: XHttpConnection
) : VlessXHttpConnection(xhttpConnection) {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override suspend fun send(data: ByteArray) {
        sendRaw(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        sendRawAsync(UdpFraming.frame(data))
    }

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = super.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        super.cancel()
    }
}

// =============================================================================
// VlessTlsConnection
// =============================================================================

/**
 * VLESS connection over a standard TLS TlsRecordConnection transport.
 */
open class VlessTlsConnection(
    private val tlsConnection: TlsRecordConnection
) : VlessConnection() {

    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = (tlsConnection.connection as? NioSocket)?.state == NioSocket.State.READY
            || tlsConnection.connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = tlsConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = tlsConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data: ByteArray?
        try {
            data = tlsConnection.receive()
        } catch (e: Exception) {
            if (e is RealityError.DecryptionFailed) {
                throw e
            }
            throw e
        }
        if (data == null || data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = tlsConnection.cancel()

    override suspend fun receiveDirectRaw(): ByteArray? = tlsConnection.receiveRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = tlsConnection.sendRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = tlsConnection.sendRawAsync(data)
}

/**
 * VLESS UDP connection over TLS with length-prefixed packets.
 */
class VlessTlsUdpConnection(
    tlsConnection: TlsRecordConnection
) : VlessTlsConnection(tlsConnection) {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override suspend fun send(data: ByteArray) {
        sendRaw(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        sendRawAsync(UdpFraming.frame(data))
    }

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = super.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        super.cancel()
    }
}

// =============================================================================
// VlessWebSocketConnection
// =============================================================================

/**
 * VLESS connection over a WebSocketConnection transport.
 */
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

/**
 * VLESS UDP connection over WebSocket with length-prefixed packets.
 */
class VlessWebSocketUdpConnection(
    wsConnection: WebSocketConnection
) : VlessWebSocketConnection(wsConnection) {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override suspend fun send(data: ByteArray) {
        sendRaw(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        sendRawAsync(UdpFraming.frame(data))
    }

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = super.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        super.cancel()
    }
}

// =============================================================================
// VlessRealityConnection
// =============================================================================

/**
 * VLESS connection over a Reality TlsRecordConnection transport.
 */
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
        val data: ByteArray?
        try {
            data = realityConnection.receive()
        } catch (e: Exception) {
            // Pass through decryption failures with raw data for Vision direct copy mode
            if (e is RealityError.DecryptionFailed) {
                throw e
            }
            throw e
        }
        if (data == null || data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = realityConnection.cancel()

    override suspend fun receiveDirectRaw(): ByteArray? = realityConnection.receiveRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = realityConnection.sendRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = realityConnection.sendRawAsync(data)
}

/**
 * VLESS UDP connection over Reality with length-prefixed packets.
 */
class VlessRealityUdpConnection(
    realityConnection: TlsRecordConnection
) : VlessRealityConnection(realityConnection) {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override suspend fun send(data: ByteArray) {
        sendRaw(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        sendRawAsync(UdpFraming.frame(data))
    }

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = super.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        super.cancel()
    }
}

// =============================================================================
// Reality Error types (forward declaration for use in this file)
// =============================================================================

sealed class RealityError(message: String) : Exception(message) {
    class DecryptionFailed(val rawData: ByteArray? = null) : RealityError("Reality decryption failed")
    class HandshakeFailed(msg: String) : RealityError("Reality handshake failed: $msg")
    class InvalidResponse(msg: String) : RealityError("Reality invalid response: $msg")
    class AuthenticationFailed : RealityError("Reality server authentication failed")
}
