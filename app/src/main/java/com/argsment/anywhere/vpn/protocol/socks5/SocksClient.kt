package com.argsment.anywhere.vpn.protocol.socks5

import android.util.Log
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.SocketProtector
import com.argsment.anywhere.vpn.protocol.ProxyClientFactory
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.delay
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

private const val TAG = "SocksClient"

// =============================================================================
// SOCKS5 Protocol Constants
// =============================================================================

private object Socks5 {
    const val VERSION: Byte = 0x05
    const val AUTH_NONE: Byte = 0x00
    const val AUTH_PASSWORD: Byte = 0x02
    const val AUTH_NO_MATCH: Byte = 0xFF.toByte()
    const val CMD_CONNECT: Byte = 0x01
    const val CMD_UDP_ASSOCIATE: Byte = 0x03
    const val ADDR_IPV4: Byte = 0x01
    const val ADDR_DOMAIN: Byte = 0x03
    const val ADDR_IPV6: Byte = 0x04
    const val STATUS_SUCCESS: Byte = 0x00
}

// =============================================================================
// SOCKS5 Read Buffer
// =============================================================================

/**
 * Shared read buffer for the SOCKS5 handshake.
 *
 * Reads data from the underlying transport in large chunks and serves exact byte counts
 * from its internal buffer. Any bytes remaining after the handshake belong to the
 * tunneled data stream and are preserved via [remaining].
 *
 * Mirrors iOS `SOCKS5Buffer`.
 */
private class Socks5Buffer(private val transport: Transport) {
    private var buffer: ByteArray = ByteArray(0)

    /** Reads exactly [count] bytes from the transport, buffering any extra data. */
    suspend fun readExact(count: Int): ByteArray {
        while (buffer.size < count) {
            val chunk = transport.receive()
                ?: throw ProxyError.ProtocolError("SOCKS5 server closed during handshake")
            if (chunk.isEmpty()) {
                throw ProxyError.ProtocolError("SOCKS5 server returned empty read")
            }
            buffer = buffer + chunk
        }
        val out = buffer.copyOfRange(0, count)
        buffer = if (buffer.size == count) ByteArray(0) else buffer.copyOfRange(count, buffer.size)
        return out
    }

    /** Returns any data left in the buffer after the handshake completes (or null if empty). */
    val remaining: ByteArray?
        get() = if (buffer.isEmpty()) null else buffer
}

// =============================================================================
// SOCKS5 Handshake
// =============================================================================

/**
 * Performs the SOCKS5 client handshake (greeting, optional auth, CONNECT or UDP ASSOCIATE).
 *
 * Mirrors iOS `SOCKS5Handshake`, which itself matches Xray-core's `ClientHandshake`.
 */
private object Socks5Handshake {

    /** Result of a UDP ASSOCIATE handshake containing the relay endpoint. */
    data class UdpRelayInfo(val host: String, val port: Int)

    /**
     * Performs a TCP CONNECT handshake. On success, the transport is ready to carry
     * the tunneled stream (any leftover bytes are returned in [Socks5Buffer.remaining]).
     */
    suspend fun performConnect(
        buffer: Socks5Buffer,
        transport: Transport,
        destinationHost: String,
        destinationPort: Int,
        username: String?,
        password: String?
    ) {
        performAuth(buffer, transport, username, password)
        sendCommand(
            buffer = buffer,
            transport = transport,
            command = Socks5.CMD_CONNECT,
            host = destinationHost,
            port = destinationPort
        )
    }

    /**
     * Performs a UDP ASSOCIATE handshake. RFC 1928 specifies that the client sends
     * 0.0.0.0:0 in the request; the server responds with the relay endpoint where
     * UDP packets should be sent.
     */
    suspend fun performUdpAssociate(
        buffer: Socks5Buffer,
        transport: Transport,
        username: String?,
        password: String?,
        serverAddress: String
    ): UdpRelayInfo {
        performAuth(buffer, transport, username, password)
        val info = sendCommand(
            buffer = buffer,
            transport = transport,
            command = Socks5.CMD_UDP_ASSOCIATE,
            host = "0.0.0.0",
            port = 0
        )
        // Always use the server's public address for the relay host -- servers
        // typically return their local/private IP which is unreachable from the client.
        return UdpRelayInfo(serverAddress, info.port)
    }

    // -- Authentication --

    private suspend fun performAuth(
        buffer: Socks5Buffer,
        transport: Transport,
        username: String?,
        password: String?
    ) {
        val hasAuth = username != null && password != null
        val authMethod = if (hasAuth) Socks5.AUTH_PASSWORD else Socks5.AUTH_NONE
        val greeting = byteArrayOf(Socks5.VERSION, 0x01, authMethod)

        transport.send(greeting)
        val resp = buffer.readExact(2)

        if (resp[0] != Socks5.VERSION) {
            throw ProxyError.ProtocolError("SOCKS5 unexpected server version: ${resp[0]}")
        }
        val expected = if (hasAuth) Socks5.AUTH_PASSWORD else Socks5.AUTH_NONE
        if (resp[1] != expected) {
            throw if (resp[1] == Socks5.AUTH_NO_MATCH) {
                ProxyError.ProtocolError("SOCKS5 server: no matching auth method")
            } else {
                ProxyError.ProtocolError("SOCKS5 auth method mismatch: expected $expected, got ${resp[1]}")
            }
        }

        if (hasAuth) {
            sendAuth(buffer, transport, username!!, password!!)
        }
    }

    /** RFC 1929 username/password sub-negotiation. */
    private suspend fun sendAuth(
        buffer: Socks5Buffer,
        transport: Transport,
        username: String,
        password: String
    ) {
        val userBytes = username.toByteArray(Charsets.UTF_8)
        val passBytes = password.toByteArray(Charsets.UTF_8)
        val userLen = minOf(userBytes.size, 255)
        val passLen = minOf(passBytes.size, 255)

        val out = ByteArray(3 + userLen + passLen)
        out[0] = 0x01 // sub-negotiation version
        out[1] = userLen.toByte()
        System.arraycopy(userBytes, 0, out, 2, userLen)
        out[2 + userLen] = passLen.toByte()
        System.arraycopy(passBytes, 0, out, 3 + userLen, passLen)

        transport.send(out)
        val resp = buffer.readExact(2)
        if (resp[1].toInt() != 0x00) {
            throw ProxyError.ProtocolError("SOCKS5 authentication failed (status ${resp[1]})")
        }
    }

    // -- Command (CONNECT / UDP ASSOCIATE) --

    private suspend fun sendCommand(
        buffer: Socks5Buffer,
        transport: Transport,
        command: Byte,
        host: String,
        port: Int
    ): UdpRelayInfo {
        val addr = encodeAddress(host)
        val request = ByteArray(3 + addr.size + 2)
        request[0] = Socks5.VERSION
        request[1] = command
        request[2] = 0x00 // reserved
        System.arraycopy(addr, 0, request, 3, addr.size)
        request[3 + addr.size] = ((port shr 8) and 0xFF).toByte()
        request[4 + addr.size] = (port and 0xFF).toByte()

        transport.send(request)
        return readCommandResponse(buffer)
    }

    /** Reads `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`. */
    private suspend fun readCommandResponse(buffer: Socks5Buffer): UdpRelayInfo {
        val head = buffer.readExact(4)
        if (head[1] != Socks5.STATUS_SUCCESS) {
            throw ProxyError.ProtocolError("SOCKS5 command failed (reply ${head[1]})")
        }
        return when (head[3]) {
            Socks5.ADDR_IPV4 -> {
                val a = buffer.readExact(4 + 2)
                val ip = "${a[0].toInt() and 0xFF}.${a[1].toInt() and 0xFF}." +
                         "${a[2].toInt() and 0xFF}.${a[3].toInt() and 0xFF}"
                val port = ((a[4].toInt() and 0xFF) shl 8) or (a[5].toInt() and 0xFF)
                UdpRelayInfo(ip, port)
            }
            Socks5.ADDR_IPV6 -> {
                val a = buffer.readExact(16 + 2)
                val parts = (0 until 16 step 2).map { i ->
                    String.format("%x", ((a[i].toInt() and 0xFF) shl 8) or (a[i + 1].toInt() and 0xFF))
                }
                val ip = parts.joinToString(":")
                val port = ((a[16].toInt() and 0xFF) shl 8) or (a[17].toInt() and 0xFF)
                UdpRelayInfo(ip, port)
            }
            Socks5.ADDR_DOMAIN -> {
                val len = buffer.readExact(1)[0].toInt() and 0xFF
                val a = buffer.readExact(len + 2)
                val domain = String(a, 0, len, Charsets.UTF_8)
                val port = ((a[len].toInt() and 0xFF) shl 8) or (a[len + 1].toInt() and 0xFF)
                UdpRelayInfo(domain, port)
            }
            else -> throw ProxyError.ProtocolError("SOCKS5 unknown address type: ${head[3]}")
        }
    }

    // -- Address Encoding --

    /** Encodes a host as a SOCKS5 address: `[ATYP, ADDR...]`. */
    fun encodeAddress(host: String): ByteArray {
        parseIPv4(host)?.let { return byteArrayOf(Socks5.ADDR_IPV4) + it }
        parseIPv6(host)?.let { return byteArrayOf(Socks5.ADDR_IPV6) + it }
        val domainBytes = host.toByteArray(Charsets.UTF_8)
        val len = minOf(domainBytes.size, 255)
        val out = ByteArray(2 + len)
        out[0] = Socks5.ADDR_DOMAIN
        out[1] = len.toByte()
        System.arraycopy(domainBytes, 0, out, 2, len)
        return out
    }

    private fun parseIPv4(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            out[i] = v.toByte()
        }
        return out
    }

    private fun parseIPv6(s: String): ByteArray? {
        val host = if (s.startsWith("[") && s.endsWith("]")) s.substring(1, s.length - 1) else s
        if (!host.contains(':')) return null
        return try {
            val addr = InetAddress.getByName(host)
            if (addr.address.size == 16) addr.address else null
        } catch (_: Exception) {
            null
        }
    }
}

// =============================================================================
// Buffer-Prefix Transport
// =============================================================================

/**
 * Wraps a [Transport] so that any leftover bytes from the SOCKS5 handshake buffer
 * are delivered on the first `receive()` call before falling through to the underlying
 * transport. Mirrors iOS `SOCKS5Transport`.
 */
private class BufferedPrefixTransport(
    private val inner: Transport,
    private var initialData: ByteArray?
) : Transport {

    override suspend fun send(data: ByteArray) = inner.send(data)
    override fun sendAsync(data: ByteArray) = inner.sendAsync(data)

    override suspend fun receive(): ByteArray? {
        val pending = initialData
        if (pending != null) {
            initialData = null
            return pending
        }
        return inner.receive()
    }

    override fun forceCancel() = inner.forceCancel()
}

// =============================================================================
// SocksTcpConnection
// =============================================================================

/**
 * SOCKS5 TCP connection. After the SOCKS5 handshake, the underlying transport
 * is a transparent byte stream — no per-message header processing.
 */
class SocksTcpConnection(private val transport: Transport) : VlessConnection() {

    init {
        // SOCKS5 has no response header, so we never need to strip one.
        responseHeaderReceived = true
    }

    override val isConnected: Boolean
        get() = (transport as? NioSocket)?.state == NioSocket.State.READY || transport !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = transport.send(data)
    override fun sendRawAsync(data: ByteArray) = transport.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = transport.receive() ?: return null
        if (data.isEmpty()) return null
        return data
    }

    override fun cancel() = transport.forceCancel()
}

// =============================================================================
// SocksUdpConnection
// =============================================================================

/**
 * SOCKS5 UDP ASSOCIATE relay connection.
 *
 * Wraps a [DatagramSocket] connected to the relay address. Outgoing packets are
 * prefixed with the SOCKS5 UDP header (`RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT`),
 * and incoming packets have the header stripped.
 *
 * Holds the TCP control connection open for the lifetime of the UDP session.
 *
 * Mirrors iOS `SOCKS5UDPProxyConnection`.
 */
class SocksUdpConnection(
    private val tcpTransport: Transport,
    private val udpSocket: DatagramSocket,
    destinationHost: String,
    destinationPort: Int
) : VlessConnection() {

    private val udpHeader: ByteArray
    @Volatile private var cancelled = false

    init {
        responseHeaderReceived = true
        // Pre-build the SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT
        val addr = Socks5Handshake.encodeAddress(destinationHost)
        udpHeader = ByteArray(3 + addr.size + 2).also {
            it[0] = 0x00; it[1] = 0x00; it[2] = 0x00
            System.arraycopy(addr, 0, it, 3, addr.size)
            it[3 + addr.size] = ((destinationPort shr 8) and 0xFF).toByte()
            it[4 + addr.size] = (destinationPort and 0xFF).toByte()
        }
    }

    override val isConnected: Boolean get() = !cancelled && udpSocket.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (cancelled) throw ProxyError.ConnectionFailed("SOCKS5 UDP not connected")
        val packet = udpHeader + data
        try {
            udpSocket.send(DatagramPacket(packet, packet.size))
        } catch (e: Exception) {
            throw ProxyError.ConnectionFailed("SOCKS5 UDP send failed: ${e.message}")
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        if (cancelled) return
        try {
            val packet = udpHeader + data
            udpSocket.send(DatagramPacket(packet, packet.size))
        } catch (_: Exception) {
            // Best-effort fire-and-forget
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        while (!cancelled) {
            val buffer = ByteArray(65536)
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                udpSocket.receive(packet)
            } catch (e: Exception) {
                if (cancelled) return null
                throw ProxyError.ConnectionFailed("SOCKS5 UDP receive failed: ${e.message}")
            }
            val payload = stripUdpHeader(buffer.copyOfRange(0, packet.length)) ?: continue
            return payload
        }
        return null
    }

    override fun cancel() {
        if (cancelled) return
        cancelled = true
        try { udpSocket.close() } catch (_: Exception) {}
        tcpTransport.forceCancel()
    }

    /** Strips the SOCKS5 UDP header from a received packet, returning the payload. */
    private fun stripUdpHeader(data: ByteArray): ByteArray? {
        if (data.size < 4) return null
        if (data[2].toInt() != 0x00) return null // reject fragments

        val headerEnd: Int = when (data[3]) {
            Socks5.ADDR_IPV4 -> 4 + 4 + 2
            Socks5.ADDR_IPV6 -> 4 + 16 + 2
            Socks5.ADDR_DOMAIN -> {
                if (data.size < 5) return null
                4 + 1 + (data[4].toInt() and 0xFF) + 2
            }
            else -> return null
        }

        if (data.size <= headerEnd) return null
        return data.copyOfRange(headerEnd, data.size)
    }
}

// =============================================================================
// SocksClient
// =============================================================================

/**
 * Client for establishing SOCKS5 proxy connections (TCP CONNECT or UDP ASSOCIATE).
 *
 * Supports proxy chaining via [tunnel] and the same retry policy as [VlessClient]
 * (5 attempts, linear backoff 0/200/400/600/800 ms, matching Xray-core).
 *
 * Mirrors iOS `SOCKS5Connection.swift` (handshake, buffer, UDP proxy connection).
 */
class SocksClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: VlessConnection? = null
) {

    private var connection: NioSocket? = null
    private var tunnelTransport: TunneledTransport? = null

    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    /** Connects to a destination via the SOCKS5 server using TCP CONNECT. */
    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): VlessConnection {
        var lastError: Exception? = null
        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }
            try {
                val transport = openTransport()
                val buffer = Socks5Buffer(transport)
                Socks5Handshake.performConnect(
                    buffer = buffer,
                    transport = transport,
                    destinationHost = destinationHost,
                    destinationPort = destinationPort,
                    username = configuration.socks5Username,
                    password = configuration.socks5Password
                )

                // Wrap the transport with any leftover handshake bytes so they are
                // delivered to the tunneled stream on the first receive() call.
                val streamTransport = BufferedPrefixTransport(transport, buffer.remaining)
                val conn = SocksTcpConnection(streamTransport)

                if (initialData != null && initialData.isNotEmpty()) {
                    conn.send(initialData)
                }
                return conn
            } catch (e: Exception) {
                Log.w(TAG, "SOCKS5 connect attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: ProxyError.ConnectionFailed("All SOCKS5 retry attempts failed")
    }

    /** Connects to a destination via the SOCKS5 server using UDP ASSOCIATE. */
    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): VlessConnection {
        var lastError: Exception? = null
        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) {
                cleanupRetryResources()
                delay(RETRY_BASE_DELAY_MS * attempt)
            }
            try {
                val transport = openTransport()
                val buffer = Socks5Buffer(transport)
                val relay = Socks5Handshake.performUdpAssociate(
                    buffer = buffer,
                    transport = transport,
                    username = configuration.socks5Username,
                    password = configuration.socks5Password,
                    serverAddress = configuration.connectAddress
                )

                // Open and protect a UDP socket to the relay endpoint.
                val socket = DatagramSocket()
                if (!SocketProtector.protect(socket)) {
                    socket.close()
                    throw ProxyError.ConnectionFailed("Failed to protect SOCKS5 UDP socket")
                }
                try {
                    socket.connect(InetSocketAddress(relay.host, relay.port))
                } catch (e: Exception) {
                    socket.close()
                    throw ProxyError.ConnectionFailed("Failed to connect SOCKS5 UDP relay: ${e.message}")
                }

                return SocksUdpConnection(
                    tcpTransport = transport,
                    udpSocket = socket,
                    destinationHost = destinationHost,
                    destinationPort = destinationPort
                )
            } catch (e: Exception) {
                Log.w(TAG, "SOCKS5 UDP attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: ProxyError.ConnectionFailed("All SOCKS5 UDP retry attempts failed")
    }

    /** Cancels the connection and releases all resources. */
    fun cancel() {
        connection?.forceCancel()
        connection = null
        tunnelTransport = null
    }

    private fun cleanupRetryResources() {
        connection?.forceCancel()
        connection = null
        tunnelTransport = null
    }

    /** Opens a Transport to the SOCKS5 server, either via tunnel or a direct TCP socket. */
    private suspend fun openTransport(): Transport {
        if (tunnel != null) {
            return TunneledTransport(tunnel).also { tunnelTransport = it }
        }
        val socket = NioSocket()
        connection = socket
        socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
        return socket
    }
}
