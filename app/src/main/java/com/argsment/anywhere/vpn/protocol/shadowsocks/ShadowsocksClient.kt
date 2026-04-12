package com.argsment.anywhere.vpn.protocol.shadowsocks

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.tls.TlsClient
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.delay

private val logger = AnywhereLogger("ShadowsocksClient")

/**
 * Client for establishing Shadowsocks proxy connections.
 *
 * Supports:
 * - Legacy AEAD ciphers (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)
 * - Shadowsocks 2022 ciphers (2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm)
 * - Optional TLS wrapping
 * - Proxy chaining (tunnel through existing connection)
 *
 * Retry logic: 5 attempts with linear backoff 0/200/400/600/800ms (matching Xray-core).
 */
class ShadowsocksClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: VlessConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    /**
     * Establishes a Shadowsocks TCP connection to the given destination.
     */
    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): VlessConnection {
        val method = configuration.ssMethod
            ?: throw ProxyError.ProtocolError("Shadowsocks method not configured")
        val password = configuration.ssPassword
            ?: throw ProxyError.ProtocolError("Shadowsocks password not configured")

        val cipher = ShadowsocksCipher.fromMethod(method)
            ?: throw ShadowsocksError.InvalidMethod(method)

        var lastError: Exception? = null

        for (attempt in 1..MAX_RETRY_ATTEMPTS) {
            if (attempt > 1) {
                delay(RETRY_BASE_DELAY_MS * (attempt - 1))
            }

            try {
                val transport = connectTransport()
                val addressHeader = ShadowsocksProtocol.buildAddressHeader(destinationHost, destinationPort)

                val connection = if (cipher.isSS2022) {
                    val pskList = ShadowsocksKeyDerivation.decodePSKList(password, cipher.keySize)
                        ?: throw ShadowsocksError.InvalidPSK()
                    Shadowsocks2022Connection(transport, cipher, pskList, addressHeader)
                } else {
                    val masterKey = ShadowsocksKeyDerivation.deriveKey(password, cipher.keySize)
                    ShadowsocksConnection(transport, cipher, masterKey, addressHeader)
                }

                // Send initial data if provided
                if (initialData != null && initialData.isNotEmpty()) {
                    connection.send(initialData)
                }

                return connection
            } catch (e: Exception) {
                if (e is com.argsment.anywhere.vpn.protocol.tls.TlsError.CertificateValidationFailed) throw e
                lastError = e
                logger.debug("Connect attempt $attempt failed: ${e.message}")
            }
        }

        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts exhausted")
    }

    /**
     * Establishes a Shadowsocks UDP connection.
     * Returns a VlessConnection that wraps the transport with per-packet UDP encryption.
     */
    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): VlessConnection {
        val method = configuration.ssMethod
            ?: throw ProxyError.ProtocolError("Shadowsocks method not configured")
        val password = configuration.ssPassword
            ?: throw ProxyError.ProtocolError("Shadowsocks password not configured")

        val cipher = ShadowsocksCipher.fromMethod(method)
            ?: throw ShadowsocksError.InvalidMethod(method)

        val transport = connectTransport()

        return if (cipher.isSS2022) {
            val pskList = ShadowsocksKeyDerivation.decodePSKList(password, cipher.keySize)
                ?: throw ShadowsocksError.InvalidPSK()
            if (cipher.isChaCha) {
                Shadowsocks2022ChaChaUDPConnection(transport, pskList.last(), destinationHost, destinationPort)
            } else {
                Shadowsocks2022AESUDPConnection(transport, cipher, pskList, destinationHost, destinationPort)
            }
        } else {
            val masterKey = ShadowsocksKeyDerivation.deriveKey(password, cipher.keySize)
            ShadowsocksUDPConnection(transport, cipher, masterKey, destinationHost, destinationPort)
        }
    }

    /**
     * Creates a [ShadowsocksUdpRelay] for direct UDP relay.
     * Caller must call connect() on the relay separately.
     */
    fun createUdpRelay(
        destinationHost: String,
        destinationPort: Int
    ): ShadowsocksUdpRelay {
        val method = configuration.ssMethod
            ?: throw ProxyError.ProtocolError("Shadowsocks method not configured")
        val password = configuration.ssPassword
            ?: throw ProxyError.ProtocolError("Shadowsocks password not configured")

        val cipher = ShadowsocksCipher.fromMethod(method)
            ?: throw ShadowsocksError.InvalidMethod(method)

        val mode = if (cipher.isSS2022) {
            val psk = ShadowsocksKeyDerivation.decodePSK(password, cipher.keySize)
                ?: throw ShadowsocksError.InvalidPSK()
            if (cipher.isChaCha) {
                ShadowsocksUdpRelay.Mode.SS2022ChaCha(psk)
            } else {
                ShadowsocksUdpRelay.Mode.SS2022AES(cipher, psk)
            }
        } else {
            val masterKey = ShadowsocksKeyDerivation.deriveKey(password, cipher.keySize)
            ShadowsocksUdpRelay.Mode.Legacy(cipher, masterKey)
        }

        return ShadowsocksUdpRelay(mode, destinationHost, destinationPort)
    }

    fun cancel() {
        // Cancel is handled by the connection itself
    }

    // -- Transport Setup --

    /**
     * Creates the underlying transport — either a direct NioSocket
     * or a tunnel through an existing proxy connection, optionally wrapped with TLS.
     *
     * Uses [ProxyConfiguration.serverAddress] (the domain name) for direct socket
     * connections, matching iOS `ProxyClient.directDialHost` which defaults to
     * `serverAddress`. DNS resolution is handled by [DnsCache] through the
     * underlying physical network, allowing DNS to refresh naturally.
     */
    private suspend fun connectTransport(): Transport {
        val transport: Transport

        if (tunnel != null) {
            transport = TunneledTransport(tunnel)
        } else {
            val socket = NioSocket()
            socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
            transport = socket
        }

        // Optionally wrap with TLS
        if (configuration.tls != null) {
            val tlsClient = TlsClient(configuration.tls)
            val tlsConnection = tlsClient.connect(transport)
            return TlsTransportAdapter(tlsConnection)
        }

        return transport
    }
}

/**
 * Adapts [TlsRecordConnection] to the [Transport] interface for use with Shadowsocks.
 */
private class TlsTransportAdapter(
    private val tls: TlsRecordConnection
) : Transport {
    override suspend fun send(data: ByteArray) = tls.send(data)
    override fun sendAsync(data: ByteArray) = tls.sendAsync(data)
    override suspend fun receive(): ByteArray? = tls.receive()
    override fun forceCancel() = tls.cancel()
}
