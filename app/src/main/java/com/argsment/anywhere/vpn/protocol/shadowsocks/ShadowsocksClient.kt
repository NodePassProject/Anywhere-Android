package com.argsment.anywhere.vpn.protocol.shadowsocks

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.delay

private val logger = AnywhereLogger("ShadowsocksClient")

/**
 * Shadowsocks proxy client. Supports legacy AEAD ciphers, Shadowsocks 2022, and proxy chaining.
 */
class ShadowsocksClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): ProxyConnection {
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

    fun cancel() {
        // Lifecycle is owned by the returned connection.
    }

    /**
     * Direct NioSocket or a tunnel through an existing proxy connection. Uses
     * [ProxyConfiguration.serverAddress] for the direct socket so DNS refresh
     * happens naturally via [DnsCache].
     */
    private suspend fun connectTransport(): Transport {
        if (tunnel != null) {
            return TunneledTransport(tunnel)
        }

        val socket = NioSocket()
        socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
        return socket
    }
}
