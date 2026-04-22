package com.argsment.anywhere.vpn.protocol.trojan

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.vpn.protocol.TunneledTransport
import com.argsment.anywhere.vpn.protocol.tls.TlsClient
import com.argsment.anywhere.vpn.protocol.tls.TlsError
import com.argsment.anywhere.vpn.protocol.tls.TlsRecordConnection
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.NioSocket
import kotlinx.coroutines.delay

private val logger = AnywhereLogger("TrojanClient")

/**
 * Client for establishing Trojan proxy connections.
 *
 * Trojan mandates TLS on the wire; the server inspects the SHA224 hash of
 * the password and falls back to its decoy HTTP site for anything that
 * doesn't match, so there is no plaintext or Reality variant. UDP rides the
 * same TLS stream via [TrojanUdpConnection]'s per-packet framing.
 * Mux is not supported.
 *
 * Retry logic: 5 attempts with linear backoff 0/200/400/600/800ms (matches
 * [com.argsment.anywhere.vpn.protocol.vless.VlessClient]).
 */
class TrojanClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: VlessConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): VlessConnection {
        val password = requirePassword()
        val tlsConfig = requireTls()

        val tlsConn = connectTls(tlsConfig)
        val trojan = TrojanConnection(tlsConn, password, destinationHost, destinationPort)
        if (initialData != null && initialData.isNotEmpty()) {
            trojan.send(initialData)
        }
        return trojan
    }

    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): VlessConnection {
        val password = requirePassword()
        val tlsConfig = requireTls()

        val tlsConn = connectTls(tlsConfig)
        return TrojanUdpConnection(tlsConn, password, destinationHost, destinationPort)
    }

    private fun requirePassword(): String {
        val password = configuration.trojanPassword
        if (password.isNullOrEmpty()) {
            throw ProxyError.ProtocolError("Trojan password not set")
        }
        return password
    }

    private fun requireTls(): TlsConfiguration {
        return configuration.trojanTls
            ?: throw ProxyError.ProtocolError("Trojan requires TLS configuration")
    }

    /**
     * Opens the mandatory TLS tunnel. Direct dials retry with linear backoff
     * matching the VLESS client; chained dials bubble the first failure up so
     * the enclosing chain driver can rebuild the upstream tunnel.
     */
    private suspend fun connectTls(tlsConfig: TlsConfiguration): TlsRecordConnection {
        if (tunnel != null) {
            val tlsClient = TlsClient(tlsConfig)
            return tlsClient.connect(TunneledTransport(tunnel))
        }

        var lastError: Exception? = null
        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (attempt > 0) delay(RETRY_BASE_DELAY_MS * attempt)
            try {
                val tlsClient = TlsClient(tlsConfig)
                return tlsClient.connect(
                    configuration.serverAddress,
                    configuration.serverPort.toInt()
                )
            } catch (e: Exception) {
                if (e is TlsError.CertificateValidationFailed) throw e
                logger.debug("Trojan TLS attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }
}
