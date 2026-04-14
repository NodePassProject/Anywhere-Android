package com.argsment.anywhere.vpn.protocol.hysteria

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection

/**
 * Adapter exposing Hysteria as a [VlessConnection] producer for the Android
 * proxy stack. Mirrors the Naive/Shadowsocks/SOCKS5 client wrappers so it
 * plugs cleanly into [com.argsment.anywhere.vpn.protocol.ProxyClientFactory].
 *
 * Note: Hysteria uses connection pooling (one QUIC session per proxy), so the
 * `tunnel` parameter (used for in-protocol chaining) is not honored — the
 * QUIC session always runs over the underlying network. Chains where Hysteria
 * is the entry hop are not supported.
 */
class HysteriaClient(
    private val configuration: ProxyConfiguration,
    @Suppress("UNUSED_PARAMETER") tunnel: VlessConnection? = null
) {

    suspend fun connect(
        host: String,
        port: Int,
        initialData: ByteArray? = null
    ): VlessConnection {
        val cfg = buildHysteriaConfiguration()
        val session = HysteriaSessionPool.acquire(cfg)
        val conn = HysteriaConnection(session, formatDestination(host, port))
        conn.open()
        if (initialData != null && initialData.isNotEmpty()) {
            conn.send(initialData)
        }
        return conn
    }

    suspend fun connectUDP(host: String, port: Int): VlessConnection {
        val cfg = buildHysteriaConfiguration()
        val session = HysteriaSessionPool.acquire(cfg)
        val conn = HysteriaUdpConnection(session, formatDestination(host, port))
        conn.open()
        return conn
    }

    private fun buildHysteriaConfiguration(): HysteriaConfiguration {
        val password = configuration.hysteriaPassword
            ?: throw HysteriaError.ConnectionFailed("Hysteria password missing")
        return HysteriaConfiguration(
            proxyHost = configuration.connectAddress,
            proxyPort = configuration.serverPort.toInt(),
            password = password,
            sni = configuration.tls?.serverName?.takeIf { it.isNotBlank() },
            // iOS does not carry a separate client-side download limit — leave
            // it unset so the server is free to choose its send rate.
            clientRxBytesPerSec = 0L,
            uploadMbps = com.argsment.anywhere.data.model.clampHysteriaUploadMbps(
                configuration.hysteriaUploadMbps ?: com.argsment.anywhere.data.model.HysteriaUploadMbpsDefault
            )
        )
    }

    private fun formatDestination(host: String, port: Int): String {
        val bracketed = if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
        return "$bracketed:$port"
    }
}
