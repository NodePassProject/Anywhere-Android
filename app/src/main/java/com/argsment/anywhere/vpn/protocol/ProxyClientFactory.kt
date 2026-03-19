package com.argsment.anywhere.vpn.protocol

import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.naive.NaiveClient
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksClient
import com.argsment.anywhere.vpn.protocol.vless.VlessClient
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection

/**
 * Factory for creating proxy connections based on protocol configuration.
 *
 * Centralizes protocol selection (VLESS, Shadowsocks, NaiveProxy) that was
 * previously inline in LwipTcpConnection and LwipUdpFlow.
 */
object ProxyClientFactory {

    /**
     * Creates a TCP proxy connection using the appropriate protocol client.
     *
     * @param config The proxy configuration determining protocol and settings.
     * @param host The destination host to connect to.
     * @param port The destination port to connect to.
     * @param initialData Optional data to send immediately after connection.
     * @param tunnel Optional existing connection to tunnel through (for proxy chaining).
     * @return A [VlessConnection] wrapping the protocol-specific connection.
     */
    suspend fun connect(
        config: ProxyConfiguration,
        host: String,
        port: Int,
        initialData: ByteArray? = null,
        tunnel: VlessConnection? = null
    ): VlessConnection {
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SHADOWSOCKS -> ShadowsocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2, OutboundProtocol.NAIVE_HTTP3 ->
                NaiveClient(config, tunnel).connect(host, port, initialData)
        }
    }

    /**
     * Creates a UDP proxy connection using the appropriate protocol client.
     * Note: NaiveProxy does not support UDP.
     *
     * @param config The proxy configuration determining protocol and settings.
     * @param host The destination host to connect to.
     * @param port The destination port to connect to.
     * @return A [VlessConnection] wrapping the protocol-specific UDP connection.
     */
    suspend fun connectUDP(
        config: ProxyConfiguration,
        host: String,
        port: Int,
        tunnel: VlessConnection? = null
    ): VlessConnection {
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.SHADOWSOCKS -> ShadowsocksClient(config, tunnel).connectUDP(host, port)
            else -> throw IllegalArgumentException("UDP not supported for ${config.outboundProtocol.displayName}")
        }
    }
}
