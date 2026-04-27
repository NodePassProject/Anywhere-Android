package com.argsment.anywhere.vpn.protocol

import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.naive.NaiveClient
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksClient
import com.argsment.anywhere.vpn.protocol.socks5.SocksClient
import com.argsment.anywhere.vpn.protocol.trojan.TrojanClient
import com.argsment.anywhere.vpn.protocol.vless.VlessClient

/** Factory for creating proxy connections based on protocol configuration. */
object ProxyClientFactory {

    suspend fun connect(
        config: ProxyConfiguration,
        host: String,
        port: Int,
        initialData: ByteArray? = null,
        tunnel: ProxyConnection? = null
    ): ProxyConnection {
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.TROJAN -> TrojanClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SHADOWSOCKS -> ShadowsocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SOCKS5 -> SocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 ->
                NaiveClient(config, tunnel).connect(host, port, initialData)
        }
    }

    /**
     * Shadowsocks UDP is intentionally absent — it never reaches the chain
     * path because [com.argsment.anywhere.vpn.LwipUdpFlow] routes SS UDP
     * through the shared per-config session (see
     * [com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksUdpSession]).
     * NaiveProxy / HTTP doesn't carry UDP at all.
     */
    suspend fun connectUDP(
        config: ProxyConfiguration,
        host: String,
        port: Int,
        tunnel: ProxyConnection? = null
    ): ProxyConnection {
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.TROJAN -> TrojanClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.SOCKS5 -> SocksClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> throw ProxyError.Dropped()
            OutboundProtocol.SHADOWSOCKS -> throw ProxyError.ProtocolError(
                "UDP not supported through TCP factory for Shadowsocks"
            )
        }
    }
}
