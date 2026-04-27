package com.argsment.anywhere.vpn.protocol.grpc

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.TlsConfiguration

/**
 * Helpers shared by gRPC transport callers. The actual connection establishment
 * lives inline in the outer protocol client (e.g. `VlessClient.connectWithGrpc`)
 * so gRPC retries/cleanup follow the same patterns as the other transports.
 */
object GrpcClient {

    /** Returns a TLS configuration with ALPN forced to `h2` (gRPC requires HTTP/2). */
    fun sanitizedTlsConfiguration(base: TlsConfiguration): TlsConfiguration =
        TlsConfiguration(
            serverName = base.serverName,
            alpn = listOf("h2"),
            allowInsecure = base.allowInsecure,
            fingerprint = base.fingerprint,
            minVersion = base.minVersion,
            maxVersion = base.maxVersion
        )

    /**
     * Resolves the HTTP/2 `:authority` value from the proxy configuration, consulting
     * the gRPC override, the TLS SNI, the Reality server name, and finally the server
     * address.
     */
    fun resolveAuthority(
        grpc: GrpcConfiguration,
        configuration: ProxyConfiguration
    ): String = grpc.resolvedAuthority(
        tlsServerName = configuration.tls?.serverName,
        realityServerName = configuration.reality?.serverName,
        serverAddress = configuration.serverAddress
    )
}
