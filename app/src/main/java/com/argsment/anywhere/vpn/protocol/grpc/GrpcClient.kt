package com.argsment.anywhere.vpn.protocol.grpc

import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.TlsConfiguration

/**
 * Helpers shared by gRPC transport callers. Mirrors the pieces of iOS
 * `ProxyClient+GRPC` that don't belong to the per-connection state machine.
 *
 * The actual connection establishment lives inline in the outer protocol client
 * (e.g. `VlessClient.connectWithGrpc`) so gRPC retries/cleanup follow the same
 * patterns as the other transports (`ws`, `httpupgrade`, `xhttp`).
 */
object GrpcClient {

    /**
     * Returns a TLS configuration to use for gRPC: ALPN forced to `h2` because gRPC
     * requires HTTP/2. Mirrors iOS `sanitizedGRPCTLSConfiguration(from:)`.
     */
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
     * address. Mirrors iOS `GRPCConfiguration.resolvedAuthority`.
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
