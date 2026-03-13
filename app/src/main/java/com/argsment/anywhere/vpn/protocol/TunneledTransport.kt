package com.argsment.anywhere.vpn.protocol

import com.argsment.anywhere.vpn.protocol.vless.VlessConnection

/**
 * Adapts a [VlessConnection] (from a previous chain link) to the [Transport] interface.
 *
 * Used for proxy chaining: the output of one proxy connection becomes the "socket" for the next.
 * Sends and receives use the raw (unframed) methods to bypass the tunnel's traffic statistics,
 * since each chain link tracks its own stats.
 */
class TunneledTransport(private val tunnel: VlessConnection) : Transport {

    override suspend fun send(data: ByteArray) = tunnel.sendRaw(data)

    override fun sendAsync(data: ByteArray) = tunnel.sendRawAsync(data)

    override suspend fun receive(): ByteArray? = tunnel.receiveRaw()

    override fun forceCancel() = tunnel.cancel()
}
