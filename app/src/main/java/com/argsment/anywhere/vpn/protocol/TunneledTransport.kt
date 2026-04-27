package com.argsment.anywhere.vpn.protocol

/**
 * Adapts a [ProxyConnection] (from a previous chain link) to the [Transport] interface.
 * Sends and receives use the raw (unframed) methods to bypass the tunnel's traffic
 * statistics, since each chain link tracks its own stats.
 */
class TunneledTransport(private val tunnel: ProxyConnection) : Transport {

    override suspend fun send(data: ByteArray) = tunnel.sendRaw(data)

    override fun sendAsync(data: ByteArray) = tunnel.sendRawAsync(data)

    override suspend fun receive(): ByteArray? = tunnel.receiveRaw()

    override fun forceCancel() = tunnel.cancel()
}
