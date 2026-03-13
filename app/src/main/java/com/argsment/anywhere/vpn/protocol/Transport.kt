package com.argsment.anywhere.vpn.protocol

/**
 * Raw transport interface for sending and receiving byte data.
 *
 * Implemented by [NioSocket] (direct TCP) and [TunneledTransport] (tunnel through
 * an existing proxy connection). Used by TLS, WebSocket, and other layers as their
 * underlying transport.
 */
interface Transport {
    suspend fun send(data: ByteArray)
    fun sendAsync(data: ByteArray)
    suspend fun receive(): ByteArray?
    fun forceCancel()
}
