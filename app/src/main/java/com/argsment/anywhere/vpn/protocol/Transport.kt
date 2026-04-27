package com.argsment.anywhere.vpn.protocol

/** Raw transport interface for sending and receiving byte data. */
interface Transport {
    suspend fun send(data: ByteArray)
    fun sendAsync(data: ByteArray)
    suspend fun receive(): ByteArray?
    fun forceCancel()
}
