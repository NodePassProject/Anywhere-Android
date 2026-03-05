package com.argsment.anywhere.vpn.protocol.direct

import android.util.Log
import com.argsment.anywhere.vpn.util.NioSocket
import com.argsment.anywhere.vpn.util.NioSocketError

private const val TAG = "DirectTCP"

/**
 * Direct TCP relay over NioSocket.
 * connect/receive/send/cancel.
 */
class DirectTcpRelay {

    private val socket = NioSocket()

    @Volatile
    private var cancelled = false

    /**
     * Connects to the destination host:port.
     */
    suspend fun connect(host: String, port: Int) {
        socket.connect(host, port)
    }

    /**
     * Receives up to 64KB from the socket.
     *
     * Returns:
     * - ByteArray: data received
     * - null: EOF (remote closed)
     * Throws on error.
     */
    suspend fun receive(): ByteArray? {
        if (cancelled) throw NioSocketError.NotConnected()
        return socket.receive()
    }

    /**
     * Sends data to the destination.
     */
    suspend fun send(data: ByteArray) {
        if (cancelled) throw NioSocketError.NotConnected()
        socket.send(data)
    }

    /**
     * Cancels the relay and closes the socket.
     */
    fun cancel() {
        if (cancelled) return
        cancelled = true
        socket.forceCancel()
    }
}
