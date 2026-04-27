package com.argsment.anywhere.vpn.protocol.direct

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.NioSocket
import com.argsment.anywhere.vpn.util.NioSocketError

private val logger = AnywhereLogger("DirectTCP")

/** Direct TCP relay over NioSocket. */
class DirectTcpRelay {

    private val socket = NioSocket()

    @Volatile
    private var cancelled = false

    suspend fun connect(host: String, port: Int) {
        socket.connect(host, port)
    }

    /** Returns received bytes, null on EOF, throws on error. */
    suspend fun receive(): ByteArray? {
        if (cancelled) throw NioSocketError.NotConnected()
        return socket.receive()
    }

    suspend fun send(data: ByteArray) {
        if (cancelled) throw NioSocketError.NotConnected()
        socket.send(data)
    }

    fun cancel() {
        if (cancelled) return
        cancelled = true
        socket.forceCancel()
    }
}
