package com.argsment.anywhere.vpn

import java.net.DatagramSocket
import java.net.Socket

/**
 * Singleton interface for protecting outbound sockets from VPN routing.
 *
 * On Android, outgoing sockets used by protocol code (VLESS, direct relay, etc.)
 * must be "protected" via VpnService.protect() so traffic doesn't loop back
 * through the TUN interface.
 *
 * Usage:
 *   SocketProtector.setProtector(...)   // set in AnywhereVpnService
 *   SocketProtector.protect(socket)     // call from protocol code
 */
object SocketProtector {

    @Volatile
    private var fdProtector: ((Int) -> Boolean)? = null

    @Volatile
    private var socketProtector: ((Socket) -> Boolean)? = null

    @Volatile
    private var datagramProtector: ((DatagramSocket) -> Boolean)? = null

    /** Register the VPN service's protect functions. Called when VPN starts. */
    fun setProtector(
        fdFn: (Int) -> Boolean,
        socketFn: (Socket) -> Boolean,
        datagramFn: (DatagramSocket) -> Boolean
    ) {
        fdProtector = fdFn
        socketProtector = socketFn
        datagramProtector = datagramFn
    }

    /** Unregister. Called when VPN stops. */
    fun clearProtector() {
        fdProtector = null
        socketProtector = null
        datagramProtector = null
    }

    /**
     * Protect a socket file descriptor from VPN routing.
     * Returns true on success, false if no protector is registered or protection failed.
     */
    fun protect(fd: Int): Boolean {
        return fdProtector?.invoke(fd) ?: false
    }

    /** Protect a TCP socket from VPN routing. */
    fun protect(socket: Socket): Boolean {
        return socketProtector?.invoke(socket) ?: false
    }

    /** Protect a UDP socket from VPN routing. */
    fun protect(socket: DatagramSocket): Boolean {
        return datagramProtector?.invoke(socket) ?: false
    }
}
