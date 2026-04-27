package com.argsment.anywhere.vpn.protocol.direct

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.SocketProtector
import com.argsment.anywhere.vpn.util.DnsCache
import com.argsment.anywhere.vpn.util.NioSocketError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.CancelledKeyException
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue

private val logger = AnywhereLogger("DirectUDP")

/** Non-blocking connected UDP socket using a shared selector thread. */
class DirectUdpRelay {

    private var channel: DatagramChannel? = null
    @Volatile
    private var selectionKey: SelectionKey? = null
    private var receiveHandler: ((ByteArray) -> Unit)? = null

    @Volatile
    private var cancelled = false

    companion object {
        /** Shared selector for all DirectUdpRelay instances — one thread for all UDP I/O. */
        private val sharedSelector: Selector = Selector.open()
        private val pendingOps = ConcurrentLinkedQueue<() -> Unit>()

        private val selectorThread = Thread({
            val buffer = ByteBuffer.allocate(65536)
            while (true) {
                try {
                    sharedSelector.select(200)

                    while (true) {
                        val op = pendingOps.poll() ?: break
                        try { op() } catch (e: Exception) {
                            logger.warning("Pending op error: ${e.message}")
                        }
                    }

                    val iter = sharedSelector.selectedKeys().iterator()
                    while (iter.hasNext()) {
                        val key = iter.next()
                        iter.remove()
                        if (!key.isValid) continue

                        val relay = key.attachment() as? DirectUdpRelay ?: continue
                        try {
                            if (key.isReadable) {
                                relay.onReadable(key, buffer)
                            }
                        } catch (_: CancelledKeyException) {
                        } catch (e: Exception) {
                            logger.warning("Key handler error: ${e.message}")
                        }
                    }
                } catch (e: Exception) {
                    logger.warning("Selector loop error: ${e.message}")
                }
            }
        }, "DirectUDP-selector").apply { isDaemon = true }

        init { selectorThread.start() }

        private fun runOnSelector(op: () -> Unit) {
            pendingOps.add(op)
            sharedSelector.wakeup()
        }
    }

    suspend fun connect(dstHost: String, dstPort: Int) {
        withContext(Dispatchers.IO) {
            val addresses = try {
                DnsCache.resolveAll(dstHost).mapNotNull { ip ->
                    try { InetAddress.getByName(ip) } catch (_: Exception) { null }
                }
            } catch (e: Exception) {
                throw NioSocketError.ResolutionFailed(e.message ?: "Unknown error")
            }

            if (addresses.isEmpty()) {
                throw NioSocketError.ResolutionFailed("No addresses returned")
            }

            // Prefer IPv4 to avoid timeouts when IPv6 is unreachable
            val sorted = addresses.sortedBy { if (it is Inet4Address) 0 else 1 }

            var lastError: Exception? = null
            for (addr in sorted) {
                try {
                    connectToAddress(InetSocketAddress(addr, dstPort))
                    return@withContext
                } catch (e: Exception) {
                    lastError = e
                }
            }

            throw NioSocketError.ConnectionFailed(lastError?.message ?: "All addresses failed")
        }
    }

    private fun connectToAddress(address: InetSocketAddress) {
        if (cancelled) throw NioSocketError.NotConnected()

        val family = if (address.address is java.net.Inet6Address)
            java.net.StandardProtocolFamily.INET6
        else
            java.net.StandardProtocolFamily.INET
        val ch = DatagramChannel.open(family)
        ch.configureBlocking(false)

        // Protect socket from VPN routing loop BEFORE connect
        if (!SocketProtector.protect(ch.socket())) {
            ch.close()
            throw NioSocketError.ConnectionFailed("Failed to protect UDP socket")
        }

        ch.connect(address)

        if (cancelled) {
            ch.close()
            throw NioSocketError.NotConnected()
        }

        channel = ch
    }

    fun send(data: ByteArray) {
        val ch = channel ?: return
        if (cancelled || !ch.isOpen) return

        try {
            val buffer = ByteBuffer.wrap(data)
            ch.write(buffer)
        } catch (e: Exception) {
            // UDP send errors are silently ignored
        }
    }

    fun startReceiving(handler: (ByteArray) -> Unit) {
        val ch = channel ?: return
        if (cancelled || !ch.isOpen) return

        receiveHandler = handler

        runOnSelector {
            try {
                val key = ch.register(sharedSelector, SelectionKey.OP_READ, this)
                selectionKey = key
            } catch (e: Exception) {
                logger.warning("Failed to register UDP channel: ${e.message}")
            }
        }
    }

    /** Called on selector thread when data is available. */
    private fun onReadable(key: SelectionKey, buffer: ByteBuffer) {
        val ch = key.channel() as DatagramChannel
        val handler = receiveHandler ?: return

        buffer.clear()
        try {
            val n = ch.read(buffer)
            if (n > 0) {
                buffer.flip()
                val data = ByteArray(n)
                buffer.get(data)
                handler(data)
            }
        } catch (e: Exception) {
            if (!cancelled) {
                logger.warning("UDP read error: ${e.message}")
            }
        }
    }

    fun cancel() {
        if (cancelled) return
        cancelled = true
        receiveHandler = null

        // Closing the channel automatically cancels the selection key
        try { channel?.close() } catch (_: Exception) {}
        channel = null
        selectionKey = null
    }
}
