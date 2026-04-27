package com.argsment.anywhere.vpn.protocol.shadowsocks

import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.util.AnywhereLogger

private val logger = AnywhereLogger("Shadowsocks")

/**
 * Shadowsocks TCP connection wrapping a transport with AEAD encryption. The address
 * header is prepended to the first send (encrypted as part of the stream).
 * Shadowsocks has no response header.
 */
class ShadowsocksConnection(
    private val transport: Transport,
    cipher: ShadowsocksCipher,
    masterKey: ByteArray,
    private var addressHeader: ByteArray?
) : ProxyConnection() {

    private val writer = ShadowsocksAEADWriter(cipher, masterKey)
    private val reader = ShadowsocksAEADReader(cipher, masterKey)
    private val headerLock = Any()

    override val isConnected: Boolean get() = true

    override suspend fun sendRaw(data: ByteArray) {
        val plaintext: ByteArray
        synchronized(headerLock) {
            val header = addressHeader
            if (header != null) {
                addressHeader = null
                plaintext = header + data
            } else {
                plaintext = data
            }
        }

        val encrypted = writer.seal(plaintext)
        transport.send(encrypted)
    }

    override fun sendRawAsync(data: ByteArray) {
        val plaintext: ByteArray
        synchronized(headerLock) {
            val header = addressHeader
            if (header != null) {
                addressHeader = null
                plaintext = header + data
            } else {
                plaintext = data
            }
        }

        try {
            val encrypted = writer.seal(plaintext)
            transport.sendAsync(encrypted)
        } catch (e: Exception) {
            logger.error("[SS] Send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        while (true) {
            val data = transport.receive() ?: return null
            if (data.isEmpty()) return null
            val plaintext = reader.open(data)
            if (plaintext.isNotEmpty()) return plaintext
            // Empty plaintext means the AEAD reader needs more bytes — loop.
        }
    }

    override fun cancel() {
        transport.forceCancel()
    }
}
