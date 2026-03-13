package com.argsment.anywhere.vpn.protocol.shadowsocks

import android.util.Log
import com.argsment.anywhere.vpn.protocol.Transport
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection

private const val TAG = "ShadowsocksConn"

// =============================================================================
// ShadowsocksConnection (TCP)
// =============================================================================

/**
 * Wraps a transport with Shadowsocks AEAD encryption.
 *
 * The address header is prepended to the first `send()` call's data
 * (encrypted as part of the stream). Shadowsocks has no response header,
 * so `responseHeaderReceived` starts as `true`.
 */
class ShadowsocksConnection(
    private val transport: Transport,
    cipher: ShadowsocksCipher,
    masterKey: ByteArray,
    private var addressHeader: ByteArray?
) : VlessConnection() {

    private val writer = ShadowsocksAEADWriter(cipher, masterKey)
    private val reader = ShadowsocksAEADReader(cipher, masterKey)
    private val headerLock = Any()

    init {
        responseHeaderReceived = true
    }

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
            Log.e(TAG, "Send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        while (true) {
            val data = transport.receive() ?: return null
            if (data.isEmpty()) return null
            val plaintext = reader.open(data)
            if (plaintext.isNotEmpty()) return plaintext
            // If plaintext is empty, we need more data — loop to receive again
        }
    }

    override fun cancel() {
        transport.forceCancel()
    }
}

// =============================================================================
// ShadowsocksUDPConnection (UDP-over-TCP)
// =============================================================================

/**
 * Wraps a transport with Shadowsocks per-packet UDP encryption.
 * Used for UDP-over-TCP tunneling.
 */
class ShadowsocksUDPConnection(
    private val transport: Transport,
    private val cipher: ShadowsocksCipher,
    private val masterKey: ByteArray,
    private val dstHost: String,
    private val dstPort: Int
) : VlessConnection() {

    init {
        responseHeaderReceived = true
    }

    override val isConnected: Boolean get() = true

    override suspend fun sendRaw(data: ByteArray) {
        val packet = ShadowsocksProtocol.encodeUDPPacket(dstHost, dstPort, data)
        val encrypted = ShadowsocksUDPCrypto.encrypt(cipher, masterKey, packet)
        transport.send(encrypted)
    }

    override fun sendRawAsync(data: ByteArray) {
        try {
            val packet = ShadowsocksProtocol.encodeUDPPacket(dstHost, dstPort, data)
            val encrypted = ShadowsocksUDPCrypto.encrypt(cipher, masterKey, packet)
            transport.sendAsync(encrypted)
        } catch (e: Exception) {
            Log.e(TAG, "UDP send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = transport.receive() ?: return null
        if (data.isEmpty()) return null
        val decrypted = ShadowsocksUDPCrypto.decrypt(cipher, masterKey, data)
        val parsed = ShadowsocksProtocol.decodeUDPPacket(decrypted) ?: throw ShadowsocksError.InvalidAddress()
        return parsed.payload
    }

    override fun cancel() {
        transport.forceCancel()
    }
}
