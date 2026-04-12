package com.argsment.anywhere.vpn.protocol.shadowsocks

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

private val logger = AnywhereLogger("SS-UDP-Relay")
private const val RECV_BUFFER_SIZE = 65536

// =============================================================================
// ShadowsocksUDPRelay
// =============================================================================

/**
 * Direct UDP relay with Shadowsocks per-packet encryption.
 *
 * Creates a UDP socket directly to the SS server and handles per-packet
 * encryption/decryption. Supports both legacy SS and SS 2022 formats.
 */
class ShadowsocksUdpRelay(
    private val mode: Mode,
    private val dstHost: String,
    private val dstPort: Int
) {
    sealed class Mode {
        /** Legacy SS: salt + AEAD_seal(address + payload) */
        data class Legacy(val cipher: ShadowsocksCipher, val masterKey: ByteArray) : Mode()
        /** SS 2022 AES variant: AES-ECB header + per-session AEAD */
        data class SS2022AES(val cipher: ShadowsocksCipher, val psk: ByteArray) : Mode()
        /** SS 2022 ChaCha20 variant: XChaCha20-Poly1305 */
        data class SS2022ChaCha(val psk: ByteArray) : Mode()
    }

    private val random = SecureRandom()
    private var socket: DatagramSocket? = null
    private val cancelled = AtomicBoolean(false)

    // SS 2022 AES session state
    private var sessionID: Long = 0
    private var packetID: Long = 0
    private var sessionCipher: ByteArray? = null
    private var remoteSessionID: Long = 0
    private var remoteSessionCipher: ByteArray? = null

    init {
        when (mode) {
            is Mode.SS2022AES -> {
                sessionID = random.nextLong()
                val sidBytes = sessionID.toBigEndianBytes()
                sessionCipher = ShadowsocksKeyDerivation.deriveSessionKey(mode.psk, sidBytes, mode.cipher.keySize)
            }
            is Mode.SS2022ChaCha -> {
                sessionID = random.nextLong()
            }
            is Mode.Legacy -> {}
        }
    }

    /** Connects the UDP socket to the Shadowsocks server. */
    suspend fun connect(serverHost: String, serverPort: Int) = withContext(Dispatchers.IO) {
        val resolvedHost = DnsCache.resolveHost(serverHost) ?: serverHost
        val addr = InetAddress.getByName(resolvedHost)

        val sock = DatagramSocket()
        sock.connect(InetSocketAddress(addr, serverPort))
        sock.soTimeout = 0 // Non-blocking for recv
        socket = sock
    }

    /** Encrypts and sends a UDP payload to the SS server. */
    fun send(data: ByteArray) {
        val sock = socket ?: return
        if (cancelled.get()) return

        val encrypted = try {
            encryptPacket(data)
        } catch (e: Exception) {
            if (!cancelled.get()) {
                logger.error("[SS-UDP] Encrypt error: ${e.message}")
            }
            return
        }
        try {
            val packet = DatagramPacket(encrypted, encrypted.size)
            sock.send(packet)
        } catch (_: Exception) {
            // Socket send errors are not logged on iOS; suppress here for parity.
        }
    }

    /**
     * Blocking receive — call from a coroutine on an IO dispatcher.
     * Returns decrypted payload, or null if the socket is closed.
     */
    suspend fun receive(): ByteArray? = withContext(Dispatchers.IO) {
        val sock = socket ?: return@withContext null
        val buf = ByteArray(RECV_BUFFER_SIZE)
        val packet = DatagramPacket(buf, buf.size)

        try {
            sock.receive(packet) // blocking
        } catch (_: Exception) {
            return@withContext null
        }
        if (cancelled.get()) return@withContext null
        val data = buf.copyOf(packet.length)
        try {
            decryptPacket(data)
        } catch (e: Exception) {
            if (!cancelled.get()) {
                logger.error("[SS-UDP] Decrypt error: ${e.message}")
            }
            null
        }
    }

    fun cancel() {
        if (cancelled.getAndSet(true)) return
        try {
            socket?.close()
        } catch (_: Exception) {}
        socket = null
    }

    // -- Packet Encryption --

    private fun encryptPacket(payload: ByteArray): ByteArray {
        val addressHeader = ShadowsocksProtocol.buildAddressHeader(dstHost, dstPort)

        return when (mode) {
            is Mode.Legacy -> {
                val packet = ShadowsocksProtocol.encodeUDPPacket(dstHost, dstPort, payload)
                ShadowsocksUDPCrypto.encrypt(mode.cipher, mode.masterKey, packet)
            }

            is Mode.SS2022AES -> {
                val sessionKey = sessionCipher ?: throw ShadowsocksError.DecryptionFailed()

                packetID++
                val header = sessionID.toBigEndianBytes() + packetID.toBigEndianBytes()

                val paddingLen = if (dstPort == 53 && payload.size < MAX_PADDING_LENGTH)
                    random.nextInt(MAX_PADDING_LENGTH - payload.size) + 1 else 0

                val body = ByteArrayOutputStream()
                body.write(HEADER_TYPE_CLIENT.toInt())
                body.write((System.currentTimeMillis() / 1000).toBigEndianBytes())
                body.write(paddingLen.toUShortBigEndian())
                if (paddingLen > 0) body.write(ByteArray(paddingLen))
                body.write(addressHeader)
                body.write(payload)

                val nonce = header.copyOfRange(4, 16)
                val sealedBody = ShadowsocksAEADCrypto.seal(mode.cipher, sessionKey, nonce, body.toByteArray())
                val encryptedHeader = AesEcb.encrypt(mode.psk, header)

                encryptedHeader + sealedBody
            }

            is Mode.SS2022ChaCha -> {
                packetID++
                val nonce = ByteArray(24)
                random.nextBytes(nonce)

                val paddingLen = if (dstPort == 53 && payload.size < MAX_PADDING_LENGTH)
                    random.nextInt(MAX_PADDING_LENGTH - payload.size) + 1 else 0

                val body = ByteArrayOutputStream()
                body.write(sessionID.toBigEndianBytes())
                body.write(packetID.toBigEndianBytes())
                body.write(HEADER_TYPE_CLIENT.toInt())
                body.write((System.currentTimeMillis() / 1000).toBigEndianBytes())
                body.write(paddingLen.toUShortBigEndian())
                if (paddingLen > 0) body.write(ByteArray(paddingLen))
                body.write(addressHeader)
                body.write(payload)

                val sealed = XChaCha20Poly1305.seal(mode.psk, nonce, body.toByteArray())
                nonce + sealed
            }
        }
    }

    // -- Packet Decryption --

    private fun decryptPacket(data: ByteArray): ByteArray {
        return when (mode) {
            is Mode.Legacy -> {
                val decrypted = ShadowsocksUDPCrypto.decrypt(mode.cipher, mode.masterKey, data)
                val parsed = ShadowsocksProtocol.decodeUDPPacket(decrypted)
                    ?: throw ShadowsocksError.InvalidAddress()
                parsed.payload
            }

            is Mode.SS2022AES -> {
                require(data.size >= 16 + 16)

                val header = AesEcb.decrypt(mode.psk, data.copyOf(16))
                val remoteSession = header.readLongBE(0)

                val remoteCipherKey: ByteArray
                val cached = remoteSessionCipher
                if (remoteSession == remoteSessionID && cached != null) {
                    remoteCipherKey = cached
                } else {
                    val rsData = remoteSession.toBigEndianBytes()
                    remoteCipherKey = ShadowsocksKeyDerivation.deriveSessionKey(mode.psk, rsData, mode.cipher.keySize)
                    remoteSessionID = remoteSession
                    remoteSessionCipher = remoteCipherKey
                }

                val nonce = header.copyOfRange(4, 16)
                val sealedBody = data.copyOfRange(16, data.size)
                val body = ShadowsocksAEADCrypto.open(mode.cipher, remoteCipherKey, nonce, sealedBody)

                parseServerUDPBody(body)
            }

            is Mode.SS2022ChaCha -> {
                require(data.size >= 24 + 16)

                val nonce = data.copyOf(24)
                val ciphertext = data.copyOfRange(24, data.size)
                val body = XChaCha20Poly1305.open(mode.psk, nonce, ciphertext)

                require(body.size >= 16)
                // Skip sessionID(8) + packetID(8)
                parseServerUDPBody(body.copyOfRange(16, body.size))
            }
        }
    }

    /** Parses decrypted SS 2022 server UDP body. */
    private fun parseServerUDPBody(body: ByteArray): ByteArray {
        require(body.size >= 1 + 8 + 8 + 2)

        var offset = 0
        val headerType = body[offset]; offset++
        if (headerType != HEADER_TYPE_SERVER) throw ShadowsocksError.BadHeaderType()

        // Validate timestamp
        val epoch = body.readLongBE(offset); offset += 8
        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - epoch) > MAX_TIMESTAMP_DIFF) throw ShadowsocksError.BadTimestamp()

        // Client session ID
        val clientSid = body.readLongBE(offset); offset += 8
        if (clientSid != sessionID) throw ShadowsocksError.DecryptionFailed()

        // Padding
        require(body.size - offset >= 2)
        val paddingLen = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
        offset += 2 + paddingLen

        val parsed = ShadowsocksProtocol.decodeUDPPacket(body.copyOfRange(offset, body.size))
            ?: throw ShadowsocksError.InvalidAddress()
        return parsed.payload
    }

    companion object {
        private const val HEADER_TYPE_CLIENT: Byte = 0
        private const val HEADER_TYPE_SERVER: Byte = 1
        private const val MAX_PADDING_LENGTH = 900
        private const val MAX_TIMESTAMP_DIFF = 30L
    }
}
