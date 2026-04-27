package com.argsment.anywhere.vpn.protocol.shadowsocks

import com.argsment.anywhere.vpn.SocketProtector
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.DnsCache
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.ScheduledExecutorService

private val logger = AnywhereLogger("SS-UDP")
private const val RECV_BUFFER_SIZE = 65536
private const val MAX_PADDING_LENGTH = 900
private const val MAX_TIMESTAMP_DIFF = 30L
private const val HEADER_TYPE_CLIENT: Byte = 0
private const val HEADER_TYPE_SERVER: Byte = 1

/**
 * Shared Shadowsocks UDP session over a single datagram socket. Multiplexes every
 * destination flow from one client configuration through one UDP socket, one
 * SS 2022 sessionID, and one monotonic packetID.
 *
 * Replies are demultiplexed by (host, port) from the reply's decrypted SS header.
 * When the server resolved a domain to an IP the client did not pre-seed, the exact
 * match fails and a port-only match is used as fallback — safe in practice because
 * a single source port typically talks to a single destination.
 *
 * Threading: state mutations and registered handlers run on [executor]. The blocking
 * receive loop runs on a dedicated daemon thread; decoded datagrams hop back to
 * [executor] before any handler dispatch.
 */
class ShadowsocksUdpSession(
    private val mode: Mode,
    private val serverHost: String,
    private val serverPort: Int,
    private val executor: ScheduledExecutorService
) {

    sealed class Mode {
        /**
         * Legacy SS: per-packet salt + AEAD(address || payload). No session state, so
         * sessionID / packetID counters are unused.
         */
        data class Legacy(val cipher: ShadowsocksCipher, val masterKey: ByteArray) : Mode()

        /**
         * SS 2022 AES variant: AES-ECB 16-byte packet header + per-session AEAD body.
         * Supports multi-PSK via identity headers.
         */
        data class SS2022AES(val cipher: ShadowsocksCipher, val pskList: List<ByteArray>) : Mode()

        /** SS 2022 ChaCha variant: XChaCha20-Poly1305 with 24-byte random nonce; single PSK only. */
        data class SS2022ChaCha(val psk: ByteArray) : Mode()
    }

    /** Handle returned by [register]; pass back to [send] / [unregister]. */
    private class Registration(
        val token: Long,
        val port: Int,
        /**
         * Hosts considered a match for this flow's replies. Seeded with the destination
         * host, extended with caller-provided hints, and opportunistically learned from
         * the reply address on the first port-only fallback delivery.
         */
        val responseHosts: MutableSet<String>,
        /**
         * True once this flow has pinned a reply source. Used by the port-only fallback
         * to prefer flows that haven't pinned yet.
         */
        var hasLearnedSource: Boolean,
        val handler: (ByteArray) -> Unit,
        val errorHandler: ((Throwable) -> Unit)?
    )

    private data class ResponseKey(val host: String, val port: Int)

    private enum class State { IDLE, CONNECTING, READY, FAILED, CANCELLED }

    private data class PendingSend(
        val token: Long,
        val dstHost: String,
        val dstPort: Int,
        val payload: ByteArray,
        val completion: ((Throwable?) -> Unit)?
    )

    private var state: State = State.IDLE
    private var failure: Throwable? = null

    private var nextToken: Long = 0
    private val registrations = HashMap<Long, Registration>()
    private val tokensByResponse = HashMap<ResponseKey, MutableList<Long>>()
    private val tokensByPort = HashMap<Int, MutableList<Long>>()
    private val pendingSends = mutableListOf<PendingSend>()

    @Volatile
    private var socket: DatagramSocket? = null
    private var receiveThread: Thread? = null

    // SS 2022 session state — sessionwide, not per-flow.
    private var sessionID: Long = 0
    private var packetIDCounter: Long = 0

    /**
     * Outbound AEAD key for the AES variant. Derived once from sessionID + user PSK
     * and reused for every outgoing packet.
     */
    private var outboundCipherKey: ByteArray? = null

    /**
     * Most recently seen server sessionID and its derived inbound AEAD key. Cached so
     * BLAKE3 DeriveKey runs only when the server rotates.
     */
    private var remoteSessionID: Long = 0
    private var remoteCipherKey: ByteArray? = null

    /** First 16 bytes of BLAKE3(pskList[i]) for i >= 1; used in SS 2022 AES identity headers. */
    private val pskHashes: List<ByteArray>

    private val random = SecureRandom()

    init {
        when (mode) {
            is Mode.SS2022AES -> {
                sessionID = random.nextLong()
                val sidBytes = sessionID.toBigEndianBytes()
                outboundCipherKey = ShadowsocksKeyDerivation.deriveSessionKey(
                    mode.pskList.last(), sidBytes, mode.cipher.keySize
                )
                pskHashes = if (mode.pskList.size >= 2) {
                    (1 until mode.pskList.size).map {
                        ShadowsocksKeyDerivation.blake3Hash16(mode.pskList[it])
                    }
                } else {
                    emptyList()
                }
            }
            is Mode.SS2022ChaCha -> {
                sessionID = random.nextLong()
                pskHashes = emptyList()
            }
            is Mode.Legacy -> {
                pskHashes = emptyList()
            }
        }
    }

    /**
     * True while the session can still accept registrations and sends. Owners must
     * check this before reusing a cached session; once false, drop the reference
     * and build a new one.
     */
    val isUsable: Boolean
        get() = when (state) {
            State.IDLE, State.CONNECTING, State.READY -> true
            State.FAILED, State.CANCELLED -> false
        }

    /**
     * Registers interest in replies whose SS address matches (dstHost, dstPort) or any
     * of [responseHostHints]. The SS server typically replies with the resolved IP, not
     * the original domain — for domain destinations, callers should pass pre-resolved
     * IPs as hints to enable exact demultiplexing; otherwise the port-only fallback runs.
     */
    fun register(
        dstHost: String,
        dstPort: Int,
        responseHostHints: List<String> = emptyList(),
        handler: (ByteArray) -> Unit,
        errorHandler: ((Throwable) -> Unit)? = null
    ): Long {
        nextToken += 1
        val token = nextToken

        val hosts = LinkedHashSet<String>()
        hosts.add(dstHost)
        hosts.addAll(responseHostHints)

        // dstHost alone isn't enough to count as "pinned" — that needs a reply.
        // Extra hints (e.g. pre-resolved IPs) let us pin before the first reply.
        val pinned = hosts.size > 1

        val reg = Registration(
            token = token,
            port = dstPort,
            responseHosts = hosts,
            hasLearnedSource = pinned,
            handler = handler,
            errorHandler = errorHandler
        )
        registrations[token] = reg
        for (host in hosts) {
            tokensByResponse.getOrPut(ResponseKey(host, dstPort)) { mutableListOf() }.add(token)
        }
        tokensByPort.getOrPut(dstPort) { mutableListOf() }.add(token)

        if (state == State.IDLE) {
            beginConnect()
        }
        return token
    }

    /**
     * Adds response-address hints to an existing registration after an async DNS
     * resolve completes, so subsequent replies route via exact match instead of
     * port-only fallback.
     */
    fun addResponseHints(token: Long, hints: List<String>) {
        val reg = registrations[token] ?: return
        var inserted = false
        for (hint in hints) {
            if (reg.responseHosts.add(hint)) {
                tokensByResponse.getOrPut(ResponseKey(hint, reg.port)) { mutableListOf() }.add(token)
                inserted = true
            }
        }
        if (inserted) reg.hasLearnedSource = true
    }

    /** Idempotent. */
    fun unregister(token: Long) {
        val reg = registrations.remove(token) ?: return
        for (host in reg.responseHosts) {
            removeToken(tokensByResponse, ResponseKey(host, reg.port), token)
        }
        removeToken(tokensByPort, reg.port, token)
        pendingSends.removeAll { it.token == token }
    }

    /**
     * Encrypts and enqueues a UDP payload. Payloads sent before socket connect completes
     * are buffered and flushed in order once ready.
     */
    fun send(
        token: Long,
        dstHost: String,
        dstPort: Int,
        payload: ByteArray,
        completion: ((Throwable?) -> Unit)? = null
    ) {
        if (registrations[token] == null) {
            completion?.invoke(ShadowsocksError.InvalidAddress())
            return
        }
        when (state) {
            State.IDLE, State.CONNECTING -> {
                pendingSends.add(PendingSend(token, dstHost, dstPort, payload, completion))
            }
            State.READY -> {
                sendNow(dstHost, dstPort, payload, completion)
            }
            State.FAILED -> {
                completion?.invoke(failure ?: ShadowsocksError.DecryptionFailed())
            }
            State.CANCELLED -> {
                completion?.invoke(java.io.IOException("Session cancelled"))
            }
        }
    }

    /** Tears down the socket and drops all registrations. Reentrant / idempotent. */
    fun cancel() {
        if (state == State.CANCELLED) return
        state = State.CANCELLED
        try { socket?.close() } catch (_: Exception) {}
        socket = null
        registrations.clear()
        tokensByResponse.clear()
        tokensByPort.clear()
        pendingSends.clear()
    }

    private fun beginConnect() {
        state = State.CONNECTING
        // Resolve + connect off [executor] — getByName / DatagramSocket can block on
        // the resolver. The connect callback hops back to [executor] for state changes.
        Thread({
            val sock: DatagramSocket
            try {
                val resolvedHost = DnsCache.resolveHost(serverHost) ?: serverHost
                val addr = InetAddress.getByName(resolvedHost)
                sock = DatagramSocket()
                try {
                    if (!SocketProtector.protect(sock)) {
                        throw java.io.IOException("Failed to protect SS UDP socket")
                    }
                    sock.connect(InetSocketAddress(addr, serverPort))
                } catch (e: Throwable) {
                    try { sock.close() } catch (_: Exception) {}
                    throw e
                }
            } catch (e: Throwable) {
                executor.execute {
                    if (state == State.CANCELLED) return@execute
                    failure = e
                    state = State.FAILED
                    notifyAllFlows(e)
                    pendingSends.clear()
                }
                return@Thread
            }

            executor.execute {
                if (state == State.CANCELLED) {
                    try { sock.close() } catch (_: Exception) {}
                    return@execute
                }
                socket = sock
                state = State.READY
                startReceiveLoop(sock)

                val flushes = pendingSends.toList()
                pendingSends.clear()
                for (p in flushes) {
                    sendNow(p.dstHost, p.dstPort, p.payload, p.completion)
                }
            }
        }, "SS-UDP-connect").apply { isDaemon = true }.start()
    }

    private fun startReceiveLoop(sock: DatagramSocket) {
        val t = Thread({
            val buf = ByteArray(RECV_BUFFER_SIZE)
            while (!sock.isClosed) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    sock.receive(packet)
                } catch (_: Exception) {
                    break
                }
                val data = buf.copyOf(packet.length)
                executor.execute { handleReceivedDatagram(data) }
            }
        }, "SS-UDP-recv").apply { isDaemon = true }
        receiveThread = t
        t.start()
    }

    private fun notifyAllFlows(error: Throwable) {
        val handlers = registrations.values.mapNotNull { it.errorHandler }
        for (h in handlers) {
            try { h(error) } catch (_: Throwable) {}
        }
    }

    private fun sendNow(
        dstHost: String,
        dstPort: Int,
        payload: ByteArray,
        completion: ((Throwable?) -> Unit)?
    ) {
        val sock = socket
        if (sock == null || sock.isClosed) {
            completion?.invoke(java.io.IOException("Session not connected"))
            return
        }
        val encrypted: ByteArray
        try {
            encrypted = encryptPacket(payload, dstHost, dstPort)
        } catch (e: Throwable) {
            logger.error("[SS-UDP] Encrypt error: ${e.message}")
            completion?.invoke(e)
            return
        }
        try {
            sock.send(DatagramPacket(encrypted, encrypted.size))
            completion?.invoke(null)
        } catch (_: Exception) {
            // UDP is best-effort — send errors are silently ignored.
            completion?.invoke(null)
        }
    }

    private fun handleReceivedDatagram(data: ByteArray) {
        val decoded: Triple<String, Int, ByteArray>
        try {
            decoded = decryptPacket(data)
        } catch (e: Throwable) {
            // Corrupt / stale datagrams happen on the open Internet; tearing the
            // session down on a single bad packet would be fragile.
            logger.debug("[SS-UDP] Decrypt error: ${e.message}")
            return
        }

        val (host, port, payload) = decoded
        val key = ResponseKey(host, port)

        tokensByResponse[key]?.let { tokens ->
            val reg = firstRegistration(tokens)
            if (reg != null) {
                try { reg.handler(payload) } catch (_: Throwable) {}
                return
            }
        }

        // Port-only fallback: multiple flows may share a port (concurrent QUIC on 443,
        // DNS to different resolvers). Prefer a flow that hasn't yet pinned a reply
        // source, since pinned flows should already have matched exactly above.
        tokensByPort[port]?.let { tokens ->
            val target = firstRegistrationWhere(tokens) { !it.hasLearnedSource }
                ?: firstRegistration(tokens)
            if (target != null) {
                if (!target.responseHosts.contains(host)) {
                    target.responseHosts.add(host)
                    tokensByResponse.getOrPut(key) { mutableListOf() }.add(target.token)
                }
                target.hasLearnedSource = true
                try { target.handler(payload) } catch (_: Throwable) {}
                return
            }
        }
        logger.debug("[SS-UDP] No flow for reply from $host:$port; dropped")
    }

    private fun firstRegistration(tokens: List<Long>): Registration? {
        for (t in tokens) {
            val reg = registrations[t]
            if (reg != null) return reg
        }
        return null
    }

    private fun firstRegistrationWhere(
        tokens: List<Long>,
        predicate: (Registration) -> Boolean
    ): Registration? {
        for (t in tokens) {
            val reg = registrations[t]
            if (reg != null && predicate(reg)) return reg
        }
        return null
    }

    private fun nextPacketID(): Long {
        packetIDCounter += 1
        return packetIDCounter
    }

    private fun encryptPacket(payload: ByteArray, dstHost: String, dstPort: Int): ByteArray {
        return when (mode) {
            is Mode.Legacy -> {
                val packet = ShadowsocksProtocol.encodeUDPPacket(dstHost, dstPort, payload)
                ShadowsocksUDPCrypto.encrypt(mode.cipher, mode.masterKey, packet)
            }
            is Mode.SS2022AES -> encryptSS2022AES(payload, dstHost, dstPort, mode.cipher, mode.pskList)
            is Mode.SS2022ChaCha -> encryptSS2022ChaCha(payload, dstHost, dstPort, mode.psk)
        }
    }

    private fun encryptSS2022AES(
        payload: ByteArray,
        dstHost: String,
        dstPort: Int,
        cipher: ShadowsocksCipher,
        pskList: List<ByteArray>
    ): ByteArray {
        val sessionKey = outboundCipherKey ?: throw ShadowsocksError.DecryptionFailed()

        // 16-byte packet header: sessionID(8) + packetID(8), big-endian.
        val header = sessionID.toBigEndianBytes() + nextPacketID().toBigEndianBytes()

        val identityData = if (pskList.size >= 2) {
            val out = ByteArrayOutputStream()
            for (i in 0 until pskList.size - 1) {
                val hash = pskHashes[i]
                val xored = ByteArray(16)
                for (j in 0 until 16) xored[j] = (hash[j].toInt() xor header[j].toInt()).toByte()
                out.write(AesEcb.encrypt(pskList[i], xored))
            }
            out.toByteArray()
        } else {
            byteArrayOf()
        }

        // AEAD body: type(0) + ts(8) + paddingLen(2) + padding + addr + payload.
        val addressHeader = ShadowsocksProtocol.buildAddressHeader(dstHost, dstPort)
        val paddingLen = if (dstPort == 53 && payload.size < MAX_PADDING_LENGTH) {
            random.nextInt(MAX_PADDING_LENGTH - payload.size) + 1
        } else 0

        val body = ByteArrayOutputStream()
        body.write(HEADER_TYPE_CLIENT.toInt())
        body.write((System.currentTimeMillis() / 1000).toBigEndianBytes())
        body.write(paddingLen.toUShortBigEndian())
        if (paddingLen > 0) body.write(ByteArray(paddingLen))
        body.write(addressHeader)
        body.write(payload)

        // AEAD nonce = last 12 bytes of the 16-byte header.
        val nonce = header.copyOfRange(4, 16)
        val sealedBody = ShadowsocksAEADCrypto.seal(cipher, sessionKey, nonce, body.toByteArray())

        // Header is AES-ECB encrypted with pskList[0] — the iPSK in multi-PSK setups,
        // or the user PSK when only one PSK is configured.
        val encryptedHeader = AesEcb.encrypt(pskList.first(), header)

        return encryptedHeader + identityData + sealedBody
    }

    private fun encryptSS2022ChaCha(
        payload: ByteArray,
        dstHost: String,
        dstPort: Int,
        psk: ByteArray
    ): ByteArray {
        val nonce = ByteArray(24).also(random::nextBytes)

        val addressHeader = ShadowsocksProtocol.buildAddressHeader(dstHost, dstPort)
        val paddingLen = if (dstPort == 53 && payload.size < MAX_PADDING_LENGTH) {
            random.nextInt(MAX_PADDING_LENGTH - payload.size) + 1
        } else 0

        val body = ByteArrayOutputStream()
        body.write(sessionID.toBigEndianBytes())
        body.write(nextPacketID().toBigEndianBytes())
        body.write(HEADER_TYPE_CLIENT.toInt())
        body.write((System.currentTimeMillis() / 1000).toBigEndianBytes())
        body.write(paddingLen.toUShortBigEndian())
        if (paddingLen > 0) body.write(ByteArray(paddingLen))
        body.write(addressHeader)
        body.write(payload)

        val sealed = XChaCha20Poly1305.seal(psk, nonce, body.toByteArray())
        return nonce + sealed
    }

    private fun decryptPacket(data: ByteArray): Triple<String, Int, ByteArray> {
        return when (mode) {
            is Mode.Legacy -> {
                val decrypted = ShadowsocksUDPCrypto.decrypt(mode.cipher, mode.masterKey, data)
                val parsed = ShadowsocksProtocol.decodeUDPPacket(decrypted)
                    ?: throw ShadowsocksError.InvalidAddress()
                Triple(parsed.host, parsed.port, parsed.payload)
            }
            is Mode.SS2022AES -> decryptSS2022AES(data, mode.cipher, mode.pskList)
            is Mode.SS2022ChaCha -> decryptSS2022ChaCha(data, mode.psk)
        }
    }

    private fun decryptSS2022AES(
        data: ByteArray,
        cipher: ShadowsocksCipher,
        pskList: List<ByteArray>
    ): Triple<String, Int, ByteArray> {
        if (data.size < 16 + 16) throw ShadowsocksError.DecryptionFailed()

        // Header AES-ECB decrypt uses pskList.last() — the user PSK.
        val header = AesEcb.decrypt(pskList.last(), data.copyOf(16))
        val serverSession = header.readLongBE(0)

        val cipherKey: ByteArray
        val cached = remoteCipherKey
        if (serverSession == remoteSessionID && cached != null) {
            cipherKey = cached
        } else {
            val rsData = serverSession.toBigEndianBytes()
            cipherKey = ShadowsocksKeyDerivation.deriveSessionKey(pskList.last(), rsData, cipher.keySize)
            remoteSessionID = serverSession
            remoteCipherKey = cipherKey
        }

        val nonce = header.copyOfRange(4, 16)
        val sealedBody = data.copyOfRange(16, data.size)
        val body = ShadowsocksAEADCrypto.open(cipher, cipherKey, nonce, sealedBody)
        return parseServerUDPBody(body)
    }

    private fun decryptSS2022ChaCha(
        data: ByteArray,
        psk: ByteArray
    ): Triple<String, Int, ByteArray> {
        if (data.size < 24 + 16) throw ShadowsocksError.DecryptionFailed()

        val nonce = data.copyOf(24)
        val ciphertext = data.copyOfRange(24, data.size)
        val body = XChaCha20Poly1305.open(psk, nonce, ciphertext)

        // Body layout: sessionID(8) + packetID(8) + [standard server body]. The server's
        // sessionID/packetID sliding window is not validated here — AEAD tag + timestamp
        // already gate acceptance.
        if (body.size < 16) throw ShadowsocksError.DecryptionFailed()
        return parseServerUDPBody(body.copyOfRange(16, body.size))
    }

    /**
     * Parses a decrypted SS 2022 server UDP body:
     * `type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + socksaddr + payload`
     */
    private fun parseServerUDPBody(body: ByteArray): Triple<String, Int, ByteArray> {
        if (body.size < 1 + 8 + 8 + 2) throw ShadowsocksError.DecryptionFailed()

        var offset = 0
        val headerType = body[offset]; offset += 1
        if (headerType != HEADER_TYPE_SERVER) throw ShadowsocksError.BadHeaderType()

        val epoch = body.readLongBE(offset); offset += 8
        val now = System.currentTimeMillis() / 1000
        if (Math.abs(now - epoch) > MAX_TIMESTAMP_DIFF) throw ShadowsocksError.BadTimestamp()

        val clientSid = body.readLongBE(offset); offset += 8
        if (clientSid != sessionID) throw ShadowsocksError.DecryptionFailed()

        if (body.size - offset < 2) throw ShadowsocksError.DecryptionFailed()
        val paddingLen = ((body[offset].toInt() and 0xFF) shl 8) or (body[offset + 1].toInt() and 0xFF)
        offset += 2 + paddingLen

        val parsed = ShadowsocksProtocol.decodeUDPPacket(body.copyOfRange(offset, body.size))
            ?: throw ShadowsocksError.InvalidAddress()
        return Triple(parsed.host, parsed.port, parsed.payload)
    }

    private fun <K> removeToken(map: HashMap<K, MutableList<Long>>, key: K, token: Long) {
        val tokens = map[key] ?: return
        tokens.removeAll { it == token }
        if (tokens.isEmpty()) map.remove(key)
    }

    companion object {
        /**
         * Returns null when the cipher or password is missing or malformed — callers
         * should treat that as a fatal misconfiguration.
         */
        fun modeFor(configuration: com.argsment.anywhere.data.model.ProxyConfiguration): Mode? {
            val method = configuration.ssMethod ?: return null
            val password = configuration.ssPassword ?: return null
            val cipher = ShadowsocksCipher.fromMethod(method) ?: return null
            return if (cipher.isSS2022) {
                val pskList = ShadowsocksKeyDerivation.decodePSKList(password, cipher.keySize) ?: return null
                if (cipher.isChaCha) {
                    Mode.SS2022ChaCha(pskList.last())
                } else {
                    Mode.SS2022AES(cipher, pskList)
                }
            } else {
                val masterKey = ShadowsocksKeyDerivation.deriveKey(password, cipher.keySize)
                Mode.Legacy(cipher, masterKey)
            }
        }
    }
}
