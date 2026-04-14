package com.argsment.anywhere.vpn.protocol.hysteria

import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.trySendBlocking
import java.security.SecureRandom

private val logger = AnywhereLogger("Hysteria-UDP")

/**
 * One Hysteria v2 UDP "session" — a virtual UDP socket carried over the
 * Hysteria QUIC connection's DATAGRAM frames. Direct port of iOS
 * `HysteriaUDPConnection.swift`, adapted to Android coroutines.
 *
 * Sends each user UDP datagram as one or more Hysteria UDP messages
 * (fragmented if it exceeds the QUIC DATAGRAM MTU). Reassembles incoming
 * fragments using Hysteria's "PacketID + FragID/FragCount" scheme, exactly
 * matching the reference implementation's single-pending-packet defragger.
 */
class HysteriaUdpConnection(
    private val session: HysteriaSession,
    private val destination: String
) : VlessConnection() {

    enum class State { IDLE, READY, CLOSED }

    @Volatile private var state: State = State.IDLE
    @Volatile private var sessionId: Int = 0

    /** Reassembled, ready-to-deliver UDP payloads. */
    private val packetQueue = Channel<ByteArray>(capacity = Channel.UNLIMITED)

    // Single-packet defragmenter state (matches reference Defragger).
    private val fragLock = Any()
    private var pendingPacketId = 0
    private var pendingFragments: Array<ByteArray?> = emptyArray()
    private var pendingFragmentsReceived = 0
    private var pendingFragmentCount = 0

    override val isConnected: Boolean get() = state == State.READY
    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    /** Registers the UDP session with the [HysteriaSession]. Throws
     *  [HysteriaError.UdpNotSupported] if the server didn't advertise UDP. */
    suspend fun open() {
        val sid = session.registerUdpSession(this) ?: throw HysteriaError.UdpNotSupported
        sessionId = sid
        state = State.READY
    }

    fun handleIncomingDatagram(msg: HysteriaProtocol.UdpMessage) {
        val assembled = if (msg.fragCount <= 1) msg.data else assembleFragment(msg)
        if (assembled != null) packetQueue.trySendBlocking(assembled)
    }

    private fun assembleFragment(msg: HysteriaProtocol.UdpMessage): ByteArray? {
        synchronized(fragLock) {
            if (msg.fragId >= msg.fragCount || msg.fragCount <= 0) return null
            if (msg.packetId != pendingPacketId || pendingFragmentCount != msg.fragCount) {
                pendingPacketId = msg.packetId
                pendingFragmentCount = msg.fragCount
                pendingFragments = arrayOfNulls(msg.fragCount)
                pendingFragmentsReceived = 0
            }
            if (pendingFragments[msg.fragId] == null) {
                pendingFragments[msg.fragId] = msg.data
                pendingFragmentsReceived += 1
            }
            if (pendingFragmentsReceived != pendingFragmentCount) return null

            var total = 0
            for (p in pendingFragments) total += (p?.size ?: return null)
            val full = ByteArray(total)
            var off = 0
            for (p in pendingFragments) {
                val pp = p!!
                System.arraycopy(pp, 0, full, off, pp.size); off += pp.size
            }
            pendingFragments = emptyArray()
            pendingFragmentsReceived = 0
            pendingFragmentCount = 0
            return full
        }
    }

    fun handleSessionError(error: Throwable) {
        if (state == State.CLOSED) return
        state = State.CLOSED
        packetQueue.close(error)
    }

    // -- VlessConnection API --

    override suspend fun sendRaw(data: ByteArray) {
        if (state != State.READY) {
            throw if (state == State.CLOSED) HysteriaError.StreamClosed else HysteriaError.NotReady
        }
        val maxSize = maxOf(1, session.maxDatagramPayloadSize)
        val packetId = newPacketId()
        val fragments = HysteriaProtocol.fragmentUdp(
            sessionId = sessionId,
            packetId = packetId,
            address = destination,
            data = data,
            maxDatagramSize = maxSize
        )
        if (fragments.isEmpty()) {
            throw HysteriaError.ConnectionFailed("UDP payload too large to fragment")
        }
        session.writeDatagrams(fragments.map { HysteriaProtocol.encodeUdpMessage(it) })
    }

    override fun sendRawAsync(data: ByteArray) {
        if (state != State.READY) return
        val maxSize = maxOf(1, session.maxDatagramPayloadSize)
        val packetId = newPacketId()
        val fragments = HysteriaProtocol.fragmentUdp(
            sessionId = sessionId, packetId = packetId,
            address = destination, data = data, maxDatagramSize = maxSize
        )
        if (fragments.isNotEmpty()) {
            session.writeDatagrams(fragments.map { HysteriaProtocol.encodeUdpMessage(it) })
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        return try { packetQueue.receive() } catch (_: Throwable) { null }
    }

    override fun cancel() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        session.releaseUdpSession(sessionId)
        packetQueue.close()
    }

    companion object {
        private val random = SecureRandom()

        /** PacketID is a non-zero u16 (0 is reserved by some Hysteria servers). */
        private fun newPacketId(): Int {
            val v = random.nextInt() and 0xFFFF
            return if (v == 0) 1 else v
        }
    }
}
