package com.argsment.anywhere.vpn.protocol.mux

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.ProxyConnection
import com.argsment.anywhere.vpn.protocol.vless.VlessClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.CoroutineContext

private val logger = AnywhereLogger("MuxClient")

/**
 * Single mux connection over VLESS with session management. Serialises writes,
 * runs a receive loop with frame parsing, applies a 16s idle timeout, and
 * supports XUDP.
 */
class MuxClient(
    val configuration: ProxyConfiguration,
    private val coroutineContext: CoroutineContext
) {
    private val scope = CoroutineScope(coroutineContext)

    private var vlessClient: VlessClient? = null
    private var vlessConnection: ProxyConnection? = null
    private val sessions = mutableMapOf<Int, MuxSession>()
    private var nextSessionID: Int = 1
    private var connecting = false
    private var connected = false

    @Volatile
    var closed: Boolean = false
        private set

    // Frames must not interleave on the wire.
    private val writeMutex = Mutex()

    private val frameParser = MuxFrameParser()

    private var idleTimerJob: Job? = null

    private var isXUDP = false

    val sessionCount: Int get() = sessions.size
    val isFull: Boolean get() = closed || isXUDP

    private val connectMutex = Mutex()
    private val pendingConnections = mutableListOf<kotlinx.coroutines.CompletableDeferred<Unit>>()

    companion object {
        private const val IDLE_TIMEOUT_MS = 16_000L
    }

    /** Lazily connects the underlying VLESS connection on first use. */
    suspend fun createSession(
        network: MuxNetwork,
        host: String,
        port: Int,
        globalID: ByteArray?
    ): MuxSession {
        if (closed) throw ProxyError.ConnectionFailed("Mux client closed")

        val sessionID: Int
        if (globalID != null) {
            // XUDP: one flow per mux connection, always session ID 0.
            sessionID = 0
            isXUDP = true
        } else {
            sessionID = nextSessionID
            nextSessionID = (nextSessionID + 1) and 0xFFFF
            // Session ID 0 is reserved.
            if (nextSessionID == 0) nextSessionID = 1
        }

        val session = MuxSession(
            sessionID = sessionID,
            network = network,
            targetHost = host,
            targetPort = port,
            client = this,
            globalID = globalID
        )
        sessions[sessionID] = session

        resetIdleTimer()

        try {
            if (!connected) {
                connectMux()
            }

            // For XUDP, defer the New frame until first data so the first UDP
            // payload is embedded in the New frame (required for server-side
            // GlobalID parsing).
            if (globalID == null) {
                val metadata = MuxFrameMetadata(
                    sessionID = sessionID,
                    status = MuxSessionStatus.NEW,
                    option = 0,
                    network = network,
                    targetHost = host,
                    targetPort = port,
                    globalID = null
                )

                val frame = encodeMuxFrame(metadata = metadata, payload = null)
                writeFrame(frame)
            }

            return session
        } catch (e: Exception) {
            sessions.remove(sessionID)
            throw e
        }
    }

    fun removeSession(sessionID: Int) {
        sessions.remove(sessionID)
        if (sessions.isEmpty()) {
            resetIdleTimer()
        }
    }

    fun closeAll() {
        if (closed) return
        closed = true

        idleTimerJob?.cancel()
        idleTimerJob = null

        val allSessions = sessions.values.toList()
        sessions.clear()

        for (session in allSessions) {
            session.deliverClose()
        }

        vlessConnection?.cancel()
        vlessClient?.cancel()
        vlessConnection = null
        vlessClient = null

        frameParser.reset()

        val pending = pendingConnections.toList()
        pendingConnections.clear()
        connecting = false
        for (deferred in pending) {
            deferred.completeExceptionally(ProxyError.ConnectionFailed("Mux client closed"))
        }
    }

    private suspend fun connectMux() {
        if (connected) return
        if (closed) throw ProxyError.ConnectionFailed("Mux client closed")

        if (connecting) {
            val deferred = kotlinx.coroutines.CompletableDeferred<Unit>()
            pendingConnections.add(deferred)
            deferred.await()
            return
        }

        connecting = true

        try {
            val client = VlessClient(configuration)
            this.vlessClient = client

            val connection = client.connectMux()
            this.vlessConnection = connection
            this.connected = true

            startReceiveLoop(connection)
            resetIdleTimer()

            connecting = false
            val pending = pendingConnections.toList()
            pendingConnections.clear()
            for (deferred in pending) {
                deferred.complete(Unit)
            }
        } catch (e: Exception) {
            logger.error("Mux connection failed: ${e.message}")
            connecting = false
            closeAll()
            throw e
        }
    }

    suspend fun writeFrame(data: ByteArray) {
        if (closed) throw ProxyError.ConnectionFailed("Mux client closed")

        writeMutex.withLock {
            try {
                val connection = vlessConnection
                    ?: throw ProxyError.ConnectionFailed("Mux client not connected")
                connection.sendRaw(data)
            } catch (e: Exception) {
                logger.error("Mux write error: ${e.message}")
                closeAll()
                throw e
            }
        }
    }

    /** Fire-and-forget write, used for End frames. */
    fun writeFrameAsync(data: ByteArray) {
        if (closed) return
        scope.launch {
            try {
                writeFrame(data)
            } catch (e: Exception) {
            }
        }
    }

    private fun startReceiveLoop(connection: ProxyConnection) {
        scope.launch {
            try {
                connection.startReceiving(
                    handler = { data ->
                        handleReceivedData(data)
                    },
                    errorHandler = { error ->
                        if (error != null) {
                            logger.error("Mux receive error: ${error.message}")
                        }
                        closeAll()
                    }
                )
            } catch (e: Exception) {
                logger.error("Mux receive loop error: ${e.message}")
                closeAll()
            }
        }
    }

    private fun handleReceivedData(data: ByteArray) {
        val frames = frameParser.feed(data)

        for ((metadata, payload) in frames) {
            when (metadata.status) {
                MuxSessionStatus.NEW -> {
                    // Server-initiated sessions are not expected for outbound mux.
                }

                MuxSessionStatus.KEEP -> {
                    val session = sessions[metadata.sessionID]
                    if (session != null && payload != null && payload.isNotEmpty()) {
                        session.deliverData(payload)
                    }
                }

                MuxSessionStatus.END -> {
                    val session = sessions[metadata.sessionID]
                    if (session != null) {
                        sessions.remove(metadata.sessionID)
                        session.deliverClose()
                    }
                }

                MuxSessionStatus.KEEP_ALIVE -> {
                }
            }
        }
    }

    private fun resetIdleTimer() {
        idleTimerJob?.cancel()
        idleTimerJob = null

        if (closed || sessions.isNotEmpty()) return

        idleTimerJob = scope.launch {
            delay(IDLE_TIMEOUT_MS)
            if (sessions.isEmpty()) {
                closeAll()
            }
        }
    }
}
