package com.argsment.anywhere.vpn.protocol.mux

import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.ProxyError
import com.argsment.anywhere.vpn.protocol.vless.VlessClient
import com.argsment.anywhere.vpn.protocol.vless.VlessConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.CoroutineContext

private val logger = AnywhereLogger("MuxClient")

/**
 * Single mux connection over VLESS with session management.
 * Write serialization, receive loop with frame parsing, 16s idle timeout.
 * XUDP support.
 */
class MuxClient(
    val configuration: ProxyConfiguration,
    private val coroutineContext: CoroutineContext
) {
    private val scope = CoroutineScope(coroutineContext)

    private var vlessClient: VlessClient? = null
    private var vlessConnection: VlessConnection? = null
    private val sessions = mutableMapOf<Int, MuxSession>()
    private var nextSessionID: Int = 1
    private var connecting = false
    private var connected = false

    @Volatile
    var closed: Boolean = false
        private set

    // Write serialization (frames must not interleave)
    private val writeMutex = Mutex()

    // Receive loop + frame parser
    private val frameParser = MuxFrameParser()

    // 16s idle timer (matching Xray-core)
    private var idleTimerJob: Job? = null

    private var isXUDP = false

    val sessionCount: Int get() = sessions.size
    val isFull: Boolean get() = closed || isXUDP

    // Pending connect continuations (queued while connecting)
    private val connectMutex = Mutex()
    private val pendingConnections = mutableListOf<kotlinx.coroutines.CompletableDeferred<Unit>>()

    companion object {
        private const val IDLE_TIMEOUT_MS = 16_000L
    }

    // =========================================================================
    // Session Management
    // =========================================================================

    /**
     * Creates a new mux session for the given target.
     * Lazily connects the underlying VLESS connection on first use.
     */
    suspend fun createSession(
        network: MuxNetwork,
        host: String,
        port: Int,
        globalID: ByteArray?
    ): MuxSession {
        if (closed) throw ProxyError.ConnectionFailed("Mux client closed")

        val sessionID: Int
        if (globalID != null) {
            // XUDP: one flow per mux connection, always session ID 0
            sessionID = 0
            isXUDP = true
        } else {
            sessionID = nextSessionID
            nextSessionID = (nextSessionID + 1) and 0xFFFF
            // Skip 0 (reserved)
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

        // Reset idle timer when a new session is added
        resetIdleTimer()

        try {
            // Ensure underlying VLESS connection is established
            if (!connected) {
                connectMux()
            }

            // For XUDP (globalID != null), defer the New frame until first data
            // so the first UDP payload is embedded in the New frame.
            // This matches iOS behavior and is needed for server-side GlobalID parsing.
            if (globalID == null) {
                // Send New frame with target address
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

    /**
     * Removes a session from the map (called by MuxSession on close).
     */
    fun removeSession(sessionID: Int) {
        sessions.remove(sessionID)
        if (sessions.isEmpty()) {
            resetIdleTimer()
        }
    }

    /**
     * Closes all sessions and the underlying VLESS connection.
     */
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

        // Complete any pending connections with error
        val pending = pendingConnections.toList()
        pendingConnections.clear()
        connecting = false
        for (deferred in pending) {
            deferred.completeExceptionally(ProxyError.ConnectionFailed("Mux client closed"))
        }
    }

    // =========================================================================
    // VLESS Mux Connection
    // =========================================================================

    private suspend fun connectMux() {
        if (connected) return
        if (closed) throw ProxyError.ConnectionFailed("Mux client closed")

        // If already connecting, wait for the result
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

            // Start receive loop
            startReceiveLoop(connection)
            resetIdleTimer()

            // Complete all pending connections
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

    // =========================================================================
    // Write Serialization
    // =========================================================================

    /**
     * Writes a frame with serialization (suspend, waits for completion).
     */
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

    /**
     * Writes a frame asynchronously (fire-and-forget, used for End frames).
     */
    fun writeFrameAsync(data: ByteArray) {
        if (closed) return
        scope.launch {
            try {
                writeFrame(data)
            } catch (e: Exception) {
                // Already handled in writeFrame
            }
        }
    }

    // =========================================================================
    // Receive Loop
    // =========================================================================

    private fun startReceiveLoop(connection: VlessConnection) {
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
                    // Server-initiated sessions -- not expected for outbound mux, ignore
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
                    // Ping from server -- no action needed
                }
            }
        }
    }

    // =========================================================================
    // Idle Timer
    // =========================================================================

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
