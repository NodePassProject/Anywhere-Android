package com.argsment.anywhere.vpn.util

import com.argsment.anywhere.vpn.LwipStack
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2Error

/**
 * Shared error-reporting helper for TCP/UDP connections.
 *
 * Consolidates classification logic: trimming redundant prefixes from
 * socket error descriptions, demoting expected cascade errors so one peer
 * reset doesn't produce a wall of lines, and attributing failures to a
 * recent tunnel interruption when one is still within the attribution
 * window.
 */
object TransportErrorLogger {

    /**
     * Strips the `"<Operation>: "` prefix that protocol errors already bake
     * in, since the operation word is also in the log line.
     */
    fun conciseErrorDescription(error: Throwable): String {
        var message = (error.message ?: error.toString()).trim()
        val redundantPrefixes = listOf(
            "Connection failed: ",
            "Send failed: ",
            "Receive failed: ",
            "DNS resolution failed: "
        )
        for (prefix in redundantPrefixes) {
            if (message.startsWith(prefix)) {
                message = message.substring(prefix.length)
                break
            }
        }
        return message
    }

    /**
     * Walks the cause chain looking for an [android.system.ErrnoException].
     * Returns the underlying POSIX errno, or null if none is found.
     */
    private fun extractErrno(error: Throwable): Int? {
        var cur: Throwable? = error
        var depth = 0
        while (cur != null && depth < 8) {
            if (cur is android.system.ErrnoException) return cur.errno
            cur = cur.cause
            depth++
        }
        return null
    }

    /**
     * Matches errors that only occur after the peer has already dropped —
     * secondary to an earlier RST/EOF, no new information. Errno-based to
     * match iOS `SocketError.posixErrno == EPIPE`; falls back to a string
     * check for paths where the JVM didn't preserve errno.
     */
    private fun isPeerGoneCascade(error: Throwable, description: String): Boolean {
        val errno = extractErrno(error)
        if (errno == android.system.OsConstants.EPIPE) return true
        return description == "Broken pipe"
    }

    /**
     * Peer-initiated RST — normal termination from the remote, not a failure
     * here. Demoted to info so peer resets stay visible in the log viewer
     * but out of the error stream. Errno-based to match iOS
     * `SocketError.posixErrno == ECONNRESET`.
     */
    private fun isPeerReset(error: Throwable, description: String): Boolean {
        val errno = extractErrno(error)
        if (errno == android.system.OsConstants.ECONNRESET) return true
        return description == "Connection reset by peer" ||
            description == "Connection reset"
    }

    /**
     * Human-readable description for an lwIP `err_t` value delivered via
     * the `tcp_err` callback.
     */
    fun describeLwIPError(err: Int): String = when (err) {
        0 -> "ERR_OK"
        -1 -> "ERR_MEM (out of memory)"
        -2 -> "ERR_BUF (buffer error)"
        -3 -> "ERR_TIMEOUT (timed out)"
        -4 -> "ERR_RTE (routing problem)"
        -5 -> "ERR_INPROGRESS"
        -6 -> "ERR_VAL (illegal value)"
        -7 -> "ERR_WOULDBLOCK"
        -8 -> "ERR_USE (address in use)"
        -9 -> "ERR_ALREADY (already connecting)"
        -10 -> "ERR_ISCONN (already connected)"
        -11 -> "ERR_CONN (not connected)"
        -12 -> "ERR_IF (low-level netif error)"
        -13 -> "ERR_ABRT (aborted locally)"
        -14 -> "ERR_RST (reset by peer)"
        -15 -> "ERR_CLSD (connection closed)"
        -16 -> "ERR_ARG (illegal argument)"
        else -> "lwIP err=$err"
    }

    /**
     * Logs a transport-level failure with a consistent shape and level.
     *
     * Classification, in order:
     * 1. [Http2Error] is downgraded to `debug` — GOAWAY / stream reset is
     *    normal churn in a long-lived h2 tunnel.
     * 2. "Broken pipe" on send is demoted to `debug` — by definition a
     *    cascade behind an earlier receive error or RST.
     * 3. "Connection reset by peer" is demoted to `info` — expected
     *    termination from the remote's side, not a local failure.
     * 4. Otherwise the failure logs at [defaultLevel].
     */
    fun log(
        operation: String,
        endpoint: String,
        error: Throwable,
        logger: AnywhereLogger,
        prefix: String,
        defaultLevel: LwipStack.LogLevel = LwipStack.LogLevel.ERROR
    ) {
        val errorDescription = conciseErrorDescription(error)

        if (error is Http2Error) {
            logger.debug("$prefix $operation error: $endpoint: $errorDescription")
            return
        }

        if (isPeerGoneCascade(error, errorDescription)) {
            logger.debug("$prefix $operation after peer close: $endpoint: $errorDescription")
            return
        }

        if (isPeerReset(error, errorDescription)) {
            logger.info("$prefix $operation failed: $endpoint: $errorDescription")
            return
        }

        when (defaultLevel) {
            LwipStack.LogLevel.INFO ->
                logger.info("$prefix $operation failed: $endpoint: $errorDescription")
            LwipStack.LogLevel.WARNING ->
                logger.warning("$prefix $operation failed: $endpoint: $errorDescription")
            LwipStack.LogLevel.ERROR ->
                logger.error("$prefix $operation failed: $endpoint: $errorDescription")
        }
    }
}
