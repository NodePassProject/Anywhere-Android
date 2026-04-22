package com.argsment.anywhere.vpn.util

import com.argsment.anywhere.vpn.LwipStack
import com.argsment.anywhere.vpn.protocol.naive.http2.Http2Error

/**
 * Shared error-reporting helper for TCP/UDP connections.
 *
 * Consolidates the classification logic that both [com.argsment.anywhere.vpn.LwipTcpConnection]
 * and [com.argsment.anywhere.vpn.LwipUdpFlow] used to duplicate: trimming
 * redundant prefixes from socket error descriptions, demoting expected
 * cascade errors so one peer reset doesn't produce a wall of lines, and
 * attributing failures to a recent tunnel interruption when one is still
 * within the attribution window.
 *
 * Mirrors iOS `TransportErrorLogger` in
 * `Anywhere Network Extension/TransportErrorLogger.swift`.
 */
object TransportErrorLogger {

    // -- Formatting --

    /**
     * Strips the `"<Operation>: "` prefix that protocol errors already bake
     * in, because the operation word is also in our log line.
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
     * Matches strerror outputs for errors that only occur after the peer
     * has already dropped — secondary to an earlier RST/EOF, no new
     * information. Mirrors iOS `TransportErrorLogger` `EPIPE` demotion to
     * `.cascade`.
     */
    private fun isPeerGoneCascade(description: String): Boolean =
        description == "Broken pipe"

    /**
     * Matches strerror outputs for a peer-initiated RST — normal
     * termination from the remote's side, not a failure of ours. Mirrors
     * iOS `TransportErrorLogger` `ECONNRESET` demotion to `.reset` so
     * peer resets stay visible in the log viewer but out of the error
     * stream. iOS uses `SocketError.posixErrno == ECONNRESET`; Android
     * matches against the localized description the kernel surfaces
     * through `ErrnoException` / `IOException`.
     */
    private fun isPeerReset(description: String): Boolean =
        description == "Connection reset by peer" ||
            description == "Connection reset"

    // -- lwIP Error Codes --

    /**
     * Human-readable description for an lwIP `err_t` value delivered via
     * the `tcp_err` callback. Mirrors the definitions in
     * `lwip/src/include/lwip/err.h` and iOS
     * `TransportErrorLogger.describeLwIPError`.
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

    // -- Classified Logging --

    /**
     * Logs a transport-level failure with a consistent shape and level.
     *
     * Classification, in order:
     * 1. [Http2Error] is downgraded to `debug` — GOAWAY / stream reset
     *    is normal churn in a long-lived h2 tunnel and doesn't indicate
     *    a user-visible problem.
     * 2. "Broken pipe" on send is demoted to `debug` — by definition a
     *    cascade behind an earlier receive error or RST. Logging it
     *    would double-report.
     * 3. "Connection reset by peer" is demoted to `info` — expected
     *    termination from the remote's side, not our failure. Matches
     *    iOS `ECONNRESET` → `.reset` demotion.
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

        if (isPeerGoneCascade(errorDescription)) {
            logger.debug("$prefix $operation after peer close: $endpoint: $errorDescription")
            return
        }

        if (isPeerReset(errorDescription)) {
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
