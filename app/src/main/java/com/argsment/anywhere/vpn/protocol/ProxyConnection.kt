package com.argsment.anywhere.vpn.protocol

import com.argsment.anywhere.data.model.TlsVersion
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.util.concurrent.atomic.AtomicLong

/** Common interface implemented by every proxy connection (VLESS, Trojan, Shadowsocks, SOCKS5, Naive). */
interface ProxyConnectionProtocol {
    val isConnected: Boolean

    suspend fun send(data: ByteArray)
    fun sendAsync(data: ByteArray)
    suspend fun receive(): ByteArray?
    suspend fun startReceiving(handler: suspend (ByteArray) -> Unit, errorHandler: suspend (Exception?) -> Unit)
    fun cancel()
}

/**
 * Abstract base class providing common proxy connection functionality.
 *
 * Subclasses must override [isConnected], [sendRaw], [sendRawAsync],
 * [receiveRaw], and [cancel]. Protocol-specific concerns (VLESS response-header
 * stripping, UDP framing, Trojan request header, …) live in subclasses or
 * composition wrappers, not here.
 */
abstract class ProxyConnection : ProxyConnectionProtocol {

    /** The negotiated TLS version of the outer transport, if applicable. */
    open val outerTlsVersion: TlsVersion? get() = null

    private val _bytesSent = AtomicLong(0)
    private val _bytesReceived = AtomicLong(0)
    val bytesSent: Long get() = _bytesSent.get()
    val bytesReceived: Long get() = _bytesReceived.get()

    override suspend fun send(data: ByteArray) {
        _bytesSent.addAndGet(data.size.toLong())
        sendRaw(data)
    }

    override fun sendAsync(data: ByteArray) {
        _bytesSent.addAndGet(data.size.toLong())
        sendRawAsync(data)
    }

    abstract suspend fun sendRaw(data: ByteArray)
    abstract fun sendRawAsync(data: ByteArray)

    override suspend fun receive(): ByteArray? {
        val data = receiveRaw()
        if (data != null && data.isNotEmpty()) {
            _bytesReceived.addAndGet(data.size.toLong())
        }
        return data
    }

    abstract suspend fun receiveRaw(): ByteArray?

    /** Receives raw data without transport decryption (for Vision direct copy mode). */
    open suspend fun receiveDirectRaw(): ByteArray? = receiveRaw()

    /** Sends raw data without transport encryption (for Vision direct copy mode). */
    open suspend fun sendDirectRaw(data: ByteArray) = sendRaw(data)
    open fun sendDirectRawAsync(data: ByteArray) = sendRawAsync(data)

    override suspend fun startReceiving(
        handler: suspend (ByteArray) -> Unit,
        errorHandler: suspend (Exception?) -> Unit
    ) = coroutineScope {
        // Pipeline: kick off the next receive BEFORE awaiting the handler so a
        // slow handler doesn't stall further frame ingest. Mirrors iOS
        // ProxyConnection.swift:132-149.
        var pending = async { receive() }
        try {
            while (true) {
                val data = pending.await()
                if (data == null || data.isEmpty()) {
                    errorHandler(null)
                    break
                }
                pending = async { receive() }
                handler(data)
            }
        } catch (e: Exception) {
            pending.cancel()
            errorHandler(e)
        }
    }
}
