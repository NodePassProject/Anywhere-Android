package com.argsment.anywhere.vpn.protocol.mux

import com.argsment.anywhere.vpn.NativeBridge
import java.security.SecureRandom

/**
 * XUDP GlobalID generation using BLAKE3 keyed hash:
 * - BaseKey: random 32-byte key generated once per process lifetime
 * - GlobalID: blake3.New(8, BaseKey).Write([]byte(source.String()))
 *
 * The source string format is "udp:host:port".
 */
object Xudp {

    /** Random 32-byte key, generated once per process lifetime. */
    private val baseKey: ByteArray by lazy {
        ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    /**
     * @param sourceAddress The source address string in "udp:host:port" format.
     * @return 8-byte GlobalID.
     */
    fun generateGlobalID(sourceAddress: String): ByteArray {
        val input = sourceAddress.toByteArray(Charsets.UTF_8)
        val hash = NativeBridge.nativeBlake3KeyedHash(baseKey, input)
        return hash.copyOfRange(0, 8)
    }
}
