package com.argsment.anywhere.vpn.protocol.naive

import android.util.Base64

/**
 * Configuration for a NaiveProxy connection.
 */
class NaiveConfiguration(
    val proxyHost: String,
    val proxyPort: Int,
    val username: String?,
    val password: String?,
    /** TLS SNI override. Defaults to [proxyHost] when null. */
    val sni: String?,
    val scheme: NaiveScheme
) {
    enum class NaiveScheme {
        HTTP11,  // HTTP/1.1 CONNECT over TLS
        HTTP2    // HTTP/2 CONNECT over TLS
    }

    /** The SNI value to use during the TLS handshake. */
    val effectiveSNI: String get() = sni ?: proxyHost

    /** Base64-encoded `user:pass` for Proxy-Authorization, or null if no credentials. */
    val basicAuth: String?
        get() {
            if (username == null || password == null) return null
            return Base64.encodeToString("$username:$password".toByteArray(), Base64.NO_WRAP)
        }
}
