package com.argsment.anywhere.vpn.protocol.tls

import android.content.Context
import android.content.SharedPreferences
import com.argsment.anywhere.data.repository.CertificateRepository

/**
 * Thread-safe cache of the global certificate-validation policy. [TlsClient]
 * consults this at validation time so it observes the latest user preferences
 * without needing to rebuild every [TlsConfiguration].
 */
object CertificatePolicy {

    @Volatile
    private var _allowInsecure: Boolean = false

    @Volatile
    private var _trustedFingerprints: List<String> = emptyList()

    val allowInsecure: Boolean
        get() = _allowInsecure

    /** SHA-256 fingerprints the user has explicitly trusted (lowercase hex). */
    val trustedFingerprints: List<String>
        get() = _trustedFingerprints

    fun reload(context: Context) {
        val prefs: SharedPreferences =
            context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        _allowInsecure = prefs.getBoolean("allowInsecure", false)
        _trustedFingerprints = CertificateRepository(context).fingerprints.value
    }

    fun setTrustedFingerprints(fingerprints: List<String>) {
        _trustedFingerprints = fingerprints
    }

    /** Pushes the latest allowInsecure value so callers see the change without waiting
     *  for the tunnel to reload. */
    fun setAllowInsecure(value: Boolean) {
        _allowInsecure = value
    }
}
