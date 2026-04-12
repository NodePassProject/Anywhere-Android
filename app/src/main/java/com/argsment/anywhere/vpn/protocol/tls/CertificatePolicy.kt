package com.argsment.anywhere.vpn.protocol.tls

import android.content.Context
import android.content.SharedPreferences
import com.argsment.anywhere.data.repository.CertificateRepository

/**
 * Thread-safe cache of the global certificate-validation policy. Both [TlsClient]
 * and the QUIC TLS handler consult this at validation time so they observe the
 * latest user preferences without needing to rebuild every [TlsConfiguration].
 *
 * Mirrors iOS `CertificatePolicy` (Protocols/Core/CertificatePolicy.swift):
 * values are refreshed when the user toggles `allowInsecure` or mutates the
 * trusted-certificate list — `VpnViewModel.signalCertificatePolicyChanged()`
 * writes a timestamp to prefs which [LwipStack] observes and uses to trigger
 * [reload].
 */
object CertificatePolicy {

    @Volatile
    private var _allowInsecure: Boolean = false

    @Volatile
    private var _trustedFingerprints: List<String> = emptyList()

    /** Whether the user has opted into accepting all certificates. */
    val allowInsecure: Boolean
        get() = _allowInsecure

    /** SHA-256 fingerprints the user has explicitly trusted (lowercase hex). */
    val trustedFingerprints: List<String>
        get() = _trustedFingerprints

    /** Re-read both values from SharedPreferences and the [CertificateRepository]. */
    fun reload(context: Context) {
        val prefs: SharedPreferences =
            context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        _allowInsecure = prefs.getBoolean("allowInsecure", false)
        _trustedFingerprints = CertificateRepository(context).fingerprints.value
    }

    /** Push a fresh fingerprint list (used by the app-side repository observer). */
    fun setTrustedFingerprints(fingerprints: List<String>) {
        _trustedFingerprints = fingerprints
    }
}
