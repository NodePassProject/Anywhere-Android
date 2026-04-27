package com.argsment.anywhere.data.repository

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Manages user-trusted certificate SHA-256 fingerprints.
 *
 * Fingerprints are stored in SharedPreferences so both the main app
 * and the VPN service can access them. TlsClient checks these
 * when system trust evaluation fails.
 */
class CertificateRepository(context: Context) {

    companion object {
        private const val KEY = "trustedCertificateSHA256s"
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)

    private val _fingerprints = MutableStateFlow<List<String>>(emptyList())
    val fingerprints: StateFlow<List<String>> = _fingerprints.asStateFlow()

    init {
        load()
    }

    /**
     * Adds a SHA-256 fingerprint (hex string, case-insensitive).
     * Returns false if the fingerprint is invalid or already exists.
     */
    fun add(fingerprint: String): Boolean {
        val normalized = normalize(fingerprint)
        if (normalized.length != 64 || !normalized.all { it in '0'..'9' || it in 'a'..'f' }) return false
        val current = _fingerprints.value
        if (current.contains(normalized)) return false
        val updated = current + normalized
        _fingerprints.value = updated
        save(updated)
        return true
    }

    fun remove(fingerprint: String) {
        val normalized = normalize(fingerprint)
        val updated = _fingerprints.value.filter { it != normalized }
        _fingerprints.value = updated
        save(updated)
    }

    fun removeAt(indices: Set<Int>) {
        val updated = _fingerprints.value.filterIndexed { index, _ -> index !in indices }
        _fingerprints.value = updated
        save(updated)
    }

    fun contains(fingerprint: String): Boolean =
        _fingerprints.value.contains(normalize(fingerprint))

    private fun normalize(fp: String) =
        fp.replace(":", "").replace(" ", "").lowercase()

    private fun save(list: List<String>) {
        prefs.edit()
            .putStringSet(KEY, list.toSet())
            // Bumping this counter triggers the VPN service's prefs listener
            // (LwipStack.prefsListener) which throttles → CertificatePolicy.reload.
            // Mirrors iOS AWCore.notifyCertificatePolicyChanged().
            .putLong("certificatePolicyChanged", System.currentTimeMillis())
            .apply()
    }

    private fun load() {
        _fingerprints.value = prefs.getStringSet(KEY, emptySet())?.toList() ?: emptyList()
    }
}
