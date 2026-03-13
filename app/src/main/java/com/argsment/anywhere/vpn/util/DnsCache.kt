package com.argsment.anywhere.vpn.util

import android.util.Log
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

private const val TAG = "DnsCache"

/**
 * Thread-safe DNS cache with TTL-based expiry.
 *
 * Wraps [InetAddress.getAllByName] with caching so repeated lookups for the same
 * host (e.g. during latency tests or reconnects) avoid redundant system DNS calls.
 *
 * IP addresses bypass the cache entirely. Results are stored as IP strings so they
 * can be shared by both TCP ([NioSocket]) and UDP callers.
 *
 * Modeled after the iOS `DNSCache` (General/DNSCache.swift).
 */
object DnsCache {

    private const val DEFAULT_TTL_MS = 120_000L

    private data class CacheEntry(val ips: List<String>, val expiry: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    /**
     * Resolves a hostname to all IP address strings, using the cache when available.
     *
     * - If [host] is already an IP address, returns it directly without caching.
     * - If [host] is a domain, checks the cache first. On miss or expiry,
     *   calls [InetAddress.getAllByName] and caches the result.
     *
     * @return All resolved IP addresses (IPv4 and IPv6), or empty on failure.
     */
    fun resolveAll(host: String): List<String> {
        val bare = stripBrackets(host)
        if (isIpAddress(bare)) return listOf(bare)

        val key = bare.lowercase()

        cache[key]?.let { entry ->
            if (System.currentTimeMillis() < entry.expiry) return entry.ips
        }

        // Cache miss — resolve via system DNS
        val ips = try {
            InetAddress.getAllByName(bare)
                .mapNotNull { it.hostAddress }
                .distinct()
        } catch (e: Exception) {
            Log.w(TAG, "DNS resolution failed for $bare: ${e.message}")
            emptyList()
        }

        if (ips.isNotEmpty()) {
            cache[key] = CacheEntry(ips, System.currentTimeMillis() + DEFAULT_TTL_MS)
        }

        return ips
    }

    /**
     * Convenience: returns a single resolved IP (first result), or `null` on failure.
     */
    fun resolveHost(host: String): String? = resolveAll(host).firstOrNull()

    /**
     * Pre-resolves and caches a hostname so subsequent lookups are instant.
     * Intended for latency tester pre-warming.
     */
    fun prewarm(host: String) {
        resolveAll(host)
    }

    /**
     * Returns `true` if [host] is an IPv4 or IPv6 address literal.
     */
    fun isIpAddress(host: String): Boolean {
        // Quick check: if it contains a colon it might be IPv6, if all digits/dots it might be IPv4
        return try {
            val addr = InetAddress.getByName(host)
            addr.hostAddress == host
        } catch (_: Exception) {
            false
        }
    }

    private fun stripBrackets(host: String): String {
        return if (host.startsWith("[") && host.endsWith("]")) {
            host.substring(1, host.length - 1)
        } else {
            host
        }
    }
}
