package com.argsment.anywhere.vpn.util

import android.net.Network
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
 * When an underlying [Network] is set (via [setUnderlyingNetwork]), DNS resolution
 * uses that network, bypassing the VPN tunnel. This matches the iOS behavior where
 * `ProxyDNSCache` resolves through the physical network interface via `getaddrinfo`.
 *
 * IP addresses bypass the cache entirely. Results are stored as IP strings so they
 * can be shared by both TCP ([NioSocket]) and UDP callers.
 *
 * Modeled after the iOS `ProxyDNSCache` (General/ProxyDNSCache.swift).
 */
object DnsCache {

    private const val DEFAULT_TTL_MS = 120_000L
    private const val EVICTION_THRESHOLD = 256
    private val ipv4Regex = Regex("""^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")

    private data class CacheEntry(val ips: List<String>, val expiry: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    @Volatile
    private var activeProxyDomain: String? = null

    /**
     * The underlying physical network for DNS resolution.
     * When set, [resolveAndCache] uses [Network.getAllByName] to resolve through the
     * physical interface, bypassing the VPN tunnel. This prevents circular dependency
     * where proxy DNS resolution would go through the (possibly broken) proxy tunnel.
     *
     * Matching iOS behavior: `ProxyDNSCache.resolveViaGetaddrinfo()` always resolves
     * through the physical network interface in the Network Extension.
     */
    @Volatile
    private var underlyingNetwork: Network? = null

    fun setActiveProxyDomain(domain: String?) {
        activeProxyDomain = domain?.let { stripBrackets(it).lowercase() }
    }

    /**
     * Sets the underlying physical network for DNS resolution.
     * Called from VpnService after the tunnel is established.
     * Pass `null` when VPN is stopped to revert to default resolution.
     */
    fun setUnderlyingNetwork(network: Network?) {
        underlyingNetwork = network
    }

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
        val now = System.currentTimeMillis()

        cache[key]?.let { entry ->
            if (now < entry.expiry) return entry.ips
            // Expired entry — remove it (prevents unbounded cache growth)
            cache.remove(key)
            if (activeProxyDomain == key) {
                refreshAsync(key, bare)
                return entry.ips
            }
        }

        // Periodic eviction: when cache exceeds threshold, purge all expired entries
        if (cache.size > EVICTION_THRESHOLD) {
            evictExpired(now)
        }

        // Cache miss — resolve via system DNS
        val ips = resolveAndCache(key, bare)
        if (ips.isNotEmpty()) return ips

        return cache[key]?.ips ?: emptyList()
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

    fun cachedIPs(host: String): List<String>? {
        val bare = stripBrackets(host)
        if (isIpAddress(bare)) return listOf(bare)
        return cache[bare.lowercase()]?.ips
    }

    /**
     * Returns `true` if [host] is an IPv4 or IPv6 address literal.
     */
    fun isIpAddress(host: String): Boolean {
        val bare = stripBrackets(host)

        // Never call InetAddress on arbitrary domains here: that would trigger a
        // real DNS lookup and can recurse back into the VPN tunnel.
        if (ipv4Regex.matches(bare)) return true
        if (!bare.contains(':')) return false

        return try {
            InetAddress.getByName(bare) is Inet6Address
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

    private fun evictExpired(now: Long) {
        val iter = cache.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next()
            if (now >= entry.value.expiry && entry.key != activeProxyDomain) {
                iter.remove()
            }
        }
    }

    private fun refreshAsync(key: String, bare: String) {
        Thread({
            resolveAndCache(key, bare)
        }, "DnsCache-refresh").apply { isDaemon = true }.start()
    }

    private fun resolveAndCache(key: String, bare: String): List<String> {
        val ips = try {
            // Resolve through the underlying physical network when available,
            // bypassing the VPN tunnel. Matches iOS ProxyDNSCache.resolveViaGetaddrinfo()
            // which always resolves through the physical interface in the Network Extension.
            val network = underlyingNetwork
            val addresses = if (network != null) {
                network.getAllByName(bare)
            } else {
                InetAddress.getAllByName(bare)
            }
            addresses.mapNotNull { it.hostAddress }.distinct()
        } catch (e: Exception) {
            Log.w(TAG, "DNS resolution failed for $bare: ${e.message}")
            emptyList()
        }

        if (ips.isNotEmpty()) {
            cache[key] = CacheEntry(ips, System.currentTimeMillis() + DEFAULT_TTL_MS)
        }

        return ips
    }
}
