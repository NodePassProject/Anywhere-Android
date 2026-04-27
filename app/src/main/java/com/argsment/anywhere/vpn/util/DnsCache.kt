package com.argsment.anywhere.vpn.util

import android.net.Network
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

private val logger = AnywhereLogger("ProxyDNSCache")

/**
 * Thread-safe DNS cache with TTL-based expiry.
 *
 * Wraps [InetAddress.getAllByName] with caching so repeated lookups for the same
 * host avoid redundant system DNS calls.
 *
 * When an underlying [Network] is set (via [setUnderlyingNetwork]), DNS resolution
 * uses that network, bypassing the VPN tunnel.
 *
 * IP addresses bypass the cache entirely. Results are stored as IP strings so they
 * can be shared by both TCP ([NioSocket]) and UDP callers.
 */
object DnsCache {

    private const val DEFAULT_TTL_MS = 120_000L
    private const val EVICTION_THRESHOLD = 256
    private val ipv4Regex = Regex("""^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")
    /** Coarse character-set guard for IPv6 literals (hex, colon, dot for IPv4-mapped, `%scope`). */
    private val ipv6LiteralForm = Regex("""^[0-9A-Fa-f:.]+(?:%[0-9A-Za-z._-]+)?$""")

    private data class CacheEntry(val ips: List<String>, val expiry: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    @Volatile
    private var activeProxyDomain: String? = null

    /**
     * Underlying physical network for DNS resolution. When set, [resolveAndCache]
     * resolves through the physical interface, bypassing the VPN tunnel — this
     * prevents a circular dependency where proxy DNS resolution would route
     * through the (possibly broken) proxy tunnel.
     */
    @Volatile
    private var underlyingNetwork: Network? = null

    fun setActiveProxyDomain(domain: String?) {
        activeProxyDomain = domain?.let { stripBrackets(it).lowercase() }
    }

    /**
     * Pass `null` when VPN is stopped to revert to default resolution.
     */
    fun setUnderlyingNetwork(network: Network?) {
        underlyingNetwork = network
    }

    fun resolveAll(host: String): List<String> {
        val bare = stripBrackets(host)
        if (isIpAddress(bare)) return listOf(bare)

        val key = bare.lowercase()
        val now = System.currentTimeMillis()
        val isActive = activeProxyDomain == key

        val entry = cache[key]
        if (entry != null && now < entry.expiry) return entry.ips

        // Active proxy with stale cache: return stale IPs immediately and refresh
        // in the background. Avoids blocking connections on the active proxy when
        // TTL expires; the stale entry stays in place so concurrent lookups
        // benefit and a failed refresh still has a fallback.
        if (entry != null && isActive) {
            refreshAsync(key, bare)
            return entry.ips
        }

        if (cache.size > EVICTION_THRESHOLD) {
            evictExpired(now)
        }

        val ips = resolveAndCache(key, bare)
        if (ips.isNotEmpty()) return ips

        // Resolution failed: fall back to stale IPs if available.
        return entry?.ips ?: emptyList()
    }

    fun resolveHost(host: String): String? = resolveAll(host).firstOrNull()

    fun prewarm(host: String) {
        resolveAll(host)
    }

    fun cachedIPs(host: String): List<String>? {
        val bare = stripBrackets(host)
        if (isIpAddress(bare)) return listOf(bare)
        return cache[bare.lowercase()]?.ips
    }

    fun isIpAddress(host: String): Boolean {
        val bare = stripBrackets(host)

        // Never call InetAddress on arbitrary domains here: that would trigger a
        // real DNS lookup and can recurse back into the VPN tunnel.
        if (ipv4Regex.matches(bare)) return true
        if (!bare.contains(':')) return false
        // IPv6 literals only contain hex digits, colons, dots (for IPv4-mapped
        // forms), and an optional `%scope` suffix. Reject anything else
        // before handing to InetAddress so a colon-bearing hostname (rare,
        // but legal in some intranet stacks) can never escape into a
        // synchronous DNS lookup.
        if (!ipv6LiteralForm.matches(bare)) return false

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
            // bypassing the VPN tunnel.
            val network = underlyingNetwork
            val addresses = if (network != null) {
                network.getAllByName(bare)
            } else {
                InetAddress.getAllByName(bare)
            }
            addresses.mapNotNull { it.hostAddress }.distinct()
        } catch (e: Exception) {
            logger.warning("[DNS] Resolution failed for $bare")
            emptyList()
        }

        if (ips.isNotEmpty()) {
            cache[key] = CacheEntry(ips, System.currentTimeMillis() + DEFAULT_TTL_MS)
        }

        return ips
    }
}
