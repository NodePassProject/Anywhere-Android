package com.argsment.anywhere.vpn

import android.util.Log
import com.argsment.anywhere.data.model.VlessConfiguration

/**
 * Manages a pool of synthetic ("fake") IP addresses mapped to domain names.
 *
 * When DNS queries for routed domains arrive, fake IPs are returned. When
 * connections to those fake IPs arrive later, the pool resolves them back to
 * the original domain and routing configuration.
 *
 * IPv4 range: 198.18.0.0/15 (offsets 1..131071)
 * IPv6 range: fc00:: + offset (same offset range)
 *
 * Thread safety: NOT internally synchronized. All access must be on the lwIP thread.
 */
class FakeIpPool {

    data class Entry(
        val domain: String,
        val configuration: VlessConfiguration?,  // null = DIRECT bypass
        val isDirect: Boolean
    )

    // IPv4: 198.18.0.0/15 → offsets 1..131071
    private val domainToOffset = HashMap<String, Int>()
    private val offsetToEntry = HashMap<Int, Entry>()

    // LRU doubly-linked list — O(1) touch/evict
    private class LruNode(val offset: Int) {
        var prev: LruNode? = null
        var next: LruNode? = null
    }

    private var lruHead: LruNode? = null  // most recently used
    private var lruTail: LruNode? = null  // least recently used
    private val offsetToNode = HashMap<Int, LruNode>()

    private var nextOffset = 1

    // -- Pool Operations --

    /**
     * Allocate (or reuse) an offset for the given domain.
     * Use [ipv4Bytes] or [ipv6Bytes] to get the actual address bytes.
     */
    fun allocate(domain: String, configuration: VlessConfiguration?, isDirect: Boolean): Pair<Int, Entry> {
        val entry = Entry(domain, configuration, isDirect)

        // Already allocated? Touch LRU and update entry (configuration may have changed)
        domainToOffset[domain]?.let { offset ->
            offsetToEntry[offset] = entry
            touchLru(offset)
            return offset to entry
        }

        // Need a new offset
        val offset: Int
        if (nextOffset <= POOL_SIZE) {
            offset = nextOffset
            nextOffset++
        } else {
            // Pool full — evict LRU
            offset = evictLru()
        }

        domainToOffset[domain] = offset
        offsetToEntry[offset] = entry
        appendLru(offset)

        val ip = ipv4Bytes(offset)
        Log.d(TAG, "[FakeIP] $domain → ${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}.${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}")
        return offset to entry
    }

    /** Look up an entry by its fake IP string (IPv4 or IPv6). */
    fun lookup(ip: String): Entry? {
        val offset = ipToOffset(ip) ?: return null
        val entry = offsetToEntry[offset] ?: return null
        touchLru(offset)
        return entry
    }

    /** Clear all mappings (called on full stop). */
    fun reset() {
        domainToOffset.clear()
        offsetToEntry.clear()
        offsetToNode.clear()
        lruHead = null
        lruTail = null
        nextOffset = 1
    }

    /**
     * Updates existing entries' configurations from the current routing rules.
     * Called on stack restart instead of [reset] so that apps holding cached fake IPs
     * still resolve to valid domain→proxy mappings.
     */
    fun rebuild(router: DomainRouter) {
        val domainsToRemove = mutableListOf<String>()

        for ((domain, offset) in domainToOffset) {
            val action = router.matchDomain(domain)
            if (action == null) {
                domainsToRemove.add(domain)
                continue
            }

            val isDirect: Boolean
            val configuration: VlessConfiguration?
            when (action) {
                is RouteAction.Direct -> {
                    isDirect = true
                    configuration = null
                }
                is RouteAction.Proxy -> {
                    isDirect = false
                    configuration = router.resolveConfiguration(action)
                    if (configuration == null) {
                        domainsToRemove.add(domain)
                        continue
                    }
                }
            }

            offsetToEntry[offset] = Entry(domain, configuration, isDirect)
        }

        for (domain in domainsToRemove) {
            domainToOffset.remove(domain)?.let { offset ->
                offsetToEntry.remove(offset)
                offsetToNode.remove(offset)?.let { node -> removeNode(node) }
            }
        }

        if (domainsToRemove.isNotEmpty()) {
            Log.i(TAG, "[FakeIP] Rebuild: removed ${domainsToRemove.size} stale entries, ${domainToOffset.size} active")
        }
    }

    // -- IP ↔ Offset Conversion --

    private fun ipToOffset(ip: String): Int? {
        return if (ip.contains(':')) ipv6ToOffset(ip) else ipv4ToOffset(ip)
    }

    private fun ipv4ToOffset(ip: String): Int? {
        val parts = ip.split('.')
        if (parts.size != 4) return null
        val a = parts[0].toLongOrNull() ?: return null
        val b = parts[1].toLongOrNull() ?: return null
        val c = parts[2].toLongOrNull() ?: return null
        val d = parts[3].toLongOrNull() ?: return null
        val ip32 = (a shl 24) or (b shl 16) or (c shl 8) or d
        val offset = (ip32 - BASE_IPV4).toInt()
        if (offset < 1 || offset > POOL_SIZE) return null
        return offset
    }

    private fun ipv6ToOffset(ip: String): Int? {
        val bytes = parseIpv6(ip) ?: return null
        if (bytes.size != 16) return null
        // Verify fc00:: prefix (bytes 0-1 = 0xFC00, bytes 2-11 = 0)
        if (bytes[0] != 0xFC.toByte() || bytes[1] != 0x00.toByte()) return null
        for (i in 2..11) {
            if (bytes[i] != 0.toByte()) return null
        }
        // Extract offset from bytes 12-15
        val offset = ((bytes[12].toInt() and 0xFF) shl 24) or
                ((bytes[13].toInt() and 0xFF) shl 16) or
                ((bytes[14].toInt() and 0xFF) shl 8) or
                (bytes[15].toInt() and 0xFF)
        if (offset < 1 || offset > POOL_SIZE) return null
        return offset
    }

    /** Minimal IPv6 parser (handles :: expansion). */
    private fun parseIpv6(ip: String): ByteArray? {
        val result = ByteArray(16)
        val doubleColonIndex = ip.indexOf("::")
        if (doubleColonIndex >= 0) {
            val left = if (doubleColonIndex == 0) emptyList()
            else ip.substring(0, doubleColonIndex).split(':')
            val right = if (doubleColonIndex + 2 >= ip.length) emptyList()
            else ip.substring(doubleColonIndex + 2).split(':')
            val totalGroups = left.size + right.size
            if (totalGroups > 8) return null
            var pos = 0
            for (group in left) {
                val value = group.toIntOrNull(16) ?: return null
                result[pos++] = (value shr 8).toByte()
                result[pos++] = (value and 0xFF).toByte()
            }
            // Fill zeros for :: expansion
            pos = 16 - right.size * 2
            for (group in right) {
                val value = group.toIntOrNull(16) ?: return null
                result[pos++] = (value shr 8).toByte()
                result[pos++] = (value and 0xFF).toByte()
            }
        } else {
            val groups = ip.split(':')
            if (groups.size != 8) return null
            var pos = 0
            for (group in groups) {
                val value = group.toIntOrNull(16) ?: return null
                result[pos++] = (value shr 8).toByte()
                result[pos++] = (value and 0xFF).toByte()
            }
        }
        return result
    }

    // -- LRU Doubly-Linked List (O(1) operations) --

    private fun touchLru(offset: Int) {
        val node = offsetToNode[offset] ?: return
        removeNode(node)
        insertAtHead(node)
    }

    private fun appendLru(offset: Int) {
        val node = LruNode(offset)
        offsetToNode[offset] = node
        insertAtHead(node)
    }

    private fun evictLru(): Int {
        val tail = lruTail ?: error("evictLru called on empty list")
        val offset = tail.offset
        removeNode(tail)
        offsetToNode.remove(offset)
        offsetToEntry.remove(offset)?.let { entry ->
            domainToOffset.remove(entry.domain)
        }
        return offset
    }

    private fun removeNode(node: LruNode) {
        node.prev?.next = node.next
        node.next?.prev = node.prev
        if (node === lruHead) lruHead = node.next
        if (node === lruTail) lruTail = node.prev
        node.prev = null
        node.next = null
    }

    private fun insertAtHead(node: LruNode) {
        node.next = lruHead
        node.prev = null
        lruHead?.prev = node
        lruHead = node
        if (lruTail == null) lruTail = node
    }

    companion object {
        private const val TAG = "FakeIpPool"

        private const val BASE_IPV4: Long = 0xC6120000L  // 198.18.0.0
        const val POOL_SIZE = 131_071  // usable offsets

        /** Fast check: is this IP in the fake IPv4 (198.18.0.0/15) or IPv6 (fc00::/18) range? */
        fun isFakeIp(ip: String): Boolean =
            ip.startsWith("198.18.") || ip.startsWith("198.19.") || ip.startsWith("fc00::")

        /** Convert an offset to 4-byte IPv4 address. */
        fun ipv4Bytes(offset: Int): ByteArray {
            val ip32 = BASE_IPV4 + offset
            return byteArrayOf(
                ((ip32 shr 24) and 0xFF).toByte(),
                ((ip32 shr 16) and 0xFF).toByte(),
                ((ip32 shr 8) and 0xFF).toByte(),
                (ip32 and 0xFF).toByte()
            )
        }

        /** Convert an offset to 16-byte IPv6 address (fc00:: + offset). */
        fun ipv6Bytes(offset: Int): ByteArray = byteArrayOf(
            0xFC.toByte(), 0x00,  // fc00
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            ((offset shr 24) and 0xFF).toByte(),
            ((offset shr 16) and 0xFF).toByte(),
            ((offset shr 8) and 0xFF).toByte(),
            (offset and 0xFF).toByte()
        )
    }
}
