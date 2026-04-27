package com.argsment.anywhere.vpn

import com.argsment.anywhere.vpn.util.AnywhereLogger

private val logger = AnywhereLogger("FakeIPPool")

/**
 * Manages a pool of synthetic ("fake") IP addresses mapped to domain names.
 *
 * When DNS queries for routed domains arrive, fake IPs are returned. When
 * connections to those fake IPs arrive later, the pool resolves them back to
 * the original domain and routing configuration.
 *
 * IPv4 range: 198.18.0.0/15 (offsets 1..[POOL_SIZE])
 * IPv6 range: fc00:: + offset (same offset range)
 *
 * Thread safety: every mutator/reader takes the intrinsic monitor on
 * [stateLock] so that calls from outside the lwIP executor (debug / stats)
 * cannot tear the LRU structure even if they momentarily race the DNS /
 * accept callbacks that normally drive allocation.
 */
class FakeIpPool {

    data class Entry(
        val domain: String
    )

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

    /** Single-purpose monitor for all mutable pool state. */
    private val stateLock = Any()

    /**
     * Allocate (or reuse) an offset for the given domain.
     * Use [ipv4Bytes] or [ipv6Bytes] to get the actual address bytes.
     *
     * Routing decisions are NOT stored in the entry — they are made at connection
     * time via [LwipStack.resolveFakeIp] which checks [DomainRouter]. This ensures
     * routing rule changes take effect immediately without rebuilding the pool.
     */
    fun allocate(domain: String): Int = synchronized(stateLock) {
        domainToOffset[domain]?.let { offset ->
            touchLru(offset)
            return@synchronized offset
        }

        val offset: Int
        if (nextOffset <= POOL_SIZE) {
            offset = nextOffset
            nextOffset++
        } else {
            offset = evictLru()
        }

        domainToOffset[domain] = offset
        offsetToEntry[offset] = Entry(domain)
        appendLru(offset)

        offset
    }

    fun lookup(ip: String): Entry? {
        val offset = ipToOffset(ip) ?: return null
        return synchronized(stateLock) {
            val entry = offsetToEntry[offset] ?: return@synchronized null
            touchLru(offset)
            entry
        }
    }

    fun reset() = synchronized(stateLock) {
        domainToOffset.clear()
        offsetToEntry.clear()
        offsetToNode.clear()
        lruHead = null
        lruTail = null
        nextOffset = 1
    }

    /** Returns the number of active entries. */
    val count: Int
        get() = synchronized(stateLock) { domainToOffset.size }

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
        // Should never happen — pool is full so the LRU list cannot be
        // empty. Fall back to offset 1 rather than crashing.
        val tail = lruTail ?: run {
            logger.debug("[FakeIPPool] evictLru called on empty list, falling back to offset 1")
            return 1
        }
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
        private val BASE_IPV4: Long = TunnelConstants.fakeIPPoolBaseIPv4
        val POOL_SIZE: Int = TunnelConstants.fakeIPPoolSize

        /** Fast check: is this IP in the fake IPv4 (198.18.0.0/15) or IPv6 (fc00:: + offset) range? */
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
