package com.argsment.anywhere.vpn

import android.content.Context
import com.argsment.anywhere.data.model.DomainRuleType
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.serialization.json.Json
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.util.UUID

sealed class RouteAction {
    data object Direct : RouteAction()
    data object Reject : RouteAction()
    data class Proxy(val configId: UUID) : RouteAction()
}

/**
 * Domain/IP routing engine.
 *
 * Rules are loaded from a JSON descriptor emitted by [RuleSetRepository.syncRoutingFile].
 * Country-bypass rules (if present) are inserted first as [RouteAction.Direct];
 * user rules then overwrite on conflict, giving the priority ordering
 * `country bypass → Direct → services → custom → ADBlock`.
 *
 *  - Domain matching: reverse-label suffix trie — O(k) where k = label count.
 *  - IP matching: binary CIDR tries — O(32) IPv4 / O(128) IPv6, independent of rule count.
 */
class DomainRouter(private val context: Context) {

    // DOMAIN-SUFFIX rules live in a reverse-label trie: "www.google.com" is
    // inserted as ["com","google","www"]. Lookup walks the domain from the
    // TLD inward and remembers the deepest action seen — naturally label-
    // aligned and longest-match, O(labels) per query.
    //
    // DOMAIN-KEYWORD rules are substring matches, evaluated only when no
    // suffix rule matched. Within the keyword tier, longer patterns win and
    // later inserts win ties.

    private class TrieNode {
        val children = HashMap<String, TrieNode>()
        var action: RouteAction? = null
    }

    private var trieRoot = TrieNode()

    private data class KeywordRule(
        val pattern: String,
        val action: RouteAction,
        val patternLength: Int
    )

    private val keywordRules = ArrayList<KeywordRule>()

    private var ipv4Trie = CIDRTrie()
    private var ipv6Trie = CIDRTrie()

    private var configurationMap = HashMap<UUID, ProxyConfiguration>()
    private var domainRuleCount = 0
    private var ipRuleCount = 0

    private val json = Json { ignoreUnknownKeys = true }

    /** Clears all routing rules and configurations. */
    fun reset() {
        trieRoot = TrieNode()
        keywordRules.clear()
        ipv4Trie = CIDRTrie()
        ipv6Trie = CIDRTrie()
        configurationMap.clear()
        domainRuleCount = 0
        ipRuleCount = 0
    }

    /**
     * Reads routing descriptor from `filesDir/routing.json`, inserts country-bypass
     * rules first as [RouteAction.Direct], then user rules that overwrite on conflict.
     */
    fun loadRoutingConfiguration() {
        reset()

        val routingFile = File(context.filesDir, "routing.json")
        if (!routingFile.exists()) {
            logger.debug("[DomainRouter] No routing.json")
            return
        }
        val jsonObj = try {
            JSONObject(routingFile.readText())
        } catch (e: Exception) {
            logger.debug("[DomainRouter] routing.json invalid: $e")
            return
        }

        // Country-bypass rules first — user rules overwrite on conflict.
        var bypassDomainCount = 0
        var bypassIPCount = 0
        jsonObj.optJSONArray("bypassRules")?.let { arr ->
            for (i in 0 until arr.length()) {
                val rule = arr.optJSONObject(i) ?: continue
                val type = parseRuleType(rule.opt("type")) ?: continue
                val value = rule.optString("value", "").takeIf { it.isNotEmpty() } ?: continue
                when (type) {
                    DomainRuleType.DOMAIN_SUFFIX -> {
                        trieInsert(value.lowercase(), RouteAction.Direct)
                        bypassDomainCount++
                    }
                    DomainRuleType.DOMAIN_KEYWORD -> {
                        insertKeywordRule(value.lowercase(), RouteAction.Direct)
                        bypassDomainCount++
                    }
                    DomainRuleType.IP_CIDR -> parseIPv4CIDR(value)?.let { (net, prefix) ->
                        ipv4Trie.insert(net, prefix, RouteAction.Direct)
                        bypassIPCount++
                    }
                    DomainRuleType.IP_CIDR6 -> parseIPv6CIDR(value)?.let { (net, prefix) ->
                        ipv6Trie.insert(net, prefix, RouteAction.Direct)
                        bypassIPCount++
                    }
                }
            }
        }
        if (bypassDomainCount > 0 || bypassIPCount > 0) {
            logger.debug("[DomainRouter] Loaded $bypassDomainCount bypass domain rules, $bypassIPCount bypass IP rules")
        }

        // Configurations
        jsonObj.optJSONObject("configs")?.let { configs ->
            val keys = configs.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val configId = runCatching { UUID.fromString(key) }.getOrNull() ?: continue
                val configJson = configs.optJSONObject(key) ?: continue
                try {
                    configurationMap[configId] = json.decodeFromString(
                        ProxyConfiguration.serializer(),
                        configJson.toString()
                    )
                } catch (e: Exception) {
                    logger.debug("[DomainRouter] Failed to parse config $key: $e")
                }
            }
        }

        // User rules — these overwrite bypass rules on conflict.
        val rules = jsonObj.optJSONArray("rules") ?: run {
            logger.warning("[VPN] Routing data malformed: missing rules")
            return
        }
        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i) ?: continue
            val action: RouteAction = when (rule.optString("action", "")) {
                "direct" -> RouteAction.Direct
                "reject" -> RouteAction.Reject
                "proxy" -> {
                    val configIdStr = rule.optString("configId", "")
                    val configId = runCatching { UUID.fromString(configIdStr) }.getOrNull()
                        ?: continue
                    RouteAction.Proxy(configId)
                }
                else -> continue
            }

            rule.optJSONArray("domainRules")?.let { arr ->
                for (j in 0 until arr.length()) {
                    val dr = arr.optJSONObject(j) ?: continue
                    val type = parseRuleType(dr.opt("type")) ?: continue
                    val value = dr.optString("value", "").takeIf { it.isNotEmpty() } ?: continue
                    when (type) {
                        DomainRuleType.DOMAIN_SUFFIX -> {
                            trieInsert(value.lowercase(), action)
                            domainRuleCount++
                        }
                        DomainRuleType.DOMAIN_KEYWORD -> {
                            insertKeywordRule(value.lowercase(), action)
                            domainRuleCount++
                        }
                        DomainRuleType.IP_CIDR, DomainRuleType.IP_CIDR6 -> Unit
                    }
                }
            }

            rule.optJSONArray("ipRules")?.let { arr ->
                for (j in 0 until arr.length()) {
                    val ir = arr.optJSONObject(j) ?: continue
                    val type = parseRuleType(ir.opt("type")) ?: continue
                    val value = ir.optString("value", "").takeIf { it.isNotEmpty() } ?: continue
                    when (type) {
                        DomainRuleType.IP_CIDR -> parseIPv4CIDR(value)?.let { (net, prefix) ->
                            ipv4Trie.insert(net, prefix, action)
                            ipRuleCount++
                        }
                        DomainRuleType.IP_CIDR6 -> parseIPv6CIDR(value)?.let { (net, prefix) ->
                            ipv6Trie.insert(net, prefix, action)
                            ipRuleCount++
                        }
                        DomainRuleType.DOMAIN_SUFFIX,
                        DomainRuleType.DOMAIN_KEYWORD -> Unit
                    }
                }
            }
        }

        logger.debug("[DomainRouter] Loaded $domainRuleCount domain rules, $ipRuleCount IP rules, ${configurationMap.size} configurations")
    }

    /** Whether any user routing rules have been loaded (excludes bypass-only). */
    val hasRules: Boolean
        get() = domainRuleCount > 0 || ipRuleCount > 0

    /**
     * Matches a domain in two tiers: suffix rules first, keyword rules second.
     * Bypass entries present as [RouteAction.Direct].
     */
    fun matchDomain(domain: String): RouteAction? {
        if (domain.isEmpty()) return null
        val lowered = domain.lowercase()
        return trieLookup(lowered) ?: lookupKeywordRule(lowered)
    }

    /** Matches an IP against CIDR rules. O(32) IPv4 / O(128) IPv6. */
    fun matchIP(ip: String): RouteAction? {
        if (ip.isEmpty()) return null
        return if (ip.contains(':')) {
            parseIPv6Address(ip)?.let { ipv6Trie.lookup(it) }
        } else {
            parseIPv4(ip)?.let { ipv4Trie.lookup(it) }
        }
    }

    /** Resolves a [RouteAction.Proxy] to its [ProxyConfiguration]; null for Direct/Reject. */
    fun resolveConfiguration(action: RouteAction): ProxyConfiguration? = when (action) {
        RouteAction.Direct, RouteAction.Reject -> null
        is RouteAction.Proxy -> configurationMap[action.configId]
    }

    private fun trieInsert(suffix: String, action: RouteAction) {
        var node = trieRoot
        for (label in suffix.split('.').asReversed()) {
            if (label.isEmpty()) continue
            node = node.children.getOrPut(label) { TrieNode() }
        }
        node.action = action
    }

    private fun trieLookup(domain: String): RouteAction? {
        var node = trieRoot
        var deepest: RouteAction? = null
        for (label in domain.split('.').asReversed()) {
            val child = node.children[label] ?: break
            node = child
            node.action?.let { deepest = it }
        }
        return deepest
    }

    /**
     * Inserts a keyword pattern, overwriting any existing entry with the
     * same pattern so user rules replace bypass rules (mirroring the suffix
     * trie's overwrite behavior).
     */
    private fun insertKeywordRule(pattern: String, action: RouteAction) {
        if (pattern.isEmpty()) return
        val rule = KeywordRule(pattern, action, pattern.toByteArray(Charsets.UTF_8).size)
        val index = keywordRules.indexOfFirst { it.pattern == pattern }
        if (index >= 0) {
            keywordRules[index] = rule
        } else {
            keywordRules.add(rule)
        }
    }

    /**
     * Linearly scans keyword rules only after suffix lookup has failed.
     * Longer keywords win; ties go to the later-inserted rule.
     */
    private fun lookupKeywordRule(domain: String): RouteAction? {
        var bestAction: RouteAction? = null
        var bestLength = -1
        for (rule in keywordRules) {
            if (!domain.contains(rule.pattern)) continue
            if (rule.patternLength >= bestLength) {
                bestAction = rule.action
                bestLength = rule.patternLength
            }
        }
        return bestAction
    }

    private fun parseRuleType(raw: Any?): DomainRuleType? {
        return when (raw) {
            is Int -> DomainRuleType.fromRawValue(raw)
            is String -> DomainRuleType.fromLegacyString(raw)
            is Number -> DomainRuleType.fromRawValue(raw.toInt())
            else -> null
        }
    }

    private fun parseIPv4CIDR(cidr: String): Pair<Long, Int>? {
        val parts = cidr.split('/', limit = 2)
        if (parts.size != 2) return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix < 0 || prefix > 32) return null
        val ip = parseIPv4(parts[0]) ?: return null
        val mask: Long = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return (ip and mask) to prefix
    }

    private fun parseIPv4(ip: String): Long? {
        val parts = ip.split('.', limit = 5)
        if (parts.size != 4) return null
        var result = 0L
        for (part in parts) {
            val byte = part.toIntOrNull() ?: return null
            if (byte < 0 || byte > 255) return null
            result = (result shl 8) or byte.toLong()
        }
        return result
    }

    private fun parseIPv6CIDR(cidr: String): Pair<ByteArray, Int>? {
        val slash = cidr.lastIndexOf('/')
        if (slash < 0) return null
        val prefixLen = cidr.substring(slash + 1).toIntOrNull() ?: return null
        if (prefixLen < 0 || prefixLen > 128) return null
        val bytes = parseIPv6Address(cidr.substring(0, slash)) ?: return null
        val network = bytes.copyOf()
        for (i in 0 until 16) {
            val bitPos = i * 8
            if (bitPos >= prefixLen) {
                network[i] = 0
            } else if (bitPos + 8 > prefixLen) {
                val keep = prefixLen - bitPos
                network[i] = (network[i].toInt() and ((0xFF shl (8 - keep)) and 0xFF)).toByte()
            }
        }
        return network to prefixLen
    }

    private fun parseIPv6Address(ip: String): ByteArray? = try {
        InetAddress.getByName(ip).address.takeIf { it.size == 16 }
    } catch (_: Exception) { null }

    companion object {
        private val logger = AnywhereLogger("DomainRouter")
    }
}

/**
 * Binary trie for longest-prefix-match on IP addresses. Each bit selects a child
 * (0 = left, 1 = right). Lookup is O(address-width) regardless of rule count.
 */
private class CIDRTrie {
    private class Node {
        var left: Node? = null
        var right: Node? = null
        var action: RouteAction? = null
    }

    private val root = Node()

    fun insert(network: Long, prefixLen: Int, action: RouteAction) {
        var node = root
        for (i in 0 until prefixLen) {
            val bit = ((network shr (31 - i)) and 1L).toInt()
            node = if (bit == 0) {
                node.left ?: Node().also { node.left = it }
            } else {
                node.right ?: Node().also { node.right = it }
            }
        }
        node.action = action
    }

    fun insert(network: ByteArray, prefixLen: Int, action: RouteAction) {
        var node = root
        for (i in 0 until prefixLen) {
            val bit = ((network[i shr 3].toInt() ushr (7 - (i and 7))) and 1)
            node = if (bit == 0) {
                node.left ?: Node().also { node.left = it }
            } else {
                node.right ?: Node().also { node.right = it }
            }
        }
        node.action = action
    }

    fun lookup(ip: Long): RouteAction? {
        var node = root
        var deepest: RouteAction? = node.action
        for (i in 0 until 32) {
            val bit = ((ip shr (31 - i)) and 1L).toInt()
            val next = if (bit == 0) node.left else node.right
            next ?: break
            node = next
            node.action?.let { deepest = it }
        }
        return deepest
    }

    fun lookup(bytes: ByteArray): RouteAction? {
        var node = root
        var deepest: RouteAction? = node.action
        for (i in 0 until 128) {
            val bit = ((bytes[i shr 3].toInt() ushr (7 - (i and 7))) and 1)
            val next = if (bit == 0) node.left else node.right
            next ?: break
            node = next
            node.action?.let { deepest = it }
        }
        return deepest
    }
}
