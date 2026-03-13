package com.argsment.anywhere.vpn

import android.content.Context
import android.util.Log
import com.argsment.anywhere.data.model.ProxyConfiguration
import kotlinx.serialization.json.Json
import org.json.JSONArray
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
 * Domain-based routing rule engine with efficient data structures.
 *
 * - Exact domains: O(1) hash lookup
 * - Suffix matching: Reverse-label trie, O(k) where k = label count
 * - Keyword matching: Aho-Corasick automaton, O(m) where m = domain length
 * - IP CIDR matching: Linear scan of pre-parsed rules
 *
 * Supports both user rules and bypass country domain rules.
 * User rules take absolute precedence over country bypass.
 *
 * Thread safety: NOT internally synchronized. All access must be on the lwIP thread.
 */
class DomainRouter(private val context: Context) {

    // -- Domain Match Result --

    data class DomainMatch(
        val userAction: RouteAction? = null,
        val isBypass: Boolean = false
    ) {
        companion object {
            val NONE = DomainMatch()
        }
    }

    // -- Suffix Trie (reverse-label) --
    //
    // Domains are split into labels and reversed: "www.google.com" → ["com","google","www"].
    // Walking the trie from root matches progressively more-specific suffixes.
    // Each node stores the deepest user action and/or a bypass flag at that suffix boundary.

    private class TrieNode {
        val children = HashMap<String, TrieNode>()
        var userAction: RouteAction? = null
        var isBypass: Boolean = false
    }

    private var trieRoot = TrieNode()

    // Exact domain matches (O(1) hash lookup, checked before the trie)
    private var exactDomains = HashMap<String, RouteAction>()
    private var bypassExactDomains = HashSet<String>()

    // -- Aho-Corasick Keyword Matcher --
    //
    // All keyword patterns (user + bypass) are compiled into a single automaton.
    // Matching scans the domain string once, O(m), and reports any keyword hit.

    private class ACState {
        val goto = HashMap<Byte, Int>()
        var failure: Int = 0
        var userAction: RouteAction? = null
        var isBypass: Boolean = false
        var outputLink: Int = -1   // nearest match state reachable via failure chain
    }

    private var acStates = mutableListOf(ACState())   // state 0 = root
    private var acBuilt = false

    // Compiled IP CIDR rules (network & mask pre-computed at load time)
    private var ipv4CIDRRules = mutableListOf<Triple<Long, Long, RouteAction>>()   // (network, mask, action)
    private var ipv6CIDRRules = mutableListOf<Triple<ByteArray, Int, RouteAction>>()   // (network, prefixLen, action)

    // Proxy configurations for rule-assigned proxies
    private var configurationMap = HashMap<UUID, ProxyConfiguration>()

    // Count for hasRules (user domain rules only)
    private var domainRuleCount = 0

    private val json = Json { ignoreUnknownKeys = true }

    // -- Loading --

    /**
     * Reads routing configuration from routing.json and compiles rules.
     * Clears all structures — must be called before [loadBypassCountryRules].
     */
    fun loadRoutingConfiguration() {
        // Clear all domain matching structures
        trieRoot = TrieNode()
        exactDomains.clear()
        bypassExactDomains.clear()
        acStates = mutableListOf(ACState())
        acBuilt = false
        domainRuleCount = 0

        ipv4CIDRRules.clear()
        ipv6CIDRRules.clear()
        configurationMap.clear()

        val routingFile = File(context.filesDir, "routing.json")
        val jsonObj: JSONObject
        try {
            if (!routingFile.exists()) {
                Log.i(TAG, "[DomainRouter] No routing.json found")
                return
            }
            jsonObj = JSONObject(routingFile.readText())
        } catch (e: Exception) {
            Log.i(TAG, "[DomainRouter] No routing.json or invalid format: $e")
            return
        }

        // Parse configurations
        val configs = jsonObj.optJSONObject("configs")
        if (configs != null) {
            val keys = configs.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val configId = runCatching { UUID.fromString(key) }.getOrNull() ?: continue
                val configJson = configs.optJSONObject(key) ?: continue
                try {
                    val configuration = json.decodeFromString(
                        ProxyConfiguration.serializer(),
                        configJson.toString()
                    )
                    configurationMap[configId] = configuration
                } catch (e: Exception) {
                    Log.w(TAG, "[DomainRouter] Failed to parse config $key: $e")
                }
            }
        }

        // Parse rules
        val rules = jsonObj.optJSONArray("rules")
        if (rules == null) {
            Log.w(TAG, "[DomainRouter] routing.json has no 'rules' array")
            return
        }

        var ipRuleCount = 0

        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i) ?: continue
            val actionStr = rule.optString("action", "") ?: continue

            val action: RouteAction = when (actionStr) {
                "direct" -> RouteAction.Direct
                "reject" -> RouteAction.Reject
                "proxy" -> {
                    val configIdStr = rule.optString("configId", "") ?: continue
                    val configId = runCatching { UUID.fromString(configIdStr) }.getOrNull() ?: continue
                    RouteAction.Proxy(configId)
                }
                else -> continue
            }

            // Domain rules
            val domainRules = rule.optJSONArray("domainRules")
            if (domainRules != null) {
                for (j in 0 until domainRules.length()) {
                    val dr = domainRules.optJSONObject(j) ?: continue
                    val typeStr = dr.optString("type", "") ?: continue
                    val value = dr.optString("value", "") ?: continue
                    if (value.isEmpty()) continue
                    val lowered = value.lowercase()

                    when (typeStr) {
                        "domain" -> {
                            exactDomains[lowered] = action
                            domainRuleCount++
                        }
                        "domainsuffix", "domainSuffix" -> {
                            trieInsert(lowered, userAction = action)
                            domainRuleCount++
                        }
                        "domainkeyword", "domainKeyword" -> {
                            acAddPattern(lowered, userAction = action)
                            domainRuleCount++
                        }
                    }
                }
            }

            // IP CIDR rules
            val ipRules = rule.optJSONArray("ipRules")
            if (ipRules != null) {
                for (j in 0 until ipRules.length()) {
                    val ir = ipRules.optJSONObject(j) ?: continue
                    val typeStr = ir.optString("type", "") ?: continue
                    val value = ir.optString("value", "") ?: continue

                    when (typeStr) {
                        "ipCIDR" -> {
                            parseIPv4CIDR(value)?.let { (network, mask) ->
                                ipv4CIDRRules.add(Triple(network, mask, action))
                                ipRuleCount++
                            }
                        }
                        "ipCIDR6" -> {
                            parseIPv6CIDR(value)?.let { (network, prefixLen) ->
                                ipv6CIDRRules.add(Triple(network, prefixLen, action))
                                ipRuleCount++
                            }
                        }
                    }
                }
            }
        }

        Log.i(TAG, "[DomainRouter] Loaded $domainRuleCount domain rules, $ipRuleCount IP rules, ${configurationMap.size} configurations")
    }

    /**
     * Reads bypass country domain rules from assets and adds them to the shared
     * trie / Aho-Corasick structures. Builds the keyword automaton.
     * Must be called after [loadRoutingConfiguration].
     */
    fun loadBypassCountryRules() {
        var count = 0

        val prefs = context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val code = prefs.getString("bypassCountryCode", "") ?: ""

        if (code.isNotEmpty()) {
            try {
                val text = context.assets.open("rulesets/$code.json").bufferedReader().use { it.readText() }
                val rules = JSONArray(text)

                for (i in 0 until rules.length()) {
                    val rule = rules.optJSONObject(i) ?: continue
                    val typeStr = rule.optString("type", "") ?: continue
                    val value = rule.optString("value", "") ?: continue
                    if (value.isEmpty()) continue
                    val lowered = value.lowercase()

                    when (typeStr) {
                        "domain" -> {
                            bypassExactDomains.add(lowered)
                            count++
                        }
                        "domainSuffix" -> {
                            trieInsertBypass(lowered)
                            count++
                        }
                        "domainKeyword" -> {
                            acAddPattern(lowered, isBypass = true)
                            count++
                        }
                        // Skip ipCIDR/ipCIDR6 — bypass is domain-based only
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "[DomainRouter] Failed to load bypass rules for '$code': $e")
            }
        }

        // Build the Aho-Corasick automaton after all patterns (user + bypass) are inserted
        acBuild()

        if (count > 0) {
            Log.i(TAG, "[DomainRouter] Loaded $count bypass country domain rules")
        }
    }

    // -- Domain Matching (public API) --

    /** Whether any user routing rules have been loaded. */
    val hasRules: Boolean
        get() = domainRuleCount > 0 || ipv4CIDRRules.isNotEmpty() || ipv6CIDRRules.isNotEmpty()

    /** Whether any IP CIDR rules have been loaded. */
    val hasIPRules: Boolean
        get() = ipv4CIDRRules.isNotEmpty() || ipv6CIDRRules.isNotEmpty()

    /**
     * Unified domain matching: checks exact → suffix trie → Aho-Corasick keywords.
     * User rules take absolute precedence over country bypass.
     */
    fun matchDomain(domain: String): DomainMatch {
        if (domain.isEmpty()) return DomainMatch.NONE
        val lowered = domain.lowercase()

        // 1. Exact match (O(1) hash lookup)
        exactDomains[lowered]?.let { action ->
            return DomainMatch(userAction = action)
        }

        // 2. Suffix match via reverse-label trie (O(k), k = label count ≈ 2-4)
        val suffix = trieLookup(lowered)
        suffix.first?.let { action ->
            return DomainMatch(userAction = action)
        }

        // 3. Keyword match via Aho-Corasick (O(m), m = domain length)
        val keyword = acMatch(lowered)
        keyword.first?.let { action ->
            return DomainMatch(userAction = action)
        }

        // 4. No user rule matched — check bypass from all three sources
        val isBypass = bypassExactDomains.contains(lowered) || suffix.second || keyword.second
        return DomainMatch(userAction = null, isBypass = isBypass)
    }

    /** Matches an IP address against IP CIDR rules. Returns null if no rule matches. */
    fun matchIP(ip: String): RouteAction? {
        if (ip.isEmpty()) return null

        if (ip.contains(':')) {
            // IPv6
            val bytes = parseIPv6Address(ip) ?: return null
            for ((network, prefixLen, action) in ipv6CIDRRules) {
                if (ipv6Matches(bytes, network, prefixLen)) return action
            }
        } else {
            // IPv4
            val ip32 = parseIPv4(ip) ?: return null
            for ((network, mask, action) in ipv4CIDRRules) {
                if ((ip32 and mask) == network) return action
            }
        }

        return null
    }

    /** Resolves a RouteAction to a ProxyConfiguration. Returns null for Direct/Reject. */
    fun resolveConfiguration(action: RouteAction): ProxyConfiguration? {
        return when (action) {
            is RouteAction.Direct, is RouteAction.Reject -> null
            is RouteAction.Proxy -> configurationMap[action.configId]
        }
    }

    // -- Suffix Trie (private) --

    /** Inserts a user suffix rule into the trie. */
    private fun trieInsert(suffix: String, userAction: RouteAction) {
        val node = trieWalkOrCreate(suffix)
        node.userAction = userAction
    }

    /** Inserts a bypass suffix rule into the trie. */
    private fun trieInsertBypass(suffix: String) {
        val node = trieWalkOrCreate(suffix)
        node.isBypass = true
    }

    /** Walks (or creates) the trie path for a domain suffix, returning the leaf node. */
    private fun trieWalkOrCreate(suffix: String): TrieNode {
        var node = trieRoot
        for (label in suffix.split('.').reversed()) {
            if (label.isEmpty()) continue
            node = node.children.getOrPut(label) { TrieNode() }
        }
        return node
    }

    /**
     * Looks up a domain in the suffix trie. Returns the deepest user action and
     * whether any bypass node was encountered along the path.
     */
    private fun trieLookup(domain: String): Pair<RouteAction?, Boolean> {
        var node = trieRoot
        var deepestUserAction: RouteAction? = null
        var foundBypass = false

        for (label in domain.split('.').reversed()) {
            val child = node.children[label] ?: break
            node = child
            if (node.userAction != null) {
                deepestUserAction = node.userAction
            }
            if (node.isBypass) {
                foundBypass = true
            }
        }

        return deepestUserAction to foundBypass
    }

    // -- Aho-Corasick (private) --

    /**
     * Inserts a keyword pattern into the automaton (before [acBuild]).
     * Set [userAction] for user rules, [isBypass] for country bypass, or both.
     */
    private fun acAddPattern(pattern: String, userAction: RouteAction? = null, isBypass: Boolean = false) {
        var state = 0
        for (byte in pattern.toByteArray(Charsets.UTF_8)) {
            val next = acStates[state].goto[byte]
            if (next != null) {
                state = next
            } else {
                val newState = acStates.size
                acStates.add(ACState())
                acStates[state].goto[byte] = newState
                state = newState
            }
        }
        if (userAction != null) {
            acStates[state].userAction = userAction
        }
        if (isBypass) {
            acStates[state].isBypass = true
        }
    }

    /**
     * Computes failure links and output links (BFS). Must be called once after
     * all patterns have been inserted.
     */
    private fun acBuild() {
        if (acStates.size <= 1) {
            acBuilt = true
            return
        }

        val queue = ArrayDeque<Int>()

        // Depth-1 states: failure → root
        for ((_, nextState) in acStates[0].goto) {
            acStates[nextState].failure = 0
            acStates[nextState].outputLink = -1
            queue.addLast(nextState)
        }

        while (queue.isNotEmpty()) {
            val current = queue.removeFirst()

            for ((byte, nextState) in acStates[current].goto) {
                // Compute failure link for nextState
                var f = acStates[current].failure
                while (f != 0 && acStates[f].goto[byte] == null) {
                    f = acStates[f].failure
                }
                val failTarget = acStates[f].goto[byte] ?: 0
                acStates[nextState].failure = if (failTarget == nextState) 0 else failTarget

                // Compute output link (nearest match state via failure chain)
                val fs = acStates[nextState].failure
                acStates[nextState].outputLink = if (acStates[fs].userAction != null || acStates[fs].isBypass) {
                    fs
                } else {
                    acStates[fs].outputLink
                }

                queue.addLast(nextState)
            }
        }
        acBuilt = true
    }

    /**
     * Scans the domain through the automaton and returns the first user keyword
     * action found and whether any bypass keyword matched.
     */
    private fun acMatch(domain: String): Pair<RouteAction?, Boolean> {
        if (!acBuilt || acStates.size <= 1) return null to false

        var state = 0
        var resultUserAction: RouteAction? = null
        var resultBypass = false

        for (byte in domain.toByteArray(Charsets.UTF_8)) {
            // Follow failure links until we find a goto or reach root
            while (state != 0 && acStates[state].goto[byte] == null) {
                state = acStates[state].failure
            }
            state = acStates[state].goto[byte] ?: 0

            // Check this state and all output-linked states for matches
            var check = state
            while (check > 0) {
                if (resultUserAction == null && acStates[check].userAction != null) {
                    resultUserAction = acStates[check].userAction
                }
                if (!resultBypass && acStates[check].isBypass) {
                    resultBypass = true
                }
                if (resultUserAction != null && resultBypass) break
                val nextCheck = acStates[check].outputLink
                if (nextCheck <= 0) break
                check = nextCheck
            }

            if (resultUserAction != null && resultBypass) break
        }

        return resultUserAction to resultBypass
    }

    // -- CIDR Parsing --

    /** Parses "A.B.C.D/prefix" into (network, mask) with host bits zeroed. */
    private fun parseIPv4CIDR(cidr: String): Pair<Long, Long>? {
        val parts = cidr.split('/', limit = 2)
        if (parts.size != 2) return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix < 0 || prefix > 32) return null
        val ip = parseIPv4(parts[0]) ?: return null
        val mask: Long = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return (ip and mask) to mask
    }

    /** Parses a dotted-quad IPv4 string to host-order UInt32 (stored as Long). */
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

    /** Parses "addr/prefix" IPv6 CIDR into (network bytes, prefix length). */
    private fun parseIPv6CIDR(cidr: String): Pair<ByteArray, Int>? {
        val slashIndex = cidr.lastIndexOf('/')
        if (slashIndex < 0) return null
        val prefixLen = cidr.substring(slashIndex + 1).toIntOrNull() ?: return null
        if (prefixLen < 0 || prefixLen > 128) return null

        val addrStr = cidr.substring(0, slashIndex)
        val bytes = parseIPv6Address(addrStr) ?: return null

        // Zero host bits
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

    /** Parses an IPv6 address string to 16 bytes. */
    private fun parseIPv6Address(ip: String): ByteArray? {
        return try {
            val addr = InetAddress.getByName(ip)
            val bytes = addr.address
            if (bytes.size == 16) bytes else null
        } catch (_: Exception) {
            null
        }
    }

    /** Checks if IPv6 address bytes match a CIDR rule. */
    private fun ipv6Matches(bytes: ByteArray, network: ByteArray, prefixLen: Int): Boolean {
        var remaining = prefixLen
        for (i in 0 until 16) {
            if (remaining <= 0) return true
            if (remaining >= 8) {
                if (bytes[i] != network[i]) return false
                remaining -= 8
            } else {
                val mask = (0xFF shl (8 - remaining)) and 0xFF
                return (bytes[i].toInt() and mask) == (network[i].toInt() and mask)
            }
        }
        return true
    }

    companion object {
        private const val TAG = "DomainRouter"
    }
}
