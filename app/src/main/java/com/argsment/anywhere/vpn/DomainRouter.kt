package com.argsment.anywhere.vpn

import android.content.Context
import android.util.Log
import com.argsment.anywhere.data.model.VlessConfiguration
import kotlinx.serialization.json.Json
import org.json.JSONObject
import java.io.File
import java.util.UUID

sealed class RouteAction {
    data object Direct : RouteAction()
    data class Proxy(val configId: UUID) : RouteAction()
}

/**
 * Domain-based routing rule engine.
 *
 * Loads rules from `routing.json` in internal storage and matches DNS query domains
 * against them to determine whether traffic should go direct or through a specific proxy.
 *
 * Thread safety: NOT internally synchronized. All access must be on the lwIP thread.
 */
class DomainRouter(private val context: Context) {

    // Compiled rules
    private var exactDomains = HashMap<String, RouteAction>()
    private var suffixRules = mutableListOf<Pair<String, RouteAction>>()  // (suffix, action)
    private var keywordRules = mutableListOf<Pair<String, RouteAction>>()  // (keyword, action)

    // Proxy configurations for rule-assigned proxies
    private var configurationMap = HashMap<UUID, VlessConfiguration>()

    private val json = Json { ignoreUnknownKeys = true }

    /** Reads routing.json from internal storage and compiles rules. */
    fun loadRoutingConfiguration() {
        exactDomains.clear()
        suffixRules.clear()
        keywordRules.clear()
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
                        VlessConfiguration.serializer(),
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

        var ruleCount = 0
        for (i in 0 until rules.length()) {
            val rule = rules.optJSONObject(i) ?: continue
            val actionStr = rule.optString("action", "") ?: continue
            val domainRules = rule.optJSONArray("domainRules") ?: continue

            val action: RouteAction = when (actionStr) {
                "direct" -> RouteAction.Direct
                "proxy" -> {
                    val configIdStr = rule.optString("configId", "") ?: continue
                    val configId = runCatching { UUID.fromString(configIdStr) }.getOrNull() ?: continue
                    RouteAction.Proxy(configId)
                }
                else -> continue
            }

            for (j in 0 until domainRules.length()) {
                val dr = domainRules.optJSONObject(j) ?: continue
                val typeStr = dr.optString("type", "") ?: continue
                val value = dr.optString("value", "") ?: continue
                if (value.isEmpty()) continue
                val lowered = value.lowercase()

                when (typeStr) {
                    "domain" -> {
                        exactDomains[lowered] = action
                        ruleCount++
                    }
                    "domainsuffix", "domainSuffix" -> {
                        suffixRules.add(lowered to action)
                        ruleCount++
                    }
                    "domainkeyword", "domainKeyword" -> {
                        keywordRules.add(lowered to action)
                        ruleCount++
                    }
                }
            }
        }

        Log.i(TAG, "[DomainRouter] Loaded $ruleCount rules, ${configurationMap.size} configurations")
    }

    /** Whether any routing rules have been loaded. */
    val hasRules: Boolean
        get() = exactDomains.isNotEmpty() || suffixRules.isNotEmpty() || keywordRules.isNotEmpty()

    /** Matches a domain against routing rules. Returns null if no rule matches. */
    fun matchDomain(domain: String): RouteAction? {
        val lowered = domain.lowercase()
        if (lowered.isEmpty()) return null

        // 1. Exact match (O(1))
        exactDomains[lowered]?.let { return it }

        // 2. Suffix match
        for ((suffix, action) in suffixRules) {
            if (lowered == suffix || lowered.endsWith(".$suffix")) {
                return action
            }
        }

        // 3. Keyword match
        for ((keyword, action) in keywordRules) {
            if (lowered.contains(keyword)) {
                return action
            }
        }

        return null
    }

    /** Resolves a RouteAction to a VlessConfiguration. Returns null for Direct. */
    fun resolveConfiguration(action: RouteAction): VlessConfiguration? {
        return when (action) {
            is RouteAction.Direct -> null
            is RouteAction.Proxy -> configurationMap[action.configId]
        }
    }

    companion object {
        private const val TAG = "DomainRouter"
    }
}
