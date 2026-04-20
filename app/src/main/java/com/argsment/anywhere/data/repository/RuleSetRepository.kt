package com.argsment.anywhere.data.repository

import android.content.Context
import android.content.SharedPreferences
import com.argsment.anywhere.data.model.DomainRule
import com.argsment.anywhere.data.model.DomainRuleType
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.rules.CountryBypassCatalog
import com.argsment.anywhere.data.rules.RulesDatabase
import com.argsment.anywhere.data.rules.ServiceCatalog
import com.argsment.anywhere.vpn.util.AnywhereLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Routing rule-set state + persistence, port of iOS [RuleSetStore.swift].
 *
 * Built-in rule sets: `Direct` + [ServiceCatalog.supportedServices] + `ADBlock`.
 * User-created [CustomRuleSet]s live between the built-ins and ADBlock so
 * they carry higher priority than services but lower than ADBlock.
 *
 * Priority ordering (lowest → highest in trie-overwrite sense):
 * country bypass → Direct → services → custom → ADBlock.
 */
class RuleSetRepository(private val context: Context) {

    data class RuleSet(
        val id: String,      // built-in: name, custom: UUID string
        val name: String,
        val assignedConfigurationId: String? = null,
        val isCustom: Boolean = false
    )

    @Serializable
    data class CustomRuleSet(
        val id: String,      // UUID string
        val name: String,
        val rules: List<DomainRule> = emptyList()
    ) {
        companion object {
            fun newNamed(name: String): CustomRuleSet =
                CustomRuleSet(id = UUID.randomUUID().toString(), name = name)
        }
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    private val serviceCatalog = ServiceCatalog.get(context)
    private val countryCatalog = CountryBypassCatalog.get(context)
    private val rulesDatabase = RulesDatabase.get(context)

    private val _ruleSets = MutableStateFlow<List<RuleSet>>(emptyList())
    val ruleSets: StateFlow<List<RuleSet>> = _ruleSets.asStateFlow()

    private val _customRuleSets = MutableStateFlow<List<CustomRuleSet>>(emptyList())
    val customRuleSets: StateFlow<List<CustomRuleSet>> = _customRuleSets.asStateFlow()

    init {
        _customRuleSets.value = loadCustomRuleSets()
        rebuildRuleSets()
    }

    // -- Rule set composition --

    private fun builtInNames(): List<String> =
        listOf("Direct") + serviceCatalog.supportedServices + listOf("ADBlock")

    private fun rebuildRuleSets() {
        val assignments = loadAssignments()
        val result = mutableListOf<RuleSet>()
        for (name in builtInNames()) {
            if (name == "ADBlock") break
            result += RuleSet(
                id = name,
                name = name,
                assignedConfigurationId = assignments[name] ?: defaultAssignments[name]
            )
        }
        for (custom in _customRuleSets.value) {
            result += RuleSet(
                id = custom.id,
                name = custom.name,
                assignedConfigurationId = assignments[custom.id],
                isCustom = true
            )
        }
        result += RuleSet(
            id = "ADBlock",
            name = "ADBlock",
            assignedConfigurationId = assignments["ADBlock"]
        )
        _ruleSets.value = result
    }

    // -- Assignment --

    fun updateAssignment(ruleSet: RuleSet, configurationId: String?) {
        _ruleSets.value = _ruleSets.value.map {
            if (it.id == ruleSet.id) it.copy(assignedConfigurationId = configurationId) else it
        }
        saveAssignments()
    }

    fun resetAssignments() {
        _ruleSets.value = _ruleSets.value.map { rs ->
            if (rs.id == "Direct") rs else rs.copy(assignedConfigurationId = null)
        }
        saveAssignments()
    }

    fun clearOrphanedAssignments(availableConfigIds: Set<String>): List<String> {
        val affected = mutableListOf<String>()
        _ruleSets.value = _ruleSets.value.map { rs ->
            val assignedId = rs.assignedConfigurationId
            if (assignedId != null && assignedId != "DIRECT" && assignedId != "REJECT" && assignedId !in availableConfigIds) {
                affected.add(rs.name)
                rs.copy(assignedConfigurationId = null)
            } else {
                rs
            }
        }
        if (affected.isNotEmpty()) saveAssignments()
        return affected
    }

    // -- Custom rule-set CRUD --

    fun addCustomRuleSet(name: String): CustomRuleSet {
        val rs = CustomRuleSet.newNamed(name)
        _customRuleSets.value = _customRuleSets.value + rs
        saveCustomRuleSets()
        rebuildRuleSets()
        return rs
    }

    fun removeCustomRuleSet(id: String) {
        _customRuleSets.value = _customRuleSets.value.filterNot { it.id == id }
        saveCustomRuleSets()
        val assignments = loadAssignments().toMutableMap()
        if (assignments.remove(id) != null) {
            saveAssignmentMap(assignments)
        }
        rebuildRuleSets()
    }

    fun updateCustomRuleSet(id: String, name: String? = null, rules: List<DomainRule>? = null) {
        val updated = _customRuleSets.value.map { rs ->
            if (rs.id == id) rs.copy(
                name = name ?: rs.name,
                rules = rules ?: rs.rules
            ) else rs
        }
        if (updated == _customRuleSets.value) return
        _customRuleSets.value = updated
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    fun addRule(customRuleSetId: String, rule: DomainRule) {
        val updated = _customRuleSets.value.map { rs ->
            if (rs.id == customRuleSetId) rs.copy(rules = rs.rules + rule) else rs
        }
        _customRuleSets.value = updated
        saveCustomRuleSets()
    }

    fun addRules(customRuleSetId: String, rules: List<DomainRule>) {
        if (rules.isEmpty()) return
        val updated = _customRuleSets.value.map { rs ->
            if (rs.id == customRuleSetId) rs.copy(rules = rs.rules + rules) else rs
        }
        _customRuleSets.value = updated
        saveCustomRuleSets()
    }

    fun removeRules(customRuleSetId: String, indices: List<Int>) {
        if (indices.isEmpty()) return
        val updated = _customRuleSets.value.map { rs ->
            if (rs.id != customRuleSetId) return@map rs
            val remaining = rs.rules.toMutableList()
            for (i in indices.sortedDescending()) {
                if (i in remaining.indices) remaining.removeAt(i)
            }
            rs.copy(rules = remaining)
        }
        _customRuleSets.value = updated
        saveCustomRuleSets()
    }

    fun customRuleSet(id: String): CustomRuleSet? =
        _customRuleSets.value.firstOrNull { it.id == id }

    // -- Rule loading --

    /** Returns rules for a built-in or custom rule set. */
    fun loadRules(ruleSet: RuleSet): List<DomainRule> {
        if (ruleSet.isCustom) {
            return customRuleSet(ruleSet.id)?.rules ?: emptyList()
        }
        return rulesDatabase.loadRules(ruleSet.name)
    }

    // -- routing.json sync --

    /**
     * Writes the compiled routing descriptor consumed by [DomainRouter.loadRoutingConfiguration].
     * Output format matches iOS `RuleSetStore.syncToAppGroup`:
     *   { rules: [{domainRules, ipRules?, action, configId?}], configs: {uuid: config}, bypassRules?: [...] }
     */
    fun syncRoutingFile(
        configurations: List<ProxyConfiguration>,
        resolveAddress: (String) -> String?
    ) {
        val routingFile = File(context.filesDir, "routing.json")

        val routingRules = JSONArray()
        val configsObj = JSONObject()

        for (ruleSet in _ruleSets.value) {
            val assignedId = ruleSet.assignedConfigurationId ?: continue
            val domainRules = loadRules(ruleSet)
            if (domainRules.isEmpty()) continue

            val domainRulesArray = JSONArray()
            val ipRulesArray = JSONArray()
            for (rule in domainRules) {
                val entry = JSONObject().apply {
                    put("type", rule.type.rawValue)
                    put("value", rule.value)
                }
                when (rule.type) {
                    DomainRuleType.IP_CIDR, DomainRuleType.IP_CIDR6 -> ipRulesArray.put(entry)
                    DomainRuleType.DOMAIN_SUFFIX,
                    DomainRuleType.DOMAIN_KEYWORD -> domainRulesArray.put(entry)
                }
            }

            val ruleEntry = JSONObject().apply {
                put("domainRules", domainRulesArray)
                if (ipRulesArray.length() > 0) {
                    put("ipRules", ipRulesArray)
                }
            }

            when (assignedId) {
                "DIRECT" -> ruleEntry.put("action", "direct")
                "REJECT" -> ruleEntry.put("action", "reject")
                else -> {
                    val configUuid = runCatching { UUID.fromString(assignedId) }.getOrNull() ?: continue
                    val config = configurations.find { it.id == configUuid } ?: continue
                    ruleEntry.put("action", "proxy")
                    ruleEntry.put("configId", assignedId)
                    val resolvedConfig = resolveConfigurationAddresses(config, resolveAddress)
                    val configJson = Json.encodeToString(ProxyConfiguration.serializer(), resolvedConfig)
                    configsObj.put(assignedId, JSONObject(configJson))
                }
            }

            routingRules.put(ruleEntry)
        }

        val routing = JSONObject().apply {
            put("rules", routingRules)
            put("configs", configsObj)
            // Country-bypass domain rules, loaded before user rules so user rules win on conflict.
            val bypassCode = prefs.getString("bypassCountryCode", "") ?: ""
            if (bypassCode.isNotEmpty()) {
                val bypassRules = countryCatalog.rules(bypassCode)
                if (bypassRules.isNotEmpty()) {
                    val arr = JSONArray()
                    for (rule in bypassRules) {
                        arr.put(JSONObject().apply {
                            put("type", rule.type.rawValue)
                            put("value", rule.value)
                        })
                    }
                    put("bypassRules", arr)
                }
            }
        }

        runCatching {
            routingFile.writeText(routing.toString())
        }.onFailure {
            logger.error("Failed to write routing.json: $it")
        }
    }

    private fun resolveConfigurationAddresses(
        config: ProxyConfiguration,
        resolveAddress: (String) -> String?
    ): ProxyConfiguration {
        val resolvedChain = config.chain?.map { resolveConfigurationAddresses(it, resolveAddress) }
        val resolvedIp = config.resolvedIP ?: resolveAddress(config.serverAddress)
        return config.copy(resolvedIP = resolvedIp, chain = resolvedChain)
    }

    // -- Persistence --

    private fun loadAssignments(): Map<String, String> {
        val result = mutableMapOf<String, String>()
        prefs.getStringSet(ASSIGNMENTS_KEY, null)?.forEach { entry ->
            val parts = entry.split("=", limit = 2)
            if (parts.size == 2) result[parts[0]] = parts[1]
        }
        return result
    }

    private fun saveAssignments() {
        val map = _ruleSets.value.mapNotNull { rs ->
            rs.assignedConfigurationId?.let { rs.id to it }
        }.toMap()
        saveAssignmentMap(map)
    }

    private fun saveAssignmentMap(map: Map<String, String>) {
        val set = map.map { (k, v) -> "$k=$v" }.toSet()
        prefs.edit().putStringSet(ASSIGNMENTS_KEY, set).apply()
    }

    private fun loadCustomRuleSets(): List<CustomRuleSet> {
        val stored = prefs.getString(CUSTOM_RULE_SETS_KEY, null) ?: return emptyList()
        return runCatching {
            json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(CustomRuleSet.serializer()), stored)
        }.getOrElse {
            logger.error("Failed to decode custom rule sets: $it")
            emptyList()
        }
    }

    private fun saveCustomRuleSets() {
        val encoded = Json.encodeToString(
            kotlinx.serialization.builtins.ListSerializer(CustomRuleSet.serializer()),
            _customRuleSets.value
        )
        prefs.edit().putString(CUSTOM_RULE_SETS_KEY, encoded).apply()
    }

    companion object {
        private val logger = AnywhereLogger("RuleSetStore")
        private const val ASSIGNMENTS_KEY = "ruleSetAssignments"
        private const val CUSTOM_RULE_SETS_KEY = "customRuleSets"
        private val defaultAssignments = mapOf("Direct" to "DIRECT")
    }
}
