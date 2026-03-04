package com.argsment.anywhere.data.repository

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.argsment.anywhere.data.model.DomainRule
import com.argsment.anywhere.data.model.DomainRuleType
import com.argsment.anywhere.data.model.VlessConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

class RuleSetRepository(private val context: Context) {

    data class RuleSet(
        val id: String,
        val name: String,
        val assignedConfigurationId: String? = null
    )

    companion object {
        private const val TAG = "RuleSetStore"
        private const val ASSIGNMENTS_KEY = "ruleSetAssignments"
        private val BUILT_IN = listOf("Telegram", "Netflix", "YouTube", "Disney+", "TikTok", "ChatGPT", "Claude")
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    private val _ruleSets = MutableStateFlow<List<RuleSet>>(emptyList())
    val ruleSets: StateFlow<List<RuleSet>> = _ruleSets.asStateFlow()

    init {
        val assignments = loadAssignments()
        _ruleSets.value = BUILT_IN.map { name ->
            RuleSet(id = name, name = name, assignedConfigurationId = assignments[name])
        }
    }

    fun updateAssignment(ruleSet: RuleSet, configurationId: String?) {
        _ruleSets.value = _ruleSets.value.map {
            if (it.id == ruleSet.id) it.copy(assignedConfigurationId = configurationId) else it
        }
        saveAssignments()
    }

    fun clearOrphanedAssignments(availableConfigIds: Set<String>): List<String> {
        val affected = mutableListOf<String>()
        _ruleSets.value = _ruleSets.value.map { ruleSet ->
            val assignedId = ruleSet.assignedConfigurationId
            if (assignedId != null && assignedId != "DIRECT" && assignedId !in availableConfigIds) {
                affected.add(ruleSet.name)
                ruleSet.copy(assignedConfigurationId = null)
            } else {
                ruleSet
            }
        }
        if (affected.isNotEmpty()) saveAssignments()
        return affected
    }

    fun loadRules(name: String): List<DomainRule> {
        return runCatching {
            val inputStream = context.assets.open("rulesets/$name.json")
            val text = inputStream.bufferedReader().use { it.readText() }
            json.decodeFromString<List<DomainRule>>(text)
        }.getOrElse {
            Log.e(TAG, "Failed to load rules for '$name': $it")
            emptyList()
        }
    }

    fun syncRoutingFile(
        configurations: List<VlessConfiguration>,
        selectedConfigId: String?,
        resolveAddress: (String) -> String?
    ) {
        val routingFile = File(context.filesDir, "routing.json")

        val routingRules = JSONArray()
        val configsObj = JSONObject()

        for (ruleSet in _ruleSets.value) {
            // "Default" (null) → use the selected configuration
            val assignedId = ruleSet.assignedConfigurationId ?: selectedConfigId ?: continue
            val domainRules = loadRules(ruleSet.name)
            if (domainRules.isEmpty()) continue

            val rulesArray = JSONArray()
            for (rule in domainRules) {
                val typeStr = when (rule.type) {
                    DomainRuleType.DOMAIN -> "domain"
                    DomainRuleType.DOMAIN_SUFFIX -> "domainSuffix"
                    DomainRuleType.DOMAIN_KEYWORD -> "domainKeyword"
                }
                rulesArray.put(JSONObject().apply {
                    put("type", typeStr)
                    put("value", rule.value)
                })
            }

            val ruleEntry = JSONObject().apply { put("domainRules", rulesArray) }

            if (assignedId == "DIRECT") {
                ruleEntry.put("action", "direct")
            } else {
                val configUuid = runCatching { UUID.fromString(assignedId) }.getOrNull() ?: continue
                val config = configurations.find { it.id == configUuid } ?: continue
                ruleEntry.put("action", "proxy")
                ruleEntry.put("configId", assignedId)
                val configJson = Json.encodeToString(VlessConfiguration.serializer(), config)
                val configObj = JSONObject(configJson)
                resolveAddress(config.serverAddress)?.let { configObj.put("resolvedIP", it) }
                configsObj.put(assignedId, configObj)
            }

            routingRules.put(ruleEntry)
        }

        val routing = JSONObject().apply {
            put("rules", routingRules)
            put("configs", configsObj)
        }

        runCatching {
            routingFile.writeText(routing.toString())
        }.onFailure {
            Log.e(TAG, "Failed to write routing.json: $it")
        }
    }

    private fun loadAssignments(): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val stored = prefs.getStringSet(ASSIGNMENTS_KEY, null)
        stored?.forEach { entry ->
            val parts = entry.split("=", limit = 2)
            if (parts.size == 2) result[parts[0]] = parts[1]
        }
        return result
    }

    private fun saveAssignments() {
        val set = _ruleSets.value.mapNotNull { rs ->
            rs.assignedConfigurationId?.let { "${rs.name}=$it" }
        }.toSet()
        prefs.edit().putStringSet(ASSIGNMENTS_KEY, set).apply()
    }
}
