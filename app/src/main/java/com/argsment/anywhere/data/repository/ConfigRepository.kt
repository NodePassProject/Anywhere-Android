package com.argsment.anywhere.data.repository

import android.content.Context
import com.argsment.anywhere.data.model.ProxyConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonArray
import java.io.File
import java.util.UUID

class ConfigRepository(context: Context) {
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "configurations.json")

    private val _configurations = MutableStateFlow<List<ProxyConfiguration>>(emptyList())
    val configurations: StateFlow<List<ProxyConfiguration>> = _configurations.asStateFlow()

    init {
        _configurations.value = loadFromDisk()
    }

    fun getAll(): List<ProxyConfiguration> = _configurations.value

    fun get(id: UUID): ProxyConfiguration? = _configurations.value.find { it.id == id }

    fun add(config: ProxyConfiguration) {
        _configurations.value = _configurations.value + config
        saveToDisk()
    }

    fun update(config: ProxyConfiguration) {
        _configurations.value = _configurations.value.map {
            if (it.id == config.id) config else it
        }
        saveToDisk()
    }

    fun delete(id: UUID) {
        _configurations.value = _configurations.value.filter { it.id != id }
        saveToDisk()
    }

    fun deleteBySubscription(subscriptionId: UUID) {
        _configurations.value = _configurations.value.filter { it.subscriptionId != subscriptionId }
        saveToDisk()
    }

    fun replaceBySubscription(subscriptionId: UUID, newConfigs: List<ProxyConfiguration>) {
        _configurations.value = _configurations.value.filter { it.subscriptionId != subscriptionId } + newConfigs
        saveToDisk()
    }

    /**
     * Decodes the configuration list element-by-element, dropping entries that
     * fail to decode, so an unrecognized entry — e.g. a saved configuration
     * referencing a removed `outboundProtocol` — is skipped instead of
     * corrupting the entire list.
     */
    private fun loadFromDisk(): List<ProxyConfiguration> {
        if (!file.exists()) return emptyList()
        return runCatching {
            val array = json.parseToJsonElement(file.readText()).jsonArray
            array.mapNotNull { element ->
                runCatching {
                    json.decodeFromJsonElement<ProxyConfiguration>(element)
                }.getOrNull()
            }
        }.getOrElse {
            println("Failed to load configurations: $it")
            emptyList()
        }
    }

    private fun saveToDisk() {
        // Snapshot here so an in-flight write doesn't observe a later mutation.
        // Mirrors iOS `Task.detached { try data.write(to: url, options: .atomic) }`.
        val payload = json.encodeToString(_configurations.value)
        file.writeTextAsync(payload) {
            println("Failed to save configurations: $it")
        }
    }
}
