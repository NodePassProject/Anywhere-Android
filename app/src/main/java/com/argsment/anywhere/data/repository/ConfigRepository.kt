package com.argsment.anywhere.data.repository

import android.content.Context
import com.argsment.anywhere.data.model.VlessConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

class ConfigRepository(context: Context) {
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "configurations.json")

    private val _configurations = MutableStateFlow<List<VlessConfiguration>>(emptyList())
    val configurations: StateFlow<List<VlessConfiguration>> = _configurations.asStateFlow()

    init {
        _configurations.value = loadFromDisk()
    }

    fun getAll(): List<VlessConfiguration> = _configurations.value

    fun get(id: UUID): VlessConfiguration? = _configurations.value.find { it.id == id }

    fun add(config: VlessConfiguration) {
        _configurations.value = _configurations.value + config
        saveToDisk()
    }

    fun update(config: VlessConfiguration) {
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

    private fun loadFromDisk(): List<VlessConfiguration> {
        if (!file.exists()) return emptyList()
        return runCatching {
            json.decodeFromString<List<VlessConfiguration>>(file.readText())
        }.getOrElse {
            println("Failed to load configurations: $it")
            emptyList()
        }
    }

    private fun saveToDisk() {
        runCatching {
            file.writeText(json.encodeToString(_configurations.value))
        }.onFailure {
            println("Failed to save configurations: $it")
        }
    }
}
