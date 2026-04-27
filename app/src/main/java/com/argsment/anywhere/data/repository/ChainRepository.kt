package com.argsment.anywhere.data.repository

import android.content.Context
import com.argsment.anywhere.data.model.ProxyChain
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

class ChainRepository(context: Context) {
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "chains.json")

    private val _chains = MutableStateFlow<List<ProxyChain>>(emptyList())
    val chains: StateFlow<List<ProxyChain>> = _chains.asStateFlow()

    init {
        _chains.value = loadFromDisk()
    }

    fun getAll(): List<ProxyChain> = _chains.value

    fun get(id: UUID): ProxyChain? = _chains.value.find { it.id == id }

    fun add(chain: ProxyChain) {
        _chains.value = _chains.value + chain
        saveToDisk()
    }

    fun update(chain: ProxyChain) {
        _chains.value = _chains.value.map {
            if (it.id == chain.id) chain else it
        }
        saveToDisk()
    }

    fun delete(id: UUID) {
        _chains.value = _chains.value.filter { it.id != id }
        saveToDisk()
    }

    private fun loadFromDisk(): List<ProxyChain> {
        if (!file.exists()) return emptyList()
        return runCatching {
            json.decodeFromString<List<ProxyChain>>(file.readText())
        }.getOrElse {
            println("Failed to load chains: $it")
            emptyList()
        }
    }

    private fun saveToDisk() {
        val payload = json.encodeToString(_chains.value)
        file.writeTextAsync(payload) {
            println("Failed to save chains: $it")
        }
    }
}
