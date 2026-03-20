package com.argsment.anywhere.viewmodel

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.net.VpnService
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.argsment.anywhere.data.model.ProxyChain
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.network.LatencyResult
import com.argsment.anywhere.data.network.LatencyTester
import com.argsment.anywhere.data.network.SubscriptionFetcher
import com.argsment.anywhere.data.repository.CertificateRepository
import com.argsment.anywhere.data.repository.ChainRepository
import com.argsment.anywhere.data.repository.ConfigRepository
import com.argsment.anywhere.data.repository.RuleSetRepository
import com.argsment.anywhere.data.repository.SubscriptionRepository
import com.argsment.anywhere.vpn.protocol.tls.TlsClient
import com.argsment.anywhere.vpn.AnywhereVpnService
import com.argsment.anywhere.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.net.Inet4Address
import java.net.InetAddress
import java.util.UUID

enum class VpnStatus {
    DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, REASSERTING
}

private const val TAG = "VpnViewModel"

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    val configRepository = ConfigRepository(application)
    val subscriptionRepository = SubscriptionRepository(application)
    val ruleSetRepository = RuleSetRepository(application)
    val certificateRepository = CertificateRepository(application)
    val chainRepository = ChainRepository(application)

    private val prefs: SharedPreferences =
        application.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    // VPN state
    private val _vpnStatus = MutableStateFlow(VpnStatus.DISCONNECTED)
    val vpnStatus: StateFlow<VpnStatus> = _vpnStatus.asStateFlow()
    private var pendingReconnect = false

    // Traffic stats
    private val _bytesIn = MutableStateFlow(0L)
    val bytesIn: StateFlow<Long> = _bytesIn.asStateFlow()

    private val _bytesOut = MutableStateFlow(0L)
    val bytesOut: StateFlow<Long> = _bytesOut.asStateFlow()

    // Selected configuration
    private val _selectedConfigId = MutableStateFlow<UUID?>(null)
    val selectedConfigId: StateFlow<UUID?> = _selectedConfigId.asStateFlow()

    // Latency results
    private val _latencyResults = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())
    val latencyResults: StateFlow<Map<UUID, LatencyResult>> = _latencyResults.asStateFlow()

    // Error state
    private val _startError = MutableStateFlow<String?>(null)
    val startError: StateFlow<String?> = _startError.asStateFlow()

    // Orphaned rule set names (after config deletion)
    private val _orphanedRuleSetNames = MutableStateFlow<List<String>>(emptyList())
    val orphanedRuleSetNames: StateFlow<List<String>> = _orphanedRuleSetNames.asStateFlow()

    // Chain selection
    private val _selectedChainId = MutableStateFlow<UUID?>(null)
    val selectedChainId: StateFlow<UUID?> = _selectedChainId.asStateFlow()

    // Chain latency results
    private val _chainLatencyResults = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())
    val chainLatencyResults: StateFlow<Map<UUID, LatencyResult>> = _chainLatencyResults.asStateFlow()

    // VPN permission request callback
    var onRequestVpnPermission: ((Intent) -> Unit)? = null

    // Service binding
    private var vpnService: AnywhereVpnService? = null
    private var serviceBound = false
    private var statsJob: Job? = null
    private var pendingConnectAfterPermission = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? AnywhereVpnService.LocalBinder ?: return
            vpnService = localBinder.service
            serviceBound = true

            // Update status based on service state
            if (localBinder.service.isRunning) {
                _vpnStatus.value = VpnStatus.CONNECTED
                startStatsPolling()
                selectedConfiguration?.let { syncProxyServerAddresses(it) }
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            vpnService = null
            serviceBound = false
            stopStatsPolling()
        }
    }

    val isButtonDisabled: Boolean
        get() = (selectedConfiguration == null) ||
            (_vpnStatus.value != VpnStatus.CONNECTED && _vpnStatus.value != VpnStatus.DISCONNECTED)

    init {
        // Restore chain or config selection
        val savedChainId = prefs.getString("selectedChainId", null)?.let {
            runCatching { UUID.fromString(it) }.getOrNull()
        }
        if (savedChainId != null && chainRepository.get(savedChainId) != null) {
            _selectedChainId.value = savedChainId
        } else {
            prefs.getString("selectedConfigurationId", null)?.let { id ->
                _selectedConfigId.value = runCatching { UUID.fromString(id) }.getOrNull()
            }
        }
        ensureValidSelection()

        // Sync trusted certificate fingerprints to TlsClient
        TlsClient.trustedFingerprints = certificateRepository.fingerprints.value
        viewModelScope.launch {
            certificateRepository.fingerprints.collect { fingerprints ->
                TlsClient.trustedFingerprints = fingerprints
            }
        }
    }

    val selectedConfiguration: ProxyConfiguration?
        get() {
            // If a chain is selected, resolve it
            val chainId = _selectedChainId.value
            if (chainId != null) {
                val chain = chainRepository.get(chainId) ?: return null
                return resolveChain(chain)
            }
            val id = _selectedConfigId.value ?: return null
            return configRepository.get(id)
        }

    fun setSelectedConfiguration(config: ProxyConfiguration) {
        _selectedChainId.value = null
        prefs.edit().remove("selectedChainId").apply()
        _selectedConfigId.value = config.id
        prefs.edit().putString("selectedConfigurationId", config.id.toString()).apply()

        // If VPN is connected, push new configuration to the tunnel
        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            switchConfig(config)
        }
    }

    // =========================================================================
    // VPN Lifecycle
    // =========================================================================

    fun toggleVPN() {
        when (_vpnStatus.value) {
            VpnStatus.DISCONNECTED -> connect()
            VpnStatus.CONNECTED, VpnStatus.CONNECTING -> disconnect()
            else -> {}
        }
    }

    fun connect() {
        val config = selectedConfiguration ?: return
        val context = getApplication<Application>()

        // Check VPN permission
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            pendingConnectAfterPermission = true
            onRequestVpnPermission?.invoke(prepareIntent)
            return
        }

        startVpnService(config)
    }

    /** Called from Activity after VPN permission is granted. */
    fun onVpnPermissionGranted() {
        if (pendingConnectAfterPermission) {
            pendingConnectAfterPermission = false
            val config = selectedConfiguration ?: return
            startVpnService(config)
        }
    }

    /** Called from Activity after VPN permission is denied. */
    fun onVpnPermissionDenied() {
        pendingConnectAfterPermission = false
        _startError.value = "VPN permission denied"
    }

    /**
     * Applies the global allowInsecure setting to a proxy configuration's TLS config.
     * The global toggle overrides per-proxy setting when enabled.
     */
    private fun applyGlobalAllowInsecure(config: ProxyConfiguration): ProxyConfiguration {
        if (!allowInsecure) return config
        val tls = config.tls ?: return config
        if (tls.allowInsecure) return config  // already insecure
        val updatedTls = tls.copy(allowInsecure = true)
        val updatedChain = config.chain?.map { applyGlobalAllowInsecure(it) }
        return config.copy(tls = updatedTls, chain = updatedChain)
    }

    private fun startVpnService(config: ProxyConfiguration) {
        val context = getApplication<Application>()
        _vpnStatus.value = VpnStatus.CONNECTING

        // Sync routing rules before starting tunnel
        syncRoutingConfigurationToNE()

        viewModelScope.launch {
            // Resolve server domain on IO thread (avoids NetworkOnMainThreadException)
            val resolvedConfig = withContext(Dispatchers.IO) {
                resolveServerAddress(applyGlobalAllowInsecure(config))
            }
            DnsCache.setActiveProxyDomain(resolvedConfig.serverAddress)
            syncProxyServerAddresses(resolvedConfig)

            val configJson = json.encodeToString(ProxyConfiguration.serializer(), resolvedConfig)
            val intent = Intent(context, AnywhereVpnService::class.java).apply {
                action = AnywhereVpnService.ACTION_START
                putExtra(AnywhereVpnService.EXTRA_CONFIG, configJson)
            }

            try {
                context.startForegroundService(intent)
                // Bind to service for stats polling and config switching
                bindToService()
                _vpnStatus.value = VpnStatus.CONNECTED
                startStatsPolling()
            } catch (e: Exception) {
                Log.e(TAG, "[VPN] Failed to start service: ${e.message}")
                _vpnStatus.value = VpnStatus.DISCONNECTED
                _startError.value = e.message
            }
        }
    }

    fun disconnect() {
        _vpnStatus.value = VpnStatus.DISCONNECTING
        val context = getApplication<Application>()

        stopStatsPolling()

        val intent = Intent(context, AnywhereVpnService::class.java).apply {
            action = AnywhereVpnService.ACTION_STOP
        }
        try {
            context.startService(intent)
        } catch (_: Exception) {}

        unbindFromService()
        _bytesIn.value = 0
        _bytesOut.value = 0
        _vpnStatus.value = VpnStatus.DISCONNECTED

        // Auto-reconnect if pending (matching iOS reconnectVPN)
        if (pendingReconnect) {
            pendingReconnect = false
            connect()
        }
    }

    /**
     * Stops the VPN and automatically reconnects once disconnected.
     * Used when switching configurations while connected (matching iOS reconnectVPN).
     */
    fun reconnect() {
        val status = _vpnStatus.value
        if (status != VpnStatus.CONNECTED && status != VpnStatus.CONNECTING) return
        pendingReconnect = true
        disconnect()
    }

    private fun switchConfig(config: ProxyConfiguration) {
        val context = getApplication<Application>()
        viewModelScope.launch {
            val resolvedConfig = withContext(Dispatchers.IO) {
                resolveServerAddress(applyGlobalAllowInsecure(config))
            }
            DnsCache.setActiveProxyDomain(resolvedConfig.serverAddress)
            syncProxyServerAddresses(resolvedConfig)
            val configJson = json.encodeToString(ProxyConfiguration.serializer(), resolvedConfig)
            val intent = Intent(context, AnywhereVpnService::class.java).apply {
                action = AnywhereVpnService.ACTION_SWITCH_CONFIG
                putExtra(AnywhereVpnService.EXTRA_CONFIG, configJson)
            }
            try {
                context.startService(intent)
            } catch (_: Exception) {}
        }
    }

    // =========================================================================
    // Service Binding
    // =========================================================================

    private fun bindToService() {
        if (serviceBound) return
        val context = getApplication<Application>()
        val intent = Intent(context, AnywhereVpnService::class.java)
        context.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    private fun unbindFromService() {
        if (!serviceBound) return
        val context = getApplication<Application>()
        try {
            context.unbindService(serviceConnection)
        } catch (_: Exception) {}
        vpnService = null
        serviceBound = false
    }

    // =========================================================================
    // Traffic Stats Polling
    // =========================================================================

    private fun startStatsPolling() {
        if (statsJob != null) return
        statsJob = viewModelScope.launch {
            while (true) {
                delay(1000)
                val service = vpnService
                if (service != null && service.isRunning) {
                    val (bytesIn, bytesOut) = service.getStats()
                    _bytesIn.value = bytesIn
                    _bytesOut.value = bytesOut
                } else if (service != null && !service.isRunning &&
                    _vpnStatus.value == VpnStatus.CONNECTED) {
                    // Service is bound but no longer running — it actually died
                    _vpnStatus.value = VpnStatus.DISCONNECTED
                    _bytesIn.value = 0
                    _bytesOut.value = 0
                    break
                }
                // If service is null, binding is still in progress — keep polling
            }
        }
    }

    private fun stopStatsPolling() {
        statsJob?.cancel()
        statsJob = null
    }

    // =========================================================================
    // DNS Resolution
    // =========================================================================

    /**
     * Resolves server address to IP before tunnel starts (avoids DNS-over-tunnel loop).
     * If already an IP, returns config as-is. If a domain, resolves via system DNS.
     */
    private fun resolveServerAddress(config: ProxyConfiguration): ProxyConfiguration {
        val resolvedConfig = resolveAddress(config)
        // Also resolve chain proxy addresses
        val resolvedChain = config.chain?.map { resolveAddress(it) }
        return if (resolvedChain != null) resolvedConfig.copy(chain = resolvedChain) else resolvedConfig
    }

    private fun resolveAddress(config: ProxyConfiguration): ProxyConfiguration {
        val resolved = resolveServerAddress(config.serverAddress) ?: return config
        return config.copy(resolvedIP = resolved)
    }

    private fun resolveServerAddress(address: String): String? {
        val bare = if (address.startsWith("[") && address.endsWith("]")) {
            address.substring(1, address.length - 1)
        } else {
            address
        }

        if (DnsCache.isIpAddress(bare)) return bare

        return try {
            val all = InetAddress.getAllByName(bare)
            val resolved = all.firstOrNull { it is Inet4Address } ?: all.firstOrNull()
            resolved?.hostAddress
        } catch (_: Exception) {
            null
        }
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    override fun onCleared() {
        super.onCleared()
        stopStatsPolling()
        unbindFromService()
    }

    fun clearStartError() {
        _startError.value = null
    }

    fun clearOrphanedRuleSetNames() {
        _orphanedRuleSetNames.value = emptyList()
    }

    // =========================================================================
    // Configuration CRUD
    // =========================================================================

    fun addConfiguration(config: ProxyConfiguration) {
        configRepository.add(config)
        if (_selectedConfigId.value == null) {
            setSelectedConfiguration(config)
        }
    }

    fun updateConfiguration(config: ProxyConfiguration) {
        configRepository.update(config)
    }

    fun deleteConfiguration(config: ProxyConfiguration) {
        configRepository.delete(config.id)
        if (_selectedConfigId.value == config.id) {
            val remaining = configRepository.getAll()
            _selectedConfigId.value = remaining.firstOrNull()?.id
            prefs.edit().putString("selectedConfigurationId", _selectedConfigId.value?.toString()).apply()
        }
        // If a chain is selected and now broken, fall back
        val chainId = _selectedChainId.value
        if (chainId != null) {
            val chain = chainRepository.get(chainId)
            if (chain == null || resolveChain(chain) == null) {
                _selectedChainId.value = null
                prefs.edit().remove("selectedChainId").apply()
                ensureValidSelection()
            }
        }
        checkOrphanedRuleSets()
    }

    fun configurations(forSubscription: Subscription): List<ProxyConfiguration> {
        return configRepository.getAll().filter { it.subscriptionId == forSubscription.id }
    }

    // =========================================================================
    // Subscription CRUD
    // =========================================================================

    fun addSubscription(configurations: List<ProxyConfiguration>, subscription: Subscription) {
        subscriptionRepository.add(subscription)
        configurations.forEach { config ->
            configRepository.add(config.copy(subscriptionId = subscription.id))
        }
        if (_selectedConfigId.value == null) {
            configurations.firstOrNull()?.let { setSelectedConfiguration(it) }
        }
    }

    fun deleteSubscription(subscription: Subscription) {
        subscriptionRepository.delete(subscription.id, configRepository)
        ensureValidSelection()
        checkOrphanedRuleSets()
    }

    suspend fun updateSubscription(subscription: Subscription) {
        val result = SubscriptionFetcher.fetch(subscription.url)

        // Match new configurations against old ones by name to preserve IDs (and routing rules).
        // When multiple configs share the same name, they are matched positionally within that group.
        val oldConfigs = configRepository.getAll().filter { it.subscriptionId == subscription.id }

        // Group old configs by name, preserving order within each group
        val oldByName = mutableMapOf<String, MutableList<ProxyConfiguration>>()
        for (old in oldConfigs) {
            oldByName.getOrPut(old.name) { mutableListOf() }.add(old)
        }
        // Track how many old configs per name have been consumed
        val oldNameCursor = mutableMapOf<String, Int>()

        val newConfigs = result.configurations.map { newConfig ->
            val name = newConfig.name
            val cursor = oldNameCursor.getOrDefault(name, 0)
            val group = oldByName[name]
            val id = if (group != null && cursor < group.size) {
                oldNameCursor[name] = cursor + 1
                group[cursor].id
            } else {
                newConfig.id
            }
            newConfig.copy(id = id, subscriptionId = subscription.id)
        }

        // Atomically replace old configurations with new ones (single StateFlow emission)
        configRepository.replaceBySubscription(subscription.id, newConfigs)

        // Update subscription metadata (preserve old values when new ones are null)
        val updated = subscription.copy(
            lastUpdate = System.currentTimeMillis(),
            name = result.name ?: subscription.name,
            upload = result.upload ?: subscription.upload,
            download = result.download ?: subscription.download,
            total = result.total ?: subscription.total,
            expire = result.expire ?: subscription.expire
        )
        subscriptionRepository.update(updated)

        ensureValidSelection()
    }

    // =========================================================================
    // Latency Testing
    // =========================================================================

    fun testLatency(forConfig: ProxyConfiguration) {
        syncProxyServerAddresses(forConfig)
        _latencyResults.value = _latencyResults.value + (forConfig.id to LatencyResult.Testing)
        viewModelScope.launch {
            val result = LatencyTester.test(applyGlobalAllowInsecure(forConfig))
            _latencyResults.value = _latencyResults.value + (forConfig.id to result)
        }
    }

    fun testAllLatencies() {
        val configs = configRepository.getAll()
        syncProxyServerAddresses(configs)
        configs.forEach { config ->
            _latencyResults.value = _latencyResults.value + (config.id to LatencyResult.Testing)
        }
        viewModelScope.launch {
            LatencyTester.testAll(configs.map { applyGlobalAllowInsecure(it) }).collect { (id, result) ->
                _latencyResults.value = _latencyResults.value + (id to result)
            }
        }
    }

    // =========================================================================
    // Chain CRUD & Selection
    // =========================================================================

    fun addChain(chain: ProxyChain) {
        chainRepository.add(chain)
    }

    fun updateChain(chain: ProxyChain) {
        chainRepository.update(chain)
        // Re-resolve if this is the active chain
        if (_selectedChainId.value == chain.id) {
            val resolved = resolveChain(chain)
            if (resolved != null && _vpnStatus.value == VpnStatus.CONNECTED) {
                switchConfig(resolved)
            }
        }
    }

    fun deleteChain(chain: ProxyChain) {
        chainRepository.delete(chain.id)
        if (_selectedChainId.value == chain.id) {
            _selectedChainId.value = null
            prefs.edit().remove("selectedChainId").apply()
            ensureValidSelection()
        }
    }

    fun selectChain(chain: ProxyChain) {
        val resolved = resolveChain(chain) ?: return
        _selectedChainId.value = chain.id
        prefs.edit()
            .putString("selectedChainId", chain.id.toString())
            .remove("selectedConfigurationId")
            .apply()
        _selectedConfigId.value = null

        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            switchConfig(resolved)
        }
    }

    /**
     * Resolves a chain into a composite ProxyConfiguration.
     * The last proxy becomes the main config; preceding proxies fill the [chain] field.
     */
    fun resolveChain(chain: ProxyChain): ProxyConfiguration? {
        val configs = chain.proxyIds.mapNotNull { id -> configRepository.get(id) }
        if (configs.size != chain.proxyIds.size || configs.size < 2) return null
        val exitProxy = configs.last()
        val chainProxies = configs.dropLast(1)
        return exitProxy.copy(
            name = chain.name,
            chain = chainProxies
        )
    }

    // =========================================================================
    // Chain Latency Testing
    // =========================================================================

    fun testChainLatency(chain: ProxyChain) {
        val resolved = resolveChain(chain) ?: return
        syncProxyServerAddresses(resolved)
        _chainLatencyResults.value = _chainLatencyResults.value + (chain.id to LatencyResult.Testing)
        viewModelScope.launch {
            val result = LatencyTester.test(applyGlobalAllowInsecure(resolved))
            _chainLatencyResults.value = _chainLatencyResults.value + (chain.id to result)
        }
    }

    fun testAllChainLatencies() {
        val chains = chainRepository.getAll()
        val resolvedChains = chains.mapNotNull { chain ->
            resolveChain(chain)?.let { chain.id to it }
        }
        syncProxyServerAddresses(resolvedChains.map { it.second })
        resolvedChains.forEach { (chainId, _) ->
            _chainLatencyResults.value = _chainLatencyResults.value + (chainId to LatencyResult.Testing)
        }
        viewModelScope.launch {
            val configs = resolvedChains.map { applyGlobalAllowInsecure(it.second) }
            val idMap = resolvedChains.associate { (chainId, config) -> config.id to chainId }
            LatencyTester.testAll(configs).collect { (configId, result) ->
                val chainId = idMap[configId] ?: return@collect
                _chainLatencyResults.value = _chainLatencyResults.value + (chainId to result)
            }
        }
    }

    // =========================================================================
    // Routing
    // =========================================================================

    fun syncRoutingConfigurationToNE() {
        ruleSetRepository.syncRoutingFile(
            configRepository.getAll()
        ) { address -> resolveServerAddress(address) }
        // Signal service to reload routing if connected
        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            prefs.edit().putLong("routingChanged", System.currentTimeMillis()).apply()
        }
    }

    // =========================================================================
    // Proxy Server Address Bypass
    // =========================================================================

    /** Collects all proxy server addresses (domains + resolved IPs) from all
     *  configurations and sends them to the VPN service. This prevents routing
     *  loops when proxy server domains match routing rules. */
    private fun syncProxyServerAddresses(configuration: ProxyConfiguration) {
        syncProxyServerAddresses(listOf(configuration))
    }

    private fun syncProxyServerAddresses(configurations: List<ProxyConfiguration>) {
        val addresses = linkedSetOf<String>()
        for (config in configurations) {
            collectProxyServerAddresses(config, addresses)
        }

        val persisted = addresses.toList()
        prefs.edit().putString("proxyServerAddresses", json.encodeToString(persisted)).apply()
        vpnService?.updateProxyServerAddresses(persisted)
    }

    private fun collectProxyServerAddresses(
        configuration: ProxyConfiguration,
        addresses: MutableSet<String>
    ) {
        addresses.add(configuration.serverAddress)
        configuration.resolvedIP?.let(addresses::add)
        DnsCache.cachedIPs(configuration.serverAddress)?.let(addresses::addAll)
        configuration.chain?.forEach { hop ->
            collectProxyServerAddresses(hop, addresses)
        }
    }

    // =========================================================================
    // Settings
    // =========================================================================

    var alwaysOnEnabled: Boolean
        get() = prefs.getBoolean("alwaysOnEnabled", false)
        set(value) = prefs.edit().putBoolean("alwaysOnEnabled", value).apply()

    var bypassCountryCode: String
        get() = prefs.getString("bypassCountryCode", "") ?: ""
        set(value) = prefs.edit().putString("bypassCountryCode", value).apply()

    var ipv6ConnectionsEnabled: Boolean
        get() = prefs.getBoolean("ipv6ConnectionsEnabled", false)
        set(value) = prefs.edit().putBoolean("ipv6ConnectionsEnabled", value).apply()

    var ipv6DnsEnabled: Boolean
        get() = prefs.getBoolean("ipv6DnsEnabled", false)
        set(value) = prefs.edit().putBoolean("ipv6DnsEnabled", value).apply()

    var encryptedDnsEnabled: Boolean
        get() = prefs.getBoolean("encryptedDnsEnabled", false)
        set(value) = prefs.edit().putBoolean("encryptedDnsEnabled", value).apply()

    var encryptedDnsProtocol: String
        get() = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
        set(value) = prefs.edit().putString("encryptedDnsProtocol", value).apply()

    var encryptedDnsServer: String
        get() = prefs.getString("encryptedDnsServer", "") ?: ""
        set(value) = prefs.edit().putString("encryptedDnsServer", value).apply()

    var allowInsecure: Boolean
        get() = prefs.getBoolean("allowInsecure", false)
        set(value) = prefs.edit().putBoolean("allowInsecure", value).apply()

    val hasCompletedOnboarding: Boolean
        get() = prefs.getBoolean("hasCompletedOnboarding", false)

    fun completeOnboarding(bypassCountryCode: String, adBlockEnabled: Boolean) {
        // Apply country bypass
        if (bypassCountryCode.isNotEmpty()) {
            this.bypassCountryCode = bypassCountryCode
        }

        // Apply ADBlock → REJECT
        if (adBlockEnabled) {
            val adBlock = ruleSetRepository.ruleSets.value.find { it.name == "ADBlock" }
            if (adBlock != null) {
                ruleSetRepository.updateAssignment(adBlock, "REJECT")
            }
        }

        // Sync routing to service
        syncRoutingConfigurationToNE()

        // Mark onboarding completed
        prefs.edit().putBoolean("hasCompletedOnboarding", true).apply()
    }

    private fun ensureValidSelection() {
        val selectedId = _selectedConfigId.value
        if (selectedId == null || configRepository.get(selectedId) == null) {
            val newId = configRepository.getAll().firstOrNull()?.id
            _selectedConfigId.value = newId
            prefs.edit().putString("selectedConfigurationId", newId?.toString()).apply()
        }
    }

    private fun checkOrphanedRuleSets() {
        val configIds = configRepository.getAll().map { it.id.toString() }.toSet()
        val orphaned = ruleSetRepository.clearOrphanedAssignments(configIds)
        if (orphaned.isNotEmpty()) {
            _orphanedRuleSetNames.value = orphaned
            syncRoutingConfigurationToNE()
        }
    }
}
