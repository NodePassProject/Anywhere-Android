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
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.model.VlessConfiguration
import com.argsment.anywhere.data.network.LatencyResult
import com.argsment.anywhere.data.network.LatencyTester
import com.argsment.anywhere.data.network.SubscriptionFetcher
import com.argsment.anywhere.data.repository.ConfigRepository
import com.argsment.anywhere.data.repository.RuleSetRepository
import com.argsment.anywhere.data.repository.SubscriptionRepository
import com.argsment.anywhere.vpn.AnywhereVpnService
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

    private val prefs: SharedPreferences =
        application.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    // VPN state
    private val _vpnStatus = MutableStateFlow(VpnStatus.DISCONNECTED)
    val vpnStatus: StateFlow<VpnStatus> = _vpnStatus.asStateFlow()

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
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            vpnService = null
            serviceBound = false
            stopStatsPolling()
        }
    }

    val isButtonDisabled: Boolean
        get() = configRepository.getAll().isEmpty() ||
            (_vpnStatus.value != VpnStatus.CONNECTED && _vpnStatus.value != VpnStatus.DISCONNECTED)

    init {
        // Load saved selected config
        prefs.getString("selectedConfigurationId", null)?.let { id ->
            _selectedConfigId.value = runCatching { UUID.fromString(id) }.getOrNull()
        }
        ensureValidSelection()
    }

    val selectedConfiguration: VlessConfiguration?
        get() {
            val id = _selectedConfigId.value ?: return null
            return configRepository.get(id)
        }

    fun setSelectedConfiguration(config: VlessConfiguration) {
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
            VpnStatus.CONNECTED -> disconnect()
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

    private fun startVpnService(config: VlessConfiguration) {
        val context = getApplication<Application>()
        _vpnStatus.value = VpnStatus.CONNECTING

        // Sync routing rules before starting tunnel
        syncRoutingConfigurationToNE()

        viewModelScope.launch {
            // Resolve server domain on IO thread (avoids NetworkOnMainThreadException)
            val resolvedConfig = withContext(Dispatchers.IO) {
                resolveServerAddress(config)
            }

            val configJson = json.encodeToString(VlessConfiguration.serializer(), resolvedConfig)
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
    }

    private fun switchConfig(config: VlessConfiguration) {
        val context = getApplication<Application>()
        viewModelScope.launch {
            val resolvedConfig = withContext(Dispatchers.IO) {
                resolveServerAddress(config)
            }
            val configJson = json.encodeToString(VlessConfiguration.serializer(), resolvedConfig)
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
    private fun resolveServerAddress(config: VlessConfiguration): VlessConfiguration {
        val address = config.serverAddress
        // Check if already an IP
        try {
            val addr = InetAddress.getByName(address)
            if (addr.hostAddress == address) return config
        } catch (_: Exception) {}

        // Resolve domain to IP, preferring IPv4 for reliable connectivity.
        // Many proxy servers have AAAA records but don't actually accept IPv6.
        return try {
            val all = InetAddress.getAllByName(address)
            val resolved = all.firstOrNull { it is Inet4Address } ?: all.firstOrNull()
            config.copy(resolvedIP = resolved?.hostAddress ?: address)
        } catch (_: Exception) {
            config
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

    fun addConfiguration(config: VlessConfiguration) {
        configRepository.add(config)
        if (_selectedConfigId.value == null) {
            setSelectedConfiguration(config)
        }
    }

    fun updateConfiguration(config: VlessConfiguration) {
        configRepository.update(config)
    }

    fun deleteConfiguration(config: VlessConfiguration) {
        configRepository.delete(config.id)
        if (_selectedConfigId.value == config.id) {
            val remaining = configRepository.getAll()
            _selectedConfigId.value = remaining.firstOrNull()?.id
            prefs.edit().putString("selectedConfigurationId", _selectedConfigId.value?.toString()).apply()
        }
        checkOrphanedRuleSets()
    }

    fun configurations(forSubscription: Subscription): List<VlessConfiguration> {
        return configRepository.getAll().filter { it.subscriptionId == forSubscription.id }
    }

    // =========================================================================
    // Subscription CRUD
    // =========================================================================

    fun addSubscription(configurations: List<VlessConfiguration>, subscription: Subscription) {
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
        val updated = subscription.copy(
            lastUpdate = System.currentTimeMillis(),
            upload = result.upload,
            download = result.download,
            total = result.total,
            expire = result.expire
        )
        subscriptionRepository.update(updated)

        // Remove old configs for this subscription and add new ones
        configRepository.deleteBySubscription(subscription.id)
        result.configurations.forEach { config ->
            configRepository.add(config.copy(subscriptionId = subscription.id))
        }
        ensureValidSelection()
    }

    // =========================================================================
    // Latency Testing
    // =========================================================================

    fun testLatency(forConfig: VlessConfiguration) {
        _latencyResults.value = _latencyResults.value + (forConfig.id to LatencyResult.Testing)
        viewModelScope.launch {
            val result = LatencyTester.test(forConfig)
            _latencyResults.value = _latencyResults.value + (forConfig.id to result)
        }
    }

    fun testAllLatencies() {
        val configs = configRepository.getAll()
        configs.forEach { config ->
            _latencyResults.value = _latencyResults.value + (config.id to LatencyResult.Testing)
        }
        viewModelScope.launch {
            LatencyTester.testAll(configs).collect { (id, result) ->
                _latencyResults.value = _latencyResults.value + (id to result)
            }
        }
    }

    // =========================================================================
    // Routing
    // =========================================================================

    fun syncRoutingConfigurationToNE() {
        ruleSetRepository.syncRoutingFile(
            configRepository.getAll(),
            _selectedConfigId.value?.toString()
        ) { null }
        // Signal service to reload routing if connected
        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            prefs.edit().putLong("routingChanged", System.currentTimeMillis()).apply()
        }
    }

    // =========================================================================
    // Settings
    // =========================================================================

    var ipv6Enabled: Boolean
        get() = prefs.getBoolean("ipv6Enabled", false)
        set(value) = prefs.edit().putBoolean("ipv6Enabled", value).apply()

    var dohEnabled: Boolean
        get() = prefs.getBoolean("dohEnabled", false)
        set(value) = prefs.edit().putBoolean("dohEnabled", value).apply()

    var alwaysOnEnabled: Boolean
        get() = prefs.getBoolean("alwaysOnEnabled", false)
        set(value) = prefs.edit().putBoolean("alwaysOnEnabled", value).apply()

    var bypassCountryCode: String
        get() = prefs.getString("bypassCountryCode", "") ?: ""
        set(value) = prefs.edit().putString("bypassCountryCode", value).apply()

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
