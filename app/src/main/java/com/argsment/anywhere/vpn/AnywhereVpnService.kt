package com.argsment.anywhere.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.ParcelFileDescriptor
import com.argsment.anywhere.MainActivity
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.tls.CertificatePolicy
import com.argsment.anywhere.vpn.util.AnywhereLogger
import com.argsment.anywhere.vpn.util.DnsCache
import com.argsment.anywhere.vpn.util.LogBuffer
import kotlinx.serialization.json.Json

/**
 * Android VPN service that creates a TUN interface, runs the lwIP TCP/IP stack,
 * and routes traffic through VLESS proxy connections.
 *
 * Equivalent of a platform packet tunnel provider.
 */
private val logger = AnywhereLogger("PacketTunnel")

class AnywhereVpnService : VpnService() {

    private var lwipStack: LwipStack? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var currentConfig: ProxyConfiguration? = null
    private val json = Json { ignoreUnknownKeys = true }

    // Tracks the most recent underlying (non-VPN) network so we can detect
    // path changes (e.g. Wi-Fi → Cellular) and restart the lwIP stack to
    // replace stale connections bound to the old interface. Mirrors iOS
    // PacketTunnelProvider's NWPathMonitor logic.
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastUnderlyingNetwork: Network? = null
    private var lastUnderlyingTransports: Int = 0
    private var lastNetworkAvailable: Boolean = false

    // Screen on/off proxy for iOS PacketTunnelProvider's sleep()/wake() — Android
    // doesn't expose those callbacks on a foreground VpnService directly, so we
    // listen on `ACTION_SCREEN_OFF` / `ACTION_SCREEN_ON` (or `ACTION_USER_PRESENT`
    // on locked devices) and infer the duration the device spent in low-power
    // doze. Long sleeps (≥ wakeRestartThresholdSecs) trigger a stack restart so
    // stale connections bound to a NAT entry that has since timed out get
    // replaced instead of waiting for keep-alive failures.
    private var screenStateReceiver: BroadcastReceiver? = null
    private var sleepTimestampMillis: Long = 0L

    // Binder for activity communication
    private val binder = LocalBinder()

    inner class LocalBinder : Binder() {
        val service: AnywhereVpnService get() = this@AnywhereVpnService
    }

    override fun onBind(intent: Intent?): IBinder {
        return if (intent?.action == SERVICE_INTERFACE) {
            // System binding for VPN
            super.onBind(intent)!!
        } else {
            // Activity binding
            binder
        }
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG)
                if (configJson == null) {
                    logger.error("[VPN] Invalid or missing configuration")
                    stopSelf()
                    return START_NOT_STICKY
                }

                val config = runCatching {
                    json.decodeFromString(ProxyConfiguration.serializer(), configJson)
                }.getOrNull()

                if (config == null) {
                    logger.error("[VPN] Invalid or missing configuration")
                    stopSelf()
                    return START_NOT_STICKY
                }

                startVpn(config)
            }
            ACTION_STOP -> stopVpn()
            ACTION_SWITCH_CONFIG -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                val config = runCatching {
                    json.decodeFromString(ProxyConfiguration.serializer(), configJson)
                }.getOrNull() ?: return START_NOT_STICKY
                getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
                    .edit()
                    .putString("lastConfigurationData", configJson)
                    .apply()
                currentConfig = config
                DnsCache.setActiveProxyDomain(config.serverAddress)
                lwipStack?.switchConfiguration(config)
                updateNotification(config.name)
            }
            null -> {
                // System auto-start (Always On VPN)
                handleAlwaysOnStart()
            }
            else -> {
                // Unknown action
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // VPN permission revoked by user or system
        logger.debug("[VPN] Permission revoked, stopping")
        stopVpn()
    }

    // =========================================================================
    // VPN Setup
    // =========================================================================

    /** Applies the global allowInsecure preference to a config's TLS settings. */
    private fun applyGlobalAllowInsecure(config: ProxyConfiguration): ProxyConfiguration {
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("allowInsecure", false)) return config
        val tls = config.tls ?: return config
        if (tls.allowInsecure) return config
        val updatedTls = tls.copy(allowInsecure = true)
        val updatedChain = config.chain?.map { applyGlobalAllowInsecure(it) }
        return config.copy(tls = updatedTls, chain = updatedChain)
    }

    private fun startVpn(config: ProxyConfiguration) {
        // Stop the existing stack before starting a new one. lwIP uses global
        // state (netif_default) and LWIP_SINGLE_NETIF asserts if netif_add() is
        // called while a netif is already registered. We must wait for
        // nativeShutdown() (which calls netif_remove → netif_default = NULL)
        // to complete before calling nativeInit() (which calls netif_add).
        lwipStack?.let { oldStack ->
            lwipStack = null
            val latch = java.util.concurrent.CountDownLatch(1)
            oldStack.stop(onComplete = Runnable { latch.countDown() })
            try {
                latch.await(5, java.util.concurrent.TimeUnit.SECONDS)
            } catch (_: InterruptedException) {}
            tunFd?.close()
            tunFd = null
        }

        // Prime the cert-policy cache so the first TLS handshake uses the latest
        // prefs even if the service starts without VpnViewModel being alive
        // (e.g. Always-On VPN bring-up).
        CertificatePolicy.reload(this)

        val effectiveConfig = applyGlobalAllowInsecure(config)
        logger.debug("[VPN] Starting tunnel to ${effectiveConfig.serverAddress}:${effectiveConfig.serverPort} " +
                "(connect: ${effectiveConfig.connectAddress}), security: ${effectiveConfig.security}, transport: ${effectiveConfig.transport}")

        currentConfig = effectiveConfig
        DnsCache.setActiveProxyDomain(effectiveConfig.serverAddress)
        getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
            .edit()
            .putString("lastConfigurationData", json.encodeToString(ProxyConfiguration.serializer(), effectiveConfig))
            .apply()

        // Create foreground notification
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, buildNotification(effectiveConfig.name),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, buildNotification(effectiveConfig.name))
        }

        // Build and establish TUN interface
        val fd = buildTunInterface(effectiveConfig) ?: run {
            logger.error("[VPN] Failed to set tunnel settings: Failed to establish TUN interface")
            stopSelf()
            return
        }
        tunFd = fd

        // Start lwIP stack. Matches iOS: a single `ipv6DNSEnabled` knob controls
        // both IPv6 routes and AAAA fake-IP resolution.
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val ipv6Dns = prefs.getBoolean("ipv6DnsEnabled", false)

        // Register socket protector so protocol code can protect outbound sockets
        SocketProtector.setProtector(
            fdFn = ::protectSocket,
            socketFn = { protect(it) },
            datagramFn = { protect(it) }
        )

        // Set the underlying physical network for DnsCache so DNS resolution
        // bypasses the VPN tunnel — matching iOS ProxyDNSCache behavior where
        // getaddrinfo always resolves through the physical interface.
        findUnderlyingNetwork()?.let { DnsCache.setUnderlyingNetwork(it) }

        val stack = LwipStack(this)
        lwipStack = stack

        // Wire logger sink so logger.info/.warning/.error forward to the
        // user-facing log buffer (matches iOS LWIPStack+Lifecycle.swift).
        AnywhereLogger.logSink = { message, level ->
            LogBuffer.append(message, level)
        }

        stack.onTunnelSettingsNeedReapply = {
            reapplyTunnelSettings(effectiveConfig)
        }

        stack.start(fd, effectiveConfig, ipv6Dns)

        // Begin observing the underlying physical network so we can restart
        // the stack when the user roams between Wi-Fi and Cellular.
        startNetworkMonitoring()

        // Mirror iOS PacketTunnelProvider.sleep()/wake(): observe screen
        // off/on as a proxy for device-level sleep so we can proactively
        // restart connections after long periods of inactivity (NAT
        // rebinds, server-side idle sweeps).
        startScreenStateMonitoring()
    }

    private fun stopVpn() {
        stopNetworkMonitoring()
        stopScreenStateMonitoring()
        SocketProtector.clearProtector()
        DnsCache.setUnderlyingNetwork(null)

        val stack = lwipStack
        lwipStack = null

        if (stack != null) {
            // Use the completion callback so the TUN file descriptor is closed
            // AFTER the lwIP executor finishes draining — avoids racing with the
            // packet reader thread.  Matches iOS's lwipQueue.sync {} ordering.
            stack.stop(onComplete = Runnable { finishStopVpn() })
        } else {
            finishStopVpn()
        }
    }

    private fun finishStopVpn() {
        tunFd?.close()
        tunFd = null

        AnywhereLogger.logSink = null

        currentConfig = null
        DnsCache.setActiveProxyDomain(null)

        @Suppress("DEPRECATION")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            stopForeground(true)
        }
        stopSelf()
    }

    /** Handles system auto-start when Always On VPN is enabled. */
    private fun handleAlwaysOnStart() {
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val lastConfig = prefs.getString("lastConfigurationData", null)?.let { saved ->
            runCatching {
                json.decodeFromString(ProxyConfiguration.serializer(), saved)
            }.getOrNull()
        }
        if (lastConfig != null) {
            startVpn(lastConfig)
            return
        }

        // Fallback for older installs that do not yet have a saved last configuration.
        val configId = prefs.getString("selectedConfigurationId", null)
        if (configId == null) {
            logger.warning("[VPN] Always On: no saved configuration")
            stopSelf()
            return
        }

        // Try to load saved config from file
        val configFile = filesDir.resolve("configurations.json")
        if (!configFile.exists()) {
            logger.warning("[VPN] Always On: no configurations file")
            stopSelf()
            return
        }

        val configs = runCatching {
            val text = configFile.readText()
            json.decodeFromString<List<ProxyConfiguration>>(text)
        }.getOrNull()

        val config = configs?.find { it.id.toString() == configId }
        if (config == null) {
            logger.warning("[VPN] Always On: selected config not found")
            stopSelf()
            return
        }

        startVpn(config)
    }

    // =========================================================================
    // Tunnel Settings
    // =========================================================================

    // Bypass routes — IP ranges excluded from VPN tunnel (sent directly)
    private data class BypassRoute(val address: String, val prefixLength: Int)

    private fun buildTunInterface(config: ProxyConfiguration): ParcelFileDescriptor? {
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        // Single IPv6 knob, matching iOS: when enabled we add IPv6 address/routes/DNS.
        val ipv6Enabled = prefs.getBoolean("ipv6DnsEnabled", false)
        val remoteAddress = config.connectAddress

        val builder = Builder()
            // TUN IP
            .addAddress("10.8.0.2", 24)
            // DNS servers
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            // MTU
            .setMtu(1400)
            // Block connections without VPN
            .setBlocking(true)

        // IPv6: add address, routes (excluding fc00::/7 and fe80::/10), and DNS servers.
        // Excluded ranges:
        //   fc00::/7  — unique-local (includes our fake IPv6 range fc00::x)
        //   fe80::/10 — link-local
        // Excluding fc00::/7 ensures fake IPv6 IPs fail fast (no route),
        // so apps fall back to IPv4 fake IPs which route through the tunnel.
        if (ipv6Enabled) {
            builder.addAddress("fd00::2", 64)
            // IPv6 routes: ::/0 minus fc00::/7 minus fe80::/10
            builder.addRoute("::", 1)          // 0000::-7fff::
            builder.addRoute("8000::", 2)      // 8000::-bfff::
            builder.addRoute("c000::", 3)      // c000::-dfff::
            builder.addRoute("e000::", 4)      // e000::-efff::
            builder.addRoute("f000::", 5)      // f000::-f7ff::
            builder.addRoute("f800::", 6)      // f800::-fbff::
            builder.addRoute("fe00::", 9)      // fe00::-fe7f::
            builder.addRoute("fec0::", 10)     // fec0::-feff::
            builder.addRoute("ff00::", 8)      // ff00::-ffff:: (multicast)
            // DNS servers (IPv6 DNS queries go through TUN → lwIP → local interception)
            builder.addDnsServer("2606:4700:4700::1111")
            builder.addDnsServer("2606:4700:4700::1001")
        }

        // Apply IPv4 bypass (exclude private/local ranges) via split routing.
        // Android has no addExcludedRoute API, so we replace the catch-all 0.0.0.0/0
        // with the complement routes that cover all public IP space. This allows
        // LAN devices (printers, NAS, local servers) to be reachable without
        // going through the VPN tunnel — matching iOS's excludedRoutes behaviour.
        //
        // The route list below covers 0.0.0.0/0 minus:
        //   10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        // (standard private / CGNAT / loopback ranges from BYPASS_IPV4_ROUTES).
        for (route in PUBLIC_IPV4_ROUTES) {
            builder.addRoute(route.address, route.prefixLength)
        }

        // Session name for system UI
        builder.setSession("Anywhere VPN")

        return try {
            builder.establish()
        } catch (e: Exception) {
            logger.error("[VPN] Failed to set tunnel settings: ${e.message ?: e}")
            null
        }
    }

    /**
     * Re-applies tunnel settings when IPv6 toggle changes.
     *
     * Only rebuilds the TUN interface and swaps the fd. The lwIP stack restart
     * is handled by LwipStack.restartStack() which is called right after this
     * from handleSettingsChanged. This avoids a deadlock: this callback is
     * invoked on the lwipExecutor, and stack.stop() would block on the same thread.
     *
     * Only rebuilds the TUN interface without touching the lwIP stack.
     */
    private fun reapplyTunnelSettings(config: ProxyConfiguration) {
        val newFd = buildTunInterface(config)
        if (newFd != null) {
            val oldFd = tunFd
            tunFd = newFd
            // Swap the TUN fd in the stack — restartStack will handle the lwIP restart
            lwipStack?.swapTunFd(newFd)
            oldFd?.close()
            logger.info("[VPN] Tunnel settings reapplied")
        } else {
            logger.error("[VPN] Failed to reapply tunnel settings")
        }
    }

    // =========================================================================
    // Socket Protection
    // =========================================================================

    /**
     * Protects a socket from VPN routing (prevents loop-back through TUN).
     * Must be called for all outbound sockets used by protocol connections.
     */
    fun protectSocket(fd: Int): Boolean {
        return protect(fd)
    }

    /**
     * Finds the underlying physical (non-VPN) network for DNS resolution.
     * Returns the first network that has internet capability and is not a VPN transport.
     * This allows DnsCache to resolve proxy server domains through the physical
     * interface, matching iOS behavior where getaddrinfo in Network Extension
     * always resolves through the physical network.
     */
    @Suppress("DEPRECATION")
    private fun findUnderlyingNetwork(): Network? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return network
        }
        return null
    }

    // =========================================================================
    // Network Path Monitoring
    // =========================================================================

    /**
     * Begins observing the system's underlying (non-VPN) network so we can
     * detect interface switches (Wi-Fi ↔ Cellular) and trigger a stack restart.
     * Mirrors iOS PacketTunnelProvider.startMonitoringPath().
     */
    private fun startNetworkMonitoring() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return

        lastUnderlyingNetwork = null
        lastUnderlyingTransports = 0
        lastNetworkAvailable = false

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .removeTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handlePathUpdate(network, available = true)
            }

            override fun onLost(network: Network) {
                if (network == lastUnderlyingNetwork) {
                    handlePathUpdate(null, available = false)
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                handlePathUpdate(network, available = true, caps = caps)
            }

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                // Underlying interface DNS / route may have changed; refresh DnsCache
                // so subsequent resolutions go through the new interface.
                if (network == lastUnderlyingNetwork) {
                    DnsCache.setUnderlyingNetwork(network)
                }
            }
        }

        try {
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: SecurityException) {
            logger.debug("[VPN] Failed to register network callback: ${e.message}")
        }
    }

    private fun stopNetworkMonitoring() {
        val callback = networkCallback ?: return
        networkCallback = null
        lastUnderlyingNetwork = null
        lastUnderlyingTransports = 0
        lastNetworkAvailable = false
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
            // Already unregistered
        }
    }

    /**
     * Listens for screen on/off so we can approximate iOS
     * `PacketTunnelProvider.sleep()/wake()`. Long sleeps (≥
     * [WAKE_RESTART_THRESHOLD_SECS]) trigger a stack restart on resume —
     * the same heuristic iOS uses to defeat carrier NAT rebinds and
     * server-side idle sweeps after the device has been off for a while.
     */
    private fun startScreenStateMonitoring() {
        if (screenStateReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        sleepTimestampMillis = System.currentTimeMillis()
                    }
                    Intent.ACTION_SCREEN_ON, Intent.ACTION_USER_PRESENT -> {
                        if (sleepTimestampMillis == 0L) return
                        val sleepSecs = (System.currentTimeMillis() - sleepTimestampMillis) / 1000L
                        sleepTimestampMillis = 0L
                        logger.info("[VPN] Device woke up after ${sleepSecs}s")
                        if (sleepSecs >= WAKE_RESTART_THRESHOLD_SECS) {
                            logger.warning(
                                "[VPN] Long sleep detected (${sleepSecs}s); restarting connections"
                            )
                            lwipStack?.handleNetworkPathChange(
                                "device wake after ${sleepSecs}s sleep"
                            )
                        }
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        try {
            registerReceiver(receiver, filter)
            screenStateReceiver = receiver
        } catch (e: Throwable) {
            logger.debug("[VPN] Screen state receiver register failed: ${e.message}")
        }
    }

    private fun stopScreenStateMonitoring() {
        val r = screenStateReceiver ?: return
        screenStateReceiver = null
        sleepTimestampMillis = 0L
        try { unregisterReceiver(r) } catch (_: Throwable) {}
    }

    /**
     * Decides whether a network update represents a meaningful change that
     * requires restarting the lwIP stack. Mirrors iOS handlePathUpdate(): we
     * compare the current snapshot to the previous one and trigger a restart
     * only when the underlying interface (or its transport set) actually
     * changed, or when connectivity is restored after being lost.
     */
    private fun handlePathUpdate(network: Network?, available: Boolean, caps: NetworkCapabilities? = null) {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return

        if (!available || network == null) {
            if (lastNetworkAvailable) {
                logger.warning("[VPN] Network path unavailable; active connections interrupted")
                lastNetworkAvailable = false
                lastUnderlyingNetwork = null
                lastUnderlyingTransports = 0
                lwipStack?.handleNetworkPathChange("network path unavailable")
            }
            return
        }

        val networkCaps = caps ?: cm.getNetworkCapabilities(network) ?: return
        if (networkCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
        if (!networkCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return

        val transports = transportBitmask(networkCaps)
        val previousNetwork = lastUnderlyingNetwork
        val previousTransports = lastUnderlyingTransports
        val wasAvailable = lastNetworkAvailable

        lastUnderlyingNetwork = network
        lastUnderlyingTransports = transports
        lastNetworkAvailable = true

        // Refresh DnsCache so domain resolution always goes through the new
        // physical interface (matches iOS getaddrinfo behavior in NE).
        DnsCache.setUnderlyingNetwork(network)

        if (!wasAvailable) {
            logger.info("[VPN] Network path restored: ${transportSummary(transports)}; restarting connections")
            lwipStack?.handleNetworkPathChange("network path restored")
            return
        }

        if (previousNetwork != network || previousTransports != transports) {
            logger.warning("[VPN] Network path changed to ${transportSummary(transports)}; restarting connections on new interface")
            lwipStack?.handleNetworkPathChange("network interface change")
        }
    }

    private fun transportBitmask(caps: NetworkCapabilities): Int {
        var mask = 0
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) mask = mask or 0x1
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) mask = mask or 0x2
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) mask = mask or 0x4
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) mask = mask or 0x8
        return mask
    }

    private fun transportSummary(mask: Int): String {
        val parts = mutableListOf<String>()
        if (mask and 0x1 != 0) parts.add("Wi-Fi")
        if (mask and 0x2 != 0) parts.add("Cellular")
        if (mask and 0x4 != 0) parts.add("Ethernet")
        if (mask and 0x8 != 0) parts.add("Bluetooth")
        return if (parts.isEmpty()) "unknown" else parts.joinToString("+")
    }

    // =========================================================================
    // Notifications
    // =========================================================================

    private fun buildNotification(configName: String? = null): Notification {
        val channelId = "anywhere_vpn"
        val channel = NotificationChannel(
            channelId,
            "VPN Service",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Notification for active VPN connection"
            setShowBadge(false)
        }
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(channel)

        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Disconnect action
        val disconnectIntent = PendingIntent.getService(
            this, 1,
            Intent(this, AnywhereVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val disconnectAction = Notification.Action.Builder(
            null, "Disconnect", disconnectIntent
        ).build()

        val contentText = if (configName != null) "Connected - $configName" else "Connected"

        return Notification.Builder(this, channelId)
            .setContentTitle("Anywhere")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .addAction(disconnectAction)
            .build()
    }

    /** Updates the notification text (e.g., after config switch). */
    private fun updateNotification(configName: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, buildNotification(configName))
    }

    // =========================================================================
    // Stats
    // =========================================================================

    /** Returns current traffic statistics (bytes in/out). */
    fun getStats(): Pair<Long, Long> {
        val stack = lwipStack ?: return 0L to 0L
        return stack.totalBytesIn.get() to stack.totalBytesOut.get()
    }

    /** Updates proxy server addresses to prevent routing loops. */
    fun updateProxyServerAddresses(addresses: List<String>) {
        lwipStack?.updateProxyServerAddresses(addresses)
    }

    /** Returns whether the VPN is currently running. */
    val isRunning: Boolean get() = lwipStack != null

    companion object {
        private const val TAG = "AnywhereVPN"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.argsment.anywhere.START"
        const val ACTION_STOP = "com.argsment.anywhere.STOP"
        const val ACTION_SWITCH_CONFIG = "com.argsment.anywhere.SWITCH_CONFIG"
        const val EXTRA_CONFIG = "config"

        /** Wake-from-sleep restart threshold. Mirrors iOS
         *  `TunnelConstants.wakeRestartThreshold`. */
        private val WAKE_RESTART_THRESHOLD_SECS: Long = TunnelConstants.wakeRestartThresholdSec

        // Private/local IPv4 ranges excluded from the VPN tunnel.
        // Mirrors iOS PacketTunnelProvider excludedRoutes.
        private val BYPASS_IPV4_ROUTES = listOf(
            BypassRoute("127.0.0.0", 8),      // loopback
            BypassRoute("10.0.0.0", 8),        // private
            BypassRoute("172.16.0.0", 12),     // private
            BypassRoute("192.168.0.0", 16),    // private
            BypassRoute("100.64.0.0", 10),     // CGNAT
            BypassRoute("162.14.0.0", 16),     // specific
            BypassRoute("211.99.96.0", 19),    // specific
            BypassRoute("162.159.192.0", 24),  // Cloudflare-specific
            BypassRoute("162.159.193.0", 24),  // Cloudflare-specific
            BypassRoute("162.159.195.0", 24),  // Cloudflare-specific
        )

        private val BYPASS_IPV6_ROUTES = listOf(
            BypassRoute("fc00::", 7),   // unique-local
            BypassRoute("fe80::", 10),  // link-local
        )

        // Pre-computed split routes covering 0.0.0.0/0 minus BYPASS_IPV4_ROUTES.
        // Android has no addExcludedRoute API, so we use split routing to let
        // private/CGNAT/loopback traffic bypass the tunnel. This matches the iOS
        // approach of using excludedRoutes on the TUN interface.
        //
        // Excluded: 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8 (loopback),
        //           172.16.0.0/12, 192.168.0.0/16
        // Note: 240.0.0.0/4 (reserved) and 224.0.0.0/4 (multicast) intentionally
        // not routed through VPN.
        private val PUBLIC_IPV4_ROUTES = listOf(
            BypassRoute("0.0.0.0", 5),         // 0.0.0.0   – 7.255.255.255
            BypassRoute("8.0.0.0", 7),          // 8.0.0.0   – 9.255.255.255  (excl 10.0.0.0/8)
            BypassRoute("11.0.0.0", 8),         // 11.0.0.0  – 11.255.255.255
            BypassRoute("12.0.0.0", 6),         // 12.0.0.0  – 15.255.255.255
            BypassRoute("16.0.0.0", 4),         // 16.0.0.0  – 31.255.255.255
            BypassRoute("32.0.0.0", 3),         // 32.0.0.0  – 63.255.255.255
            BypassRoute("64.0.0.0", 3),         // 64.0.0.0  – 95.255.255.255
            BypassRoute("96.0.0.0", 6),         // 96.0.0.0  – 99.255.255.255
            BypassRoute("100.0.0.0", 10),       // 100.0.0.0 – 100.63.255.255 (before CGNAT)
            BypassRoute("100.128.0.0", 9),      // 100.128.0.0 – 100.255.255.255 (after CGNAT)
            BypassRoute("101.0.0.0", 8),        // 101.x.x.x
            BypassRoute("102.0.0.0", 7),        // 102.0.0.0 – 103.255.255.255
            BypassRoute("104.0.0.0", 5),        // 104.0.0.0 – 111.255.255.255
            BypassRoute("112.0.0.0", 5),        // 112.0.0.0 – 119.255.255.255
            BypassRoute("120.0.0.0", 6),        // 120.0.0.0 – 123.255.255.255
            BypassRoute("124.0.0.0", 7),        // 124.0.0.0 – 125.255.255.255
            BypassRoute("126.0.0.0", 8),        // 126.x.x.x               (excl 127.0.0.0/8)
            BypassRoute("128.0.0.0", 3),        // 128.0.0.0 – 159.255.255.255
            BypassRoute("160.0.0.0", 5),        // 160.0.0.0 – 167.255.255.255
            BypassRoute("168.0.0.0", 6),        // 168.0.0.0 – 171.255.255.255
            BypassRoute("172.0.0.0", 12),       // 172.0.0.0 – 172.15.255.255 (before 172.16/12)
            BypassRoute("172.32.0.0", 11),      // 172.32.0.0 – 172.63.255.255
            BypassRoute("172.64.0.0", 10),      // 172.64.0.0 – 172.127.255.255
            BypassRoute("172.128.0.0", 9),      // 172.128.0.0 – 172.255.255.255
            BypassRoute("173.0.0.0", 8),        // 173.x.x.x
            BypassRoute("174.0.0.0", 7),        // 174.0.0.0 – 175.255.255.255
            BypassRoute("176.0.0.0", 4),        // 176.0.0.0 – 191.255.255.255
            BypassRoute("192.0.0.0", 9),        // 192.0.0.0 – 192.127.255.255
            BypassRoute("192.128.0.0", 11),     // 192.128.0.0 – 192.159.255.255
            BypassRoute("192.160.0.0", 13),     // 192.160.0.0 – 192.167.255.255
            BypassRoute("192.169.0.0", 16),     // 192.169.x.x             (after 192.168/16)
            BypassRoute("192.170.0.0", 15),     // 192.170.0.0 – 192.171.255.255
            BypassRoute("192.172.0.0", 14),     // 192.172.0.0 – 192.175.255.255
            BypassRoute("192.176.0.0", 12),     // 192.176.0.0 – 192.191.255.255
            BypassRoute("192.192.0.0", 10),     // 192.192.0.0 – 192.255.255.255
            BypassRoute("193.0.0.0", 8),        // 193.x.x.x
            BypassRoute("194.0.0.0", 7),        // 194.0.0.0 – 195.255.255.255
            BypassRoute("196.0.0.0", 6),        // 196.0.0.0 – 199.255.255.255
            BypassRoute("200.0.0.0", 5),        // 200.0.0.0 – 207.255.255.255
            BypassRoute("208.0.0.0", 4),        // 208.0.0.0 – 223.255.255.255
        )
    }
}
