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
 */
private val logger = AnywhereLogger("PacketTunnel")

class AnywhereVpnService : VpnService() {

    private var lwipStack: LwipStack? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var currentConfig: ProxyConfiguration? = null
    private val json = Json { ignoreUnknownKeys = true }

    // Tracks the most recent underlying (non-VPN) network so we can detect
    // path changes (e.g. Wi-Fi → Cellular) and restart the lwIP stack to
    // replace stale connections bound to the old interface.
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastUnderlyingNetwork: Network? = null
    private var lastUnderlyingTransports: Int = 0
    private var lastNetworkAvailable: Boolean = false

    // Screen on/off used to approximate device-level sleep — Android doesn't
    // expose sleep/wake callbacks on a foreground VpnService directly, so we
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
                currentConfig = config
                DnsCache.setActiveProxyDomain(config.serverAddress)
                lwipStack?.switchConfiguration(config)
                updateNotification(config.name)
            }
            null -> {
                // No-op: Always On VPN is not implemented on Android, so we
                // don't expect the system to auto-start the service. Stop
                // immediately if we get here unexpectedly (e.g. system tried
                // to restart a killed STICKY service — shouldn't happen since
                // we return START_NOT_STICKY).
                logger.debug("[VPN] Service started without action; stopping")
                stopSelf()
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
        // prefs. The VPN service shares the app process on Android so VpnViewModel
        // would normally have already populated this cache, but a fresh process
        // (system-killed app + user-tapped reconnect) can race the first handshake.
        CertificatePolicy.reload(this)

        val effectiveConfig = applyGlobalAllowInsecure(config)
        logger.debug("[VPN] Starting tunnel to ${effectiveConfig.serverAddress}:${effectiveConfig.serverPort} " +
                "(connect: ${effectiveConfig.connectAddress}), security: ${effectiveConfig.security}, transport: ${effectiveConfig.transport}")

        currentConfig = effectiveConfig
        DnsCache.setActiveProxyDomain(effectiveConfig.serverAddress)

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

        // Start lwIP stack. The single `ipv6DNSEnabled` knob controls both IPv6
        // routes and AAAA fake-IP resolution.
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val ipv6Dns = prefs.getBoolean("ipv6DnsEnabled", false)

        // Register socket protector so protocol code can protect outbound sockets
        SocketProtector.setProtector(
            fdFn = ::protectSocket,
            socketFn = { protect(it) },
            datagramFn = { protect(it) }
        )

        // Set the underlying physical network for DnsCache so DNS resolution
        // bypasses the VPN tunnel.
        findUnderlyingNetwork()?.let { DnsCache.setUnderlyingNetwork(it) }

        val stack = LwipStack(this)
        lwipStack = stack

        // Wire logger sink so logger.info/.warning/.error forward to the
        // user-facing log buffer.
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

        // Observe screen off/on as a proxy for device-level sleep so we can
        // proactively restart connections after long periods of inactivity
        // (NAT rebinds, server-side idle sweeps).
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
            // packet reader thread.
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

    // Bypass routes — IP ranges excluded from VPN tunnel (sent directly)
    private data class BypassRoute(val address: String, val prefixLength: Int)

    private fun buildTunInterface(config: ProxyConfiguration): ParcelFileDescriptor? {
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        // When enabled we add IPv6 address/routes/DNS.
        val ipv6Enabled = prefs.getBoolean("ipv6DnsEnabled", false)
        val remoteAddress = config.connectAddress

        val builder = Builder()
            // TUN IP
            .addAddress("10.8.0.2", 24)
            // DNS servers
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            // MTU
            .setMtu(1500)
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
        // going through the VPN tunnel.
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
     * This allows DnsCache to resolve proxy server domains through the physical interface.
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

    /**
     * Begins observing the system's underlying (non-VPN) network so we can
     * detect interface switches (Wi-Fi ↔ Cellular) and trigger a stack restart.
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
     * Listens for screen on/off as a proxy for device-level sleep. Long sleeps
     * (≥ [WAKE_RESTART_THRESHOLD_SECS]) trigger a stack restart on resume to
     * defeat carrier NAT rebinds and server-side idle sweeps after the device
     * has been off for a while.
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
                                "[VPN] Long sleep detected (${sleepSecs}s); invalidating outbound state"
                            )
                            // Targeted abort of outbound proxy state instead of a
                            // full stack rebuild. The lwIP netif, listeners, FakeIP
                            // pool, and routing all survive sleep — only the
                            // kernel-killed outbound sockets need invalidating.
                            lwipStack?.handleWake()
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
     * requires restarting the lwIP stack. Compares the current snapshot to the
     * previous one and triggers a restart only when the underlying interface
     * (or its transport set) actually changed, or when connectivity is restored
     * after being lost.
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
        // physical interface.
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

        /** Wake-from-sleep restart threshold. */
        private val WAKE_RESTART_THRESHOLD_SECS: Long = TunnelConstants.wakeRestartThresholdSec

        // Private/local IPv4 ranges excluded from the VPN tunnel.
        private val BYPASS_IPV4_ROUTES = listOf(
            BypassRoute("127.0.0.0", 8),      // loopback
            BypassRoute("10.0.0.0", 8),        // private
            BypassRoute("172.16.0.0", 12),     // private
            BypassRoute("192.168.0.0", 16),    // private
            BypassRoute("100.64.0.0", 10),     // CGNAT
            BypassRoute("162.14.0.0", 16),
            BypassRoute("211.99.96.0", 19),
            BypassRoute("162.159.192.0", 24),  // Cloudflare
            BypassRoute("162.159.193.0", 24),  // Cloudflare
            BypassRoute("162.159.195.0", 24),  // Cloudflare
        )

        private val BYPASS_IPV6_ROUTES = listOf(
            BypassRoute("fc00::", 7),   // unique-local
            BypassRoute("fe80::", 10),  // link-local
        )

        /**
         * Split routes covering 0.0.0.0/0 minus [BYPASS_IPV4_ROUTES], computed once
         * at class load. Android lacks `VpnService.Builder.addExcludedRoute()` below
         * API 33, so we feed `addRoute()` the explicit complement instead.
         *
         * Computed dynamically so adding entries to [BYPASS_IPV4_ROUTES] (e.g. the
         * Cloudflare and China Telecom ranges) automatically adjusts the routed
         * set without manually re-deriving the CIDRs.
         *
         * Note: 240.0.0.0/4 (reserved) and 224.0.0.0/4 (multicast) are intentionally
         * left out of [BYPASS_IPV4_ROUTES] but also not routed through the VPN —
         * they fall outside the public range we explicitly include below.
         */
        private val PUBLIC_IPV4_ROUTES: List<BypassRoute> by lazy {
            computeIPv4SplitRoutes(BYPASS_IPV4_ROUTES)
        }

        /**
         * Returns CIDR routes covering 0.0.0.0/0 with the given bypass routes
         * removed. Uses a longest-aligned-prefix decomposition: for each gap
         * between bypass ranges, emit the largest /N block aligned to the
         * current cursor that fits, then advance.
         */
        private fun computeIPv4SplitRoutes(bypass: List<BypassRoute>): List<BypassRoute> {
            // Sort bypass ranges by start address and merge overlaps.
            val ranges = bypass.map { it.toIpv4Range() }.sortedBy { it.first }
            val merged = mutableListOf<LongRange>()
            for (r in ranges) {
                val last = merged.lastOrNull()
                if (last != null && r.first <= last.last + 1) {
                    merged[merged.size - 1] = last.first..maxOf(last.last, r.last)
                } else {
                    merged.add(r)
                }
            }

            val routes = mutableListOf<BypassRoute>()
            var cursor = 0L
            // Stop one above the public unicast range — multicast (224/4) and
            // reserved (240/4) should not be routed through the tunnel.
            val publicEnd = 0xE0000000L  // 224.0.0.0
            for (r in merged) {
                if (r.first >= publicEnd) break
                if (r.first > cursor) {
                    appendIpv4CidrRange(cursor, r.first - 1, routes)
                }
                cursor = r.last + 1
            }
            if (cursor < publicEnd) {
                appendIpv4CidrRange(cursor, publicEnd - 1, routes)
            }
            return routes
        }

        private fun BypassRoute.toIpv4Range(): LongRange {
            val ip = ipv4ToLong(address)
            val size = 1L shl (32 - prefixLength)
            return ip until (ip + size)
        }

        private fun ipv4ToLong(addr: String): Long {
            val parts = addr.split(".").map { it.toLong() }
            require(parts.size == 4) { "Invalid IPv4: $addr" }
            return (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
        }

        private fun longToIpv4(ip: Long): String =
            "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

        private fun appendIpv4CidrRange(
            startInclusive: Long,
            endInclusive: Long,
            out: MutableList<BypassRoute>
        ) {
            var s = startInclusive
            while (s <= endInclusive) {
                // Largest k such that s is 2^k-aligned and s + 2^k - 1 <= endInclusive.
                var k = 32
                while (k > 0) {
                    val size = 1L shl k
                    if ((s and (size - 1)) == 0L && s + size - 1 <= endInclusive) break
                    k--
                }
                out.add(BypassRoute(longToIpv4(s), 32 - k))
                s += if (k == 0) 1L else (1L shl k)
            }
        }
    }
}
