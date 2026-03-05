package com.argsment.anywhere.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.content.pm.ServiceInfo
import android.os.ParcelFileDescriptor
import android.util.Log
import com.argsment.anywhere.MainActivity
import com.argsment.anywhere.data.model.VlessConfiguration
import kotlinx.serialization.json.Json

/**
 * Android VPN service that creates a TUN interface, runs the lwIP TCP/IP stack,
 * and routes traffic through VLESS proxy connections.
 *
 * Equivalent of a platform packet tunnel provider.
 */
class AnywhereVpnService : VpnService() {

    private var lwipStack: LwipStack? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var currentConfig: VlessConfiguration? = null
    private val json = Json { ignoreUnknownKeys = true }

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
                    Log.e(TAG, "[VPN] Missing configuration in start intent")
                    stopSelf()
                    return START_NOT_STICKY
                }

                val config = runCatching {
                    json.decodeFromString(VlessConfiguration.serializer(), configJson)
                }.getOrNull()

                if (config == null) {
                    Log.e(TAG, "[VPN] Invalid configuration JSON")
                    stopSelf()
                    return START_NOT_STICKY
                }

                startVpn(config)
            }
            ACTION_STOP -> stopVpn()
            ACTION_SWITCH_CONFIG -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                val config = runCatching {
                    json.decodeFromString(VlessConfiguration.serializer(), configJson)
                }.getOrNull() ?: return START_NOT_STICKY
                currentConfig = config
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
        Log.i(TAG, "[VPN] Permission revoked, stopping")
        stopVpn()
    }

    // =========================================================================
    // VPN Setup
    // =========================================================================

    private fun startVpn(config: VlessConfiguration) {
        Log.i(TAG, "[VPN] Starting tunnel to ${config.serverAddress}:${config.serverPort} " +
                "(connect: ${config.connectAddress}), security: ${config.security}, transport: ${config.transport}")

        currentConfig = config

        // Create foreground notification
        startForeground(NOTIFICATION_ID, buildNotification(config.name),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)

        // Build and establish TUN interface
        val fd = buildTunInterface(config) ?: run {
            Log.e(TAG, "[VPN] Failed to establish TUN interface")
            stopSelf()
            return
        }
        tunFd = fd

        // Start lwIP stack
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val ipv6Enabled = prefs.getBoolean("ipv6Enabled", false)

        // Register socket protector so protocol code can protect outbound sockets
        SocketProtector.setProtector(
            fdFn = ::protectSocket,
            socketFn = { protect(it) },
            datagramFn = { protect(it) }
        )

        val stack = LwipStack(this)
        lwipStack = stack

        stack.onTunnelSettingsNeedReapply = {
            reapplyTunnelSettings(config)
        }

        stack.start(fd, config, ipv6Enabled)
    }

    private fun stopVpn() {
        SocketProtector.clearProtector()

        lwipStack?.stop()
        lwipStack = null

        tunFd?.close()
        tunFd = null

        currentConfig = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** Handles system auto-start when Always On VPN is enabled. */
    private fun handleAlwaysOnStart() {
        // Load last used config from SharedPreferences
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val configId = prefs.getString("selectedConfigurationId", null)
        if (configId == null) {
            Log.w(TAG, "[VPN] Always On: no saved configuration")
            stopSelf()
            return
        }

        // Try to load saved config from file
        val configFile = filesDir.resolve("configurations.json")
        if (!configFile.exists()) {
            Log.w(TAG, "[VPN] Always On: no configurations file")
            stopSelf()
            return
        }

        val configs = runCatching {
            val text = configFile.readText()
            json.decodeFromString<List<VlessConfiguration>>(text)
        }.getOrNull()

        val config = configs?.find { it.id.toString() == configId }
        if (config == null) {
            Log.w(TAG, "[VPN] Always On: selected config not found")
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

    private fun buildTunInterface(config: VlessConfiguration): ParcelFileDescriptor? {
        val prefs = getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
        val ipv6Enabled = prefs.getBoolean("ipv6Enabled", false)
        val remoteAddress = config.connectAddress

        val builder = Builder()
            // TUN IP
            .addAddress("10.8.0.2", 24)
            // Default route: all traffic
            .addRoute("0.0.0.0", 0)
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

        // On Android, bypass is achieved by:
        // 1. Route 0.0.0.0/0 captures all traffic into TUN
        // 2. Protecting outbound proxy sockets via VpnService.protect()
        // Private-range bypass routes are not needed because our protocol sockets
        // are protected and lwIP + domain routing handles bypass decisions internally.
        // The server IP does NOT need a special route — protect() on the proxy
        // socket prevents the routing loop.

        // Session name for system UI
        builder.setSession("Anywhere VPN")

        return try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "[VPN] Failed to establish: $e")
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
    private fun reapplyTunnelSettings(config: VlessConfiguration) {
        val newFd = buildTunInterface(config)
        if (newFd != null) {
            val oldFd = tunFd
            tunFd = newFd
            // Swap the TUN fd in the stack — restartStack will handle the lwIP restart
            lwipStack?.swapTunFd(newFd)
            oldFd?.close()
            Log.i(TAG, "[VPN] Tunnel settings reapplied (fd swapped)")
        } else {
            Log.e(TAG, "[VPN] Failed to reapply tunnel settings")
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

    /** Returns whether the VPN is currently running. */
    val isRunning: Boolean get() = lwipStack != null

    companion object {
        private const val TAG = "AnywhereVPN"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.argsment.anywhere.START"
        const val ACTION_STOP = "com.argsment.anywhere.STOP"
        const val ACTION_SWITCH_CONFIG = "com.argsment.anywhere.SWITCH_CONFIG"
        const val EXTRA_CONFIG = "config"

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
    }
}
