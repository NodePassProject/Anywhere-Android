package com.argsment.anywhere.vpn

import android.content.Context
import android.content.SharedPreferences
import android.os.ParcelFileDescriptor
import android.util.Log
import com.argsment.anywhere.data.model.ProxyConfiguration
import java.io.FileInputStream
import java.io.FileOutputStream
import com.argsment.anywhere.vpn.protocol.mux.MuxManager
import kotlinx.coroutines.asCoroutineDispatcher
import org.json.JSONArray
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Main coordinator for the lwIP TCP/IP stack on Android.
 *
 * All lwIP calls run on a single-threaded [lwipExecutor] (lwIP is not thread-safe).
 * One instance per VPN service, accessible via [instance].
 *
 * Reads IP packets from the TUN file descriptor, feeds them into lwIP for TCP/UDP
 * reassembly, and dispatches resulting connections through VLESS proxy clients.
 * Response data is written back to the TUN fd.
 */
class LwipStack(private val context: Context) : NativeBridge.LwipCallback {

    // -- Threading --

    /** Single-threaded executor for all lwIP operations (lwIP is not thread-safe).
     *  DiscardPolicy silently drops tasks submitted after shutdown(), preventing
     *  RejectedExecutionException from in-flight coroutines that resume during teardown. */
    val lwipExecutor: ScheduledExecutorService = ScheduledThreadPoolExecutor(1) { r ->
        Thread(r, "lwip-thread").apply { isDaemon = true }
    }.apply {
        rejectedExecutionHandler = ThreadPoolExecutor.DiscardPolicy()
    }

    /** Pool of reusable MTU-sized byte arrays to avoid per-packet allocation in the TUN reader. */
    private val packetPool = ConcurrentLinkedQueue<ByteArray>()

    // -- State --

    private var tunFd: ParcelFileDescriptor? = null
    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null
    var configuration: ProxyConfiguration? = null
        private set

    // Settings (read from SharedPreferences)
    var ipv6ConnectionsEnabled: Boolean = false
        private set
    var ipv6DNSEnabled: Boolean = false
        private set
    var encryptedDnsEnabled: Boolean = false
        private set
    var encryptedDnsProtocol: String = "doh"
        private set
    var encryptedDnsServer: String = ""
        private set
    private var running = false
    @Volatile
    private var tunFdSwapped = false

    // Timers
    private var timeoutTimer: ScheduledFuture<*>? = null
    private var udpCleanupTimer: ScheduledFuture<*>? = null

    /** GeoIP database for country-based bypass (loaded once, reused). */
    private var geoIpDatabase: GeoIpDatabase? = null

    /** Packed country code to bypass (0 = disabled). */
    var bypassCountry: Int = 0
        private set

    /** Global traffic counters. */
    val totalBytesIn = AtomicLong(0)
    val totalBytesOut = AtomicLong(0)

    /** All proxy server addresses (domains and resolved IPs) from all configurations.
     *  Prevents routing loops when proxy server domains match routing rules. */
    private var proxyServerAddresses: Set<String> = emptySet()

    /** Mux manager for multiplexing UDP flows (created when Vision+Mux is active). */
    var muxManager: MuxManager? = null

    /** Active UDP flows keyed by 5-tuple string. */
    val udpFlows = ConcurrentHashMap<String, LwipUdpFlow>()

    /** Active TCP connections keyed by connection ID. */
    private val tcpConnections = ConcurrentHashMap<Long, LwipTcpConnection>()
    private val nextConnId = AtomicLong(1)

    /** Domain-based DNS routing. */
    val domainRouter = DomainRouter(context)

    /** Fake-IP pool for mapping domains to synthetic IPs. */
    val fakeIpPool = FakeIpPool()

    /** SharedPreferences for settings. */
    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences("anywhere_settings", Context.MODE_PRIVATE)
    }

    /** Callback to request VPN tunnel settings reapply (e.g. for IPv6 toggle). */
    var onTunnelSettingsNeedReapply: (() -> Unit)? = null

    private sealed class FakeIpResolution {
        data object Passthrough : FakeIpResolution()
        data class Resolved(
            val domain: String,
            val configurationOverride: ProxyConfiguration?,
            val forceBypass: Boolean
        ) : FakeIpResolution()
        data object Drop : FakeIpResolution()
        data object Unreachable : FakeIpResolution()
    }

    // -- Settings observation --
    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        when (key) {
            "ipv6ConnectionsEnabled",
            "ipv6DnsEnabled",
            "bypassCountryCode",
            "encryptedDnsEnabled",
            "encryptedDnsProtocol",
            "encryptedDnsServer" -> handleSettingsChanged()
            "routingChanged" -> handleRoutingChanged()
        }
    }

    // -- GeoIP Bypass --

    /** Returns true if traffic to the given host should bypass the tunnel.
     *  Checks proxy server addresses first (prevents routing loops after config switch),
     *  then falls back to GeoIP country-based bypass. */
    fun shouldBypass(host: String): Boolean {
        if (isProxyServerAddress(host)) return true
        if (bypassCountry == 0) return false
        return geoIpDatabase?.lookup(host) == bypassCountry
    }

    /** Returns true if the given host matches any proxy server address across all
     *  configurations. Prevents routing loops and ensures latency tests bypass the tunnel. */
    private fun isProxyServerAddress(host: String): Boolean {
        // Fast path: direct set lookup (covers domains and resolved IPs)
        if (proxyServerAddresses.contains(host)) return true
        // Fallback: check active config in case proxyServerAddresses hasn't been populated yet
        val config = configuration ?: return false
        if (host == config.serverAddress || host == config.resolvedIP) return true
        val chain = config.chain
        if (chain != null) {
            for (proxy in chain) {
                if (host == proxy.serverAddress || host == proxy.resolvedIP) return true
            }
        }
        return false
    }

    /** Updates the set of proxy server addresses from the app.
     *  The app persists domains plus any already-resolved IPs, so the VPN process
     *  can restore them without triggering fresh DNS lookups inside the tunnel. */
    fun updateProxyServerAddresses(addresses: List<String>) {
        lwipExecutor.execute {
            proxyServerAddresses = normalizeProxyServerAddresses(addresses)
        }
    }

    private fun loadProxyServerAddresses() {
        val stored = prefs.getString("proxyServerAddresses", null) ?: return
        val parsed = runCatching {
            val array = JSONArray(stored)
            buildList(array.length()) {
                for (index in 0 until array.length()) {
                    val value = array.optString(index, "")
                    if (value.isNotBlank()) add(value)
                }
            }
        }.getOrElse {
            Log.w(TAG, "[LwipStack] Failed to parse proxyServerAddresses: $it")
            emptyList()
        }
        proxyServerAddresses = normalizeProxyServerAddresses(parsed)
    }

    private fun seedProxyServerAddresses(config: ProxyConfiguration) {
        val addresses = collectProxyServerAddresses(config)
        proxyServerAddresses = proxyServerAddresses + addresses
        // Resolve domain names in background to catch DNS-resolved IPs (matching iOS)
        resolveProxyDomains(addresses)
    }

    /**
     * Resolves proxy server domain names in background and adds resolved IPs.
     * Matching iOS resolveProxyDomains() behavior.
     */
    private fun resolveProxyDomains(addresses: Set<String>) {
        Thread {
            for (address in addresses) {
                // Skip if already an IP address
                if (address.contains(':') || address.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))) continue
                try {
                    val resolved = java.net.InetAddress.getAllByName(address)
                    val ips = resolved.mapNotNull { it.hostAddress }.toSet()
                    if (ips.isNotEmpty()) {
                        lwipExecutor.execute {
                            proxyServerAddresses = proxyServerAddresses + ips
                        }
                    }
                } catch (_: Exception) {
                    // DNS resolution failure is not fatal
                }
            }
        }.start()
    }

    private fun collectProxyServerAddresses(config: ProxyConfiguration): Set<String> {
        val addresses = linkedSetOf<String>()
        addresses.add(config.serverAddress)
        config.resolvedIP?.let(addresses::add)
        config.chain?.forEach { hop ->
            addresses.addAll(collectProxyServerAddresses(hop))
        }
        return addresses
    }

    private fun normalizeProxyServerAddresses(addresses: Collection<String>): Set<String> {
        return addresses.asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toCollection(linkedSetOf())
    }

    private fun loadBypassCountry() {
        val code = prefs.getString("bypassCountryCode", "") ?: ""
        bypassCountry = if (code.isEmpty()) 0 else GeoIpDatabase.packCountryCode(code)
        if (bypassCountry != 0) {
            Log.i(TAG, "[LwipStack] Bypass country: $code")
        }
    }

    private fun loadEncryptedDnsSettings() {
        encryptedDnsEnabled = prefs.getBoolean("encryptedDnsEnabled", false)
        encryptedDnsProtocol = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
        encryptedDnsServer = prefs.getString("encryptedDnsServer", "") ?: ""
    }

    // -- Lifecycle --

    /**
     * Starts the lwIP stack and begins reading packets from the TUN.
     *
     * @param fd          The TUN file descriptor from VpnService.establish()
     * @param config      The VLESS proxy configuration
     * @param ipv6        Whether IPv6 is enabled
     */
    fun start(fd: ParcelFileDescriptor, config: ProxyConfiguration, ipv6Connections: Boolean = false, ipv6Dns: Boolean = false) {
        Log.i(TAG, "[LwipStack] Starting, ipv6Connections=$ipv6Connections, ipv6Dns=$ipv6Dns")
        instance = this
        this.tunFd = fd
        this.tunInput = FileInputStream(fd.fileDescriptor)
        this.tunOutput = FileOutputStream(fd.fileDescriptor)
        this.configuration = config
        this.ipv6ConnectionsEnabled = ipv6Connections
        this.ipv6DNSEnabled = ipv6Dns

        // Register as lwIP callback handler
        NativeBridge.callback = this

        lwipExecutor.execute {
            running = true
            totalBytesIn.set(0)
            totalBytesOut.set(0)

            // Load GeoIP database once
            if (geoIpDatabase == null) {
                geoIpDatabase = GeoIpDatabase.load(context)
            }
            loadBypassCountry()
            loadEncryptedDnsSettings()

            // Create MuxManager when Vision+Mux is active (VLESS only, matching iOS)
            if (config.outboundProtocol == com.argsment.anywhere.data.model.OutboundProtocol.VLESS && config.muxEnabled && (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")) {
                muxManager = MuxManager(config, lwipExecutor.asCoroutineDispatcher())
            }

            loadProxyServerAddresses()
            seedProxyServerAddresses(config)
            domainRouter.loadRoutingConfiguration()
            domainRouter.loadBypassCountryRules()
            NativeBridge.nativeInit()
            startTimeoutTimer()
            startUdpCleanupTimer()
            startReadingPackets()
            Log.i(TAG, "[LwipStack] Started, mux=${muxManager != null}, bypass=${bypassCountry != 0}, encryptedDns=$encryptedDnsEnabled, ipv6conn=$ipv6ConnectionsEnabled, ipv6dns=$ipv6DNSEnabled")
        }

        startObservingSettings()
    }

    /** Stops the lwIP stack and closes all active flows. */
    fun stop() {
        Log.i(TAG, "[LwipStack] Stopping")
        stopObservingSettings()

        // All state clearing happens on the lwipExecutor to avoid races with
        // in-flight callbacks (e.g., onOutput() reading tunOutput).
        val latch = java.util.concurrent.CountDownLatch(1)
        lwipExecutor.execute {
            running = false
            shutdownInternal()
            fakeIpPool.reset()
            NativeBridge.callback = null
            tunInput = null
            tunOutput = null
            tunFd = null
            configuration = null
            instance = null
            latch.countDown()
        }

        // Wait for shutdown to complete, then release the executor thread
        try {
            latch.await(5, TimeUnit.SECONDS)
        } catch (_: Exception) {}
        lwipExecutor.shutdown()
    }

    /** Switches to a new configuration, tearing down all active connections. */
    fun switchConfiguration(newConfig: ProxyConfiguration) {
        Log.i(TAG, "[LwipStack] Switching configuration")
        lwipExecutor.execute {
            restartStack(newConfig, ipv6ConnectionsEnabled, ipv6DNSEnabled)
        }
    }

    /**
     * Swaps the TUN file descriptor (called from VpnService when tunnel settings
     * are reapplied, e.g. IPv6 toggle). Updates the input/output streams so the
     * next read loop uses the new fd. The old read thread will die naturally when
     * the old fd is closed by the caller.
     *
     * Must be called before [restartStack] so the flag is set.
     */
    fun swapTunFd(newFd: ParcelFileDescriptor) {
        this.tunFd = newFd
        this.tunInput = FileInputStream(newFd.fileDescriptor)
        this.tunOutput = FileOutputStream(newFd.fileDescriptor)
        tunFdSwapped = true
    }

    /**
     * Shuts down the lwIP stack and all active flows. Must be called on lwipExecutor.
     * Does NOT change [running] — callers manage it.
     */
    private fun shutdownInternal() {
        totalBytesIn.set(0)
        totalBytesOut.set(0)

        timeoutTimer?.cancel(false)
        timeoutTimer = null
        udpCleanupTimer?.cancel(false)
        udpCleanupTimer = null

        muxManager?.closeAll()
        muxManager = null

        val flowCount = udpFlows.size
        for (flow in udpFlows.values) {
            flow.close()
        }
        udpFlows.clear()

        for (conn in tcpConnections.values) {
            if (!conn.closed) {
                conn.close()
            }
        }
        tcpConnections.clear()

        NativeBridge.nativeShutdown()
        Log.i(TAG, "[LwipStack] Shutdown complete, closed $flowCount UDP flows")
    }

    /** Tears down and restarts the lwIP stack. Must be called on lwipExecutor. */
    private fun restartStack(config: ProxyConfiguration, ipv6Connections: Boolean, ipv6Dns: Boolean) {
        shutdownInternal()

        this.configuration = config
        this.ipv6ConnectionsEnabled = ipv6Connections
        this.ipv6DNSEnabled = ipv6Dns
        loadBypassCountry()
        loadEncryptedDnsSettings()

        if (config.muxEnabled && (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")) {
            muxManager = MuxManager(config, lwipExecutor.asCoroutineDispatcher())
        }

        loadProxyServerAddresses()
        seedProxyServerAddresses(config)
        domainRouter.loadRoutingConfiguration()
        domainRouter.loadBypassCountryRules()
        NativeBridge.nativeInit()
        startTimeoutTimer()
        startUdpCleanupTimer()
        // Start new read loop if TUN fd was swapped (old loop died with old fd).
        // Otherwise existing read loop continues uninterrupted.
        if (tunFdSwapped) {
            tunFdSwapped = false
            startReadingPackets()
        }
        Log.i(TAG, "[LwipStack] Restarted, mux=${muxManager != null}, bypass=${bypassCountry != 0}, encryptedDns=$encryptedDnsEnabled, ipv6conn=$ipv6ConnectionsEnabled, ipv6dns=$ipv6DNSEnabled")
    }

    // -- Settings Observation --

    private fun startObservingSettings() {
        prefs.registerOnSharedPreferenceChangeListener(prefsListener)
    }

    private fun stopObservingSettings() {
        prefs.unregisterOnSharedPreferenceChangeListener(prefsListener)
    }

    private fun handleSettingsChanged() {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute

            val newIpv6Connections = prefs.getBoolean("ipv6ConnectionsEnabled", false)
            val newIpv6Dns = prefs.getBoolean("ipv6DnsEnabled", false)
            val newBypassCode = prefs.getString("bypassCountryCode", "") ?: ""
            val newBypass = if (newBypassCode.isEmpty()) 0 else GeoIpDatabase.packCountryCode(newBypassCode)
            val newEncryptedDnsEnabled = prefs.getBoolean("encryptedDnsEnabled", false)
            val newEncryptedDnsProtocol = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
            val newEncryptedDnsServer = prefs.getString("encryptedDnsServer", "") ?: ""

            val ipv6ConnectionsChanged = newIpv6Connections != ipv6ConnectionsEnabled
            val ipv6DnsChanged = newIpv6Dns != ipv6DNSEnabled
            val bypassChanged = newBypass != bypassCountry
            val encryptedDnsEnabledChanged = newEncryptedDnsEnabled != encryptedDnsEnabled
            val encryptedDnsProtocolChanged = newEncryptedDnsProtocol != encryptedDnsProtocol
            val encryptedDnsServerChanged = newEncryptedDnsServer != encryptedDnsServer

            if (!ipv6ConnectionsChanged &&
                !ipv6DnsChanged &&
                !bypassChanged &&
                !encryptedDnsEnabledChanged &&
                !encryptedDnsProtocolChanged &&
                !encryptedDnsServerChanged
            ) return@execute

            if (ipv6ConnectionsChanged ||
                encryptedDnsEnabledChanged ||
                encryptedDnsProtocolChanged ||
                encryptedDnsServerChanged
            ) {
                onTunnelSettingsNeedReapply?.invoke()
            }

            Log.i(TAG, "[LwipStack] Settings changed, restarting (bypass=${newBypass != 0}, ipv6conn=$newIpv6Connections, ipv6dns=$newIpv6Dns, encryptedDns=$newEncryptedDnsEnabled)")
            restartStack(config, newIpv6Connections, newIpv6Dns)
        }
    }

    private fun handleRoutingChanged() {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute
            Log.i(TAG, "[LwipStack] Routing rules changed, restarting")
            restartStack(config, ipv6ConnectionsEnabled, ipv6DNSEnabled)
        }
    }

    // -- NativeBridge.LwipCallback Implementation --

    override fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean) {
        totalBytesIn.addAndGet(length.toLong())
        // Write synchronously — TUN writes are fast kernel buffer copies.
        try {
            tunOutput?.write(packet, 0, length)
        } catch (e: Exception) {
            Log.e(TAG, "[LwipStack] TUN write error: $e")
        }
    }

    override fun onTcpAccept(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean, pcb: Long
    ): Long {
        val defaultConfig = configuration ?: run {
            Log.e(TAG, "[LwipStack] tcp_accept: no configuration")
            return 0L
        }

        if (isIpv6 && !ipv6ConnectionsEnabled) {
            return 0L
        }

        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"
        var dstHost = dstIpString
        var connectionConfig = defaultConfig
        var forceBypass = false

        when (val resolution = resolveFakeIp(dstIpString, dstPort, "TCP")) {
            FakeIpResolution.Passthrough -> {
                domainRouter.matchIP(dstIpString)?.let { action ->
                    when (action) {
                        RouteAction.Direct -> forceBypass = true
                        RouteAction.Reject -> return 0L
                        is RouteAction.Proxy -> {
                            val resolved = domainRouter.resolveConfiguration(action)
                            if (resolved != null) {
                                connectionConfig = inheritChain(defaultConfig, resolved)
                            } else {
                                Log.w(TAG, "[LwipStack] TCP proxy config ${action.configId} not found for IP $dstIpString")
                            }
                        }
                    }
                }
            }
            is FakeIpResolution.Resolved -> {
                dstHost = resolution.domain
                forceBypass = resolution.forceBypass
                connectionConfig = resolution.configurationOverride?.let {
                    inheritChain(defaultConfig, it)
                } ?: defaultConfig
            }
            FakeIpResolution.Drop, FakeIpResolution.Unreachable -> return 0L
        }

        val connId = nextConnId.getAndIncrement()
        val connection = LwipTcpConnection(
            connId = connId,
            pcb = pcb,
            dstHost = dstHost,
            dstPort = dstPort,
            configuration = connectionConfig,
            forceBypass = forceBypass,
            lwipExecutor = lwipExecutor
        )
        tcpConnections[connId] = connection
        return connId
    }

    override fun onTcpRecv(connId: Long, data: ByteArray?) {
        val connection = tcpConnections[connId] ?: run {
            Log.e(TAG, "[LwipStack] tcp_recv: connection $connId not found")
            return
        }
        if (data != null && data.isNotEmpty()) {
            connection.handleReceivedData(data)
        } else {
            connection.handleRemoteClose()
        }
    }

    override fun onTcpSent(connId: Long, length: Int) {
        val connection = tcpConnections[connId] ?: return
        connection.handleSent(length)
    }

    override fun onTcpErr(connId: Long, err: Int) {
        val connection = tcpConnections.remove(connId) ?: run {
            Log.e(TAG, "[LwipStack] tcp_err: connection $connId not found, err=$err")
            return
        }
        connection.handleError(err)
    }

    override fun onUdpRecv(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean, data: ByteArray
    ) {
        if (isIpv6 && !ipv6ConnectionsEnabled) {
            return
        }

        // DNS interception: intercept port-53 queries for matched domains
        if (dstPort == 53) {
            if (handleDnsQuery(data, srcIp, srcPort, dstIp, dstPort, isIpv6)) {
                return  // Fake response sent, no flow needed
            }
            // No rule match — fall through, create normal UDP flow to proxy DNS
        }

        val srcHost = NativeBridge.nativeIpToString(srcIp, isIpv6) ?: "?"
        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"

        // Fake-IP lookup for non-DNS packets
        var dstHost = dstIpString
        val defaultConfig = configuration ?: return
        var flowConfig = defaultConfig
        var forceBypass = false

        when (val resolution = resolveFakeIp(dstIpString, dstPort, "UDP")) {
            FakeIpResolution.Passthrough -> {
                domainRouter.matchIP(dstIpString)?.let { action ->
                    when (action) {
                        RouteAction.Direct -> forceBypass = true
                        RouteAction.Reject -> {
                            sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
                            return
                        }
                        is RouteAction.Proxy -> {
                            val resolved = domainRouter.resolveConfiguration(action)
                            if (resolved != null) {
                                flowConfig = inheritChain(defaultConfig, resolved)
                            } else {
                                Log.w(TAG, "[LwipStack] UDP proxy config ${action.configId} not found for IP $dstIpString")
                            }
                        }
                    }
                }
            }
            is FakeIpResolution.Resolved -> {
                dstHost = resolution.domain
                forceBypass = resolution.forceBypass
                flowConfig = resolution.configurationOverride?.let {
                    inheritChain(defaultConfig, it)
                } ?: defaultConfig
            }
            FakeIpResolution.Drop -> {
                sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
                return
            }
            FakeIpResolution.Unreachable -> {
                Log.d(TAG, "[FakeIP] UDP to $dstIpString:$dstPort — stale DNS cache (no pool entry)")
                sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
                return
            }
        }

        // flowKey uses dstIpString (not domain) for consistency with lwIP packet delivery
        val flowKey = "$srcHost:$srcPort-$dstIpString:$dstPort"

        udpFlows[flowKey]?.let { flow ->
            flow.handleReceivedData(data, data.size)
            return
        }

        if (udpFlows.size >= MAX_UDP_FLOWS) {
            // Evict the oldest idle flow instead of dropping the new one.
            // Prefer evicting DNS flows (port 53) since they're one-shot.
            var oldestKey: String? = null
            var oldestTime = Double.MAX_VALUE
            var oldestDnsKey: String? = null
            var oldestDnsTime = Double.MAX_VALUE
            for ((key, flow) in udpFlows) {
                if (flow.lastActivity < oldestTime) {
                    oldestTime = flow.lastActivity
                    oldestKey = key
                }
                if (flow.dstPort == 53 && flow.lastActivity < oldestDnsTime) {
                    oldestDnsTime = flow.lastActivity
                    oldestDnsKey = key
                }
            }
            val evictKey = oldestDnsKey ?: oldestKey
            if (evictKey != null) {
                udpFlows.remove(evictKey)?.close()
            } else {
                Log.e(TAG, "[LwipStack] UDP max flows reached ($MAX_UDP_FLOWS), dropping $flowKey")
                return
            }
        }

        val flow = LwipUdpFlow(
            flowKey = flowKey,
            srcHost = srcHost, srcPort = srcPort,
            dstHost = dstHost, dstPort = dstPort,
            srcIpBytes = srcIp.copyOf(),
            dstIpBytes = dstIp.copyOf(),
            isIpv6 = isIpv6,
            configuration = flowConfig,
            forceBypass = forceBypass,
            lwipExecutor = lwipExecutor
        )
        udpFlows[flowKey] = flow
        flow.handleReceivedData(data, data.size)
    }

    private fun resolveFakeIp(ip: String, dstPort: Int, proto: String): FakeIpResolution {
        if (!FakeIpPool.isFakeIp(ip)) return FakeIpResolution.Passthrough

        val entry = fakeIpPool.lookup(ip) ?: return FakeIpResolution.Unreachable
        val match = domainRouter.matchDomain(entry.domain)

        return when (val action = match.userAction) {
            RouteAction.Direct -> FakeIpResolution.Resolved(entry.domain, null, true)
            RouteAction.Reject -> {
                Log.d(TAG, "[FakeIP] $proto to ${entry.domain}:$dstPort — REJECT")
                FakeIpResolution.Drop
            }
            is RouteAction.Proxy -> {
                val resolved = domainRouter.resolveConfiguration(action)
                if (resolved == null) {
                    Log.w(TAG, "[FakeIP] $proto proxy config ${action.configId} not found for ${entry.domain}")
                }
                FakeIpResolution.Resolved(entry.domain, resolved, false)
            }
            null -> {
                if (bypassCountry != 0 && match.isBypass) {
                    FakeIpResolution.Resolved(entry.domain, null, true)
                } else {
                    FakeIpResolution.Resolved(entry.domain, null, false)
                }
            }
        }
    }

    private fun inheritChain(
        defaultConfig: ProxyConfiguration,
        overrideConfig: ProxyConfiguration
    ): ProxyConfiguration {
        val chain = defaultConfig.chain
        return if (!chain.isNullOrEmpty() && overrideConfig.chain == null) {
            overrideConfig.withChain(chain)
        } else {
            overrideConfig
        }
    }

    // -- DNS Interception (Fake-IP) --

    /**
     * Intercepts a DNS query. Returns true if handled (no UDP flow needed).
     */
    private fun handleDnsQuery(
        payload: ByteArray,
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean
    ): Boolean {
        // Parse domain + QTYPE via JNI
        val result = NativeBridge.nativeParseDnsQueryExt(payload) ?: return false
        if (result.size < 2) return false
        val domain = (result[0] as? String)?.lowercase() ?: return false
        val qtype = (result[1] as? Int) ?: return false

        // Block DDR when encrypted DNS is disabled
        if (!encryptedDnsEnabled && domain == "_dns.resolver.arpa") {
            return sendNodata(payload, srcIp, srcPort, dstIp, dstPort, isIpv6, qtype)
        }

        // Block SVCB/HTTPS (qtype=65, RFC 9460) queries with NODATA.
        // When proxied to real DNS, these queries follow CNAME chains
        // (e.g. example.com → example.com.cdn.net), causing the browser to
        // connect using the CNAME target domain instead of the original.
        // Since routing/bypass rules match on the original domain, the CNAME
        // target may not match, sending traffic through the wrong proxy path.
        // Returning NODATA forces the browser to fall back to A/AAAA records,
        // which are intercepted by our fake-IP system with correct routing.
        if (qtype == 65) {
            return sendNodata(payload, srcIp, srcPort, dstIp, dstPort, isIpv6, qtype)
        }

        // Only intercept A (1) and AAAA (28) queries
        if (qtype != 1 && qtype != 28) return false

        // Skip if no routing rules loaded
        if (!domainRouter.hasRules) return false

        // Check routing rules
        val match = domainRouter.matchDomain(domain)
        val action = match.userAction
        if (action == null && !match.isBypass) return false

        val isDirect: Boolean
        val isReject: Boolean
        val routeConfig: ProxyConfiguration?
        if (action is RouteAction.Proxy) {
            isDirect = false
            isReject = false
            val resolved = domainRouter.resolveConfiguration(action)
            if (resolved == null) {
                Log.w(TAG, "[FakeIP] Proxy configuration ${action.configId} not found, forwarding DNS normally")
                return false
            }
            // If the routing config matches the default config, use null so the
            // resolved default config (with connectAddress already set) is used.
            // The routing.json config has no resolvedIP, which would cause a DNS loop.
            routeConfig = if (resolved.id == configuration?.id) null else resolved
        } else if (action is RouteAction.Reject) {
            isDirect = true
            isReject = true
            routeConfig = null
        } else {
            // Direct or bypass (no user action)
            isDirect = true
            isReject = false
            routeConfig = null
        }

        // Allocate offset (same offset for both A and AAAA of the same domain)
        val (offset, _) = fakeIpPool.allocate(domain, routeConfig, isDirect, isReject)

        // Build fake IP bytes for the response.
        // A queries always get fake IPv4. AAAA queries get fake IPv6 only when
        // ipv6DNSEnabled is true; otherwise NODATA so apps fall back to IPv4
        // fake IPs. Omitting fc00::/7 from VPN routes causes fake IPv6 packets
        // to fall through to the physical network and time out slowly.
        // Returning NODATA for AAAA avoids this entirely.
        val fakeIpBytes: ByteArray? = when (qtype) {
            1 -> FakeIpPool.ipv4Bytes(offset)
            28 -> if (ipv6DNSEnabled) FakeIpPool.ipv6Bytes(offset) else null
            else -> null
        }

        // Generate DNS response via JNI
        val response = NativeBridge.nativeGenerateDnsResponse(payload, fakeIpBytes, qtype) ?: return false

        // Send response back via lwIP (swap src/dst)
        NativeBridge.nativeUdpSendto(
            dstIp, dstPort,     // original dst becomes response src
            srcIp, srcPort,     // original src becomes response dst
            isIpv6,
            response, response.size
        )

        return true
    }

    /** Sends a NODATA DNS response (ANCOUNT=0) for the given query. */
    private fun sendNodata(
        payload: ByteArray,
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean, qtype: Int
    ): Boolean {
        val response = NativeBridge.nativeGenerateDnsResponse(payload, null, qtype) ?: return false

        NativeBridge.nativeUdpSendto(
            dstIp, dstPort,
            srcIp, srcPort,
            isIpv6,
            response, response.size
        )
        Log.i(TAG, "[FakeIP] Blocked DDR query (qtype=$qtype)")
        return true
    }

    // -- ICMP Port Unreachable --
    //
    // Sent when UDP arrives at a stale fake IP no longer in the pool (e.g. from a
    // previous VPN session) or at a rejected domain. The ICMP response causes
    // QUIC/UDP clients to abandon the stale connection and re-resolve DNS,
    // instead of retrying indefinitely.

    /**
     * Crafts and writes an ICMP Destination Unreachable (Port Unreachable) response.
     * Must be called on lwipExecutor.
     */
    private fun sendIcmpPortUnreachable(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean,
        udpPayloadLength: Int
    ) {
        val packet = if (isIpv6) {
            buildIcmpv6PortUnreachable(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)
        } else {
            buildIcmpv4PortUnreachable(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)
        }
        try {
            tunOutput?.write(packet)
        } catch (e: Exception) {
            Log.e(TAG, "[LwipStack] ICMP write error: $e")
        }
    }

    /**
     * Builds an IPv4 ICMP Destination Unreachable (Type 3, Code 3) packet.
     * Contains a reconstructed original IPv4+UDP header per RFC 792.
     */
    private fun buildIcmpv4PortUnreachable(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        udpPayloadLength: Int
    ): ByteArray {
        // Outer IPv4 (20) + ICMP header (8) + inner IPv4 (20) + UDP header (8) = 56
        val packetLen = 56
        val p = ByteArray(packetLen)

        // --- Outer IPv4 header (src=fake IP, dst=sender) ---
        p[0] = 0x45.toByte()                                   // Version 4, IHL 5
        p[1] = 0x00                                             // TOS
        p[2] = (packetLen shr 8).toByte()                       // Total length
        p[3] = (packetLen and 0xFF).toByte()
        // p[4..5] = 0 (Identification)
        // p[6..7] = 0 (Flags + Fragment offset)
        p[8] = 64                                               // TTL
        p[9] = 1                                                // Protocol: ICMP
        // p[10..11] = 0 (Checksum, computed below)
        System.arraycopy(dstIp, 0, p, 12, 4)                   // Src = fake IP
        System.arraycopy(srcIp, 0, p, 16, 4)                   // Dst = sender

        // IPv4 header checksum
        var sum = 0L
        for (i in 0 until 20 step 2) {
            sum += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
        }
        while (sum > 0xFFFF) sum = (sum and 0xFFFF) + (sum shr 16)
        val ipCksum = sum.toInt().inv() and 0xFFFF
        p[10] = (ipCksum shr 8).toByte()
        p[11] = (ipCksum and 0xFF).toByte()

        // --- ICMP header (Type 3 = Dest Unreachable, Code 3 = Port Unreachable) ---
        p[20] = 3; p[21] = 3                                   // Type, Code
        // p[22..23] = 0 (Checksum, computed below)
        // p[24..27] = 0 (Unused)

        // --- Reconstructed original IPv4 header ---
        val udpTotalLen = 8 + udpPayloadLength
        val innerTotalLen = 20 + udpTotalLen
        p[28] = 0x45.toByte(); p[29] = 0x00                    // Version 4, IHL 5, TOS
        p[30] = ((innerTotalLen shr 8) and 0xFF).toByte()       // Total length
        p[31] = (innerTotalLen and 0xFF).toByte()
        // p[32..33] = 0 (Identification)
        // p[34..35] = 0 (Flags + Fragment offset)
        p[36] = 64; p[37] = 17                                 // TTL, Protocol: UDP
        // p[38..39] = 0 (Checksum, 0 OK in ICMP payload)
        System.arraycopy(srcIp, 0, p, 40, 4)                   // Src = original sender
        System.arraycopy(dstIp, 0, p, 44, 4)                   // Dst = fake IP

        // --- First 8 bytes of original UDP ---
        p[48] = (srcPort shr 8).toByte(); p[49] = (srcPort and 0xFF).toByte()
        p[50] = (dstPort shr 8).toByte(); p[51] = (dstPort and 0xFF).toByte()
        p[52] = ((udpTotalLen shr 8) and 0xFF).toByte()
        p[53] = (udpTotalLen and 0xFF).toByte()
        // p[54..55] = 0 (UDP checksum)

        // ICMP checksum (over ICMP header + data, offset 20..55)
        sum = 0L
        for (i in 20 until packetLen step 2) {
            sum += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
        }
        while (sum > 0xFFFF) sum = (sum and 0xFFFF) + (sum shr 16)
        val icmpCksum = sum.toInt().inv() and 0xFFFF
        p[22] = (icmpCksum shr 8).toByte()
        p[23] = (icmpCksum and 0xFF).toByte()

        return p
    }

    /**
     * Builds an IPv6 ICMPv6 Destination Unreachable (Type 1, Code 4) packet.
     * Contains a reconstructed original IPv6+UDP header per RFC 4443.
     */
    private fun buildIcmpv6PortUnreachable(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        udpPayloadLength: Int
    ): ByteArray {
        // Outer IPv6 (40) + ICMPv6 header (8) + inner IPv6 (40) + UDP header (8) = 96
        val icmpLen = 56  // 8 + 40 + 8
        val packetLen = 40 + icmpLen
        val p = ByteArray(packetLen)

        // --- Outer IPv6 header (src=fake IP, dst=sender) ---
        p[0] = 0x60; p[1] = 0; p[2] = 0; p[3] = 0            // Version 6, TC, Flow Label
        p[4] = (icmpLen shr 8).toByte()                         // Payload length
        p[5] = (icmpLen and 0xFF).toByte()
        p[6] = 58                                               // Next Header: ICMPv6
        p[7] = 64                                               // Hop Limit
        System.arraycopy(dstIp, 0, p, 8, 16)                   // Src = fake IP
        System.arraycopy(srcIp, 0, p, 24, 16)                  // Dst = sender

        // --- ICMPv6 header (Type 1 = Dest Unreachable, Code 4 = Port Unreachable) ---
        p[40] = 1; p[41] = 4                                   // Type, Code
        // p[42..43] = 0 (Checksum, computed below)
        // p[44..47] = 0 (Unused)

        // --- Reconstructed original IPv6 header ---
        val udpTotalLen = 8 + udpPayloadLength
        p[48] = 0x60; p[49] = 0; p[50] = 0; p[51] = 0         // Version 6
        p[52] = (udpTotalLen shr 8).toByte()                    // Payload length
        p[53] = (udpTotalLen and 0xFF).toByte()
        p[54] = 17; p[55] = 64                                 // Next Header: UDP, Hop Limit
        System.arraycopy(srcIp, 0, p, 56, 16)                  // Src = original sender
        System.arraycopy(dstIp, 0, p, 72, 16)                  // Dst = fake IP

        // --- First 8 bytes of original UDP ---
        p[88] = (srcPort shr 8).toByte(); p[89] = (srcPort and 0xFF).toByte()
        p[90] = (dstPort shr 8).toByte(); p[91] = (dstPort and 0xFF).toByte()
        p[92] = ((udpTotalLen shr 8) and 0xFF).toByte()
        p[93] = (udpTotalLen and 0xFF).toByte()
        // p[94..95] = 0 (UDP checksum)

        // ICMPv6 checksum (includes pseudo-header per RFC 4443 §2.3)
        var sum = 0L
        // Pseudo-header: source address (outer src = dstIp)
        for (i in 8 until 24 step 2) {
            sum += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
        }
        // Pseudo-header: destination address (outer dst = srcIp)
        for (i in 24 until 40 step 2) {
            sum += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
        }
        // Pseudo-header: upper-layer packet length + next header (58)
        sum += icmpLen.toLong()
        sum += 58
        // ICMPv6 header + data
        for (i in 40 until packetLen step 2) {
            sum += ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
        }
        while (sum > 0xFFFF) sum = (sum and 0xFFFF) + (sum shr 16)
        val cksum = sum.toInt().inv() and 0xFFFF
        p[42] = (cksum shr 8).toByte()
        p[43] = (cksum and 0xFF).toByte()

        return p
    }

    // -- Packet Reading --

    /** Continuously reads IP packets from the TUN fd and feeds them into lwIP. */
    private fun startReadingPackets() {
        Thread({
            val buffer = ByteArray(1500)  // MTU-sized read buffer
            val input = tunInput ?: return@Thread

            while (running) {
                try {
                    val length = input.read(buffer)
                    if (length <= 0) {
                        if (!running) break
                        continue
                    }

                    totalBytesOut.addAndGet(length.toLong())

                    // Acquire a pooled buffer instead of allocating a new one per packet.
                    // The buffer is returned to the pool after nativeInput completes.
                    val packet = packetPool.poll() ?: ByteArray(1500)
                    System.arraycopy(buffer, 0, packet, 0, length)

                    lwipExecutor.execute {
                        if (running) {
                            NativeBridge.nativeInput(packet, length)
                        }
                        if (packetPool.size < MAX_PACKET_POOL_SIZE) {
                            packetPool.offer(packet)
                        }
                    }
                } catch (e: Exception) {
                    if (running) {
                        Log.e(TAG, "[LwipStack] TUN read error: $e")
                    }
                    break
                }
            }
        }, "tun-reader").apply { isDaemon = true }.start()
    }

    // -- Timers --

    /** Starts the lwIP periodic timeout timer (250ms interval). */
    private fun startTimeoutTimer() {
        timeoutTimer = lwipExecutor.scheduleAtFixedRate({
            if (running) {
                NativeBridge.nativeTimerPoll()
            }
        }, 250, 250, TimeUnit.MILLISECONDS)
    }

    /** Starts the UDP flow cleanup timer (1-second interval). */
    private fun startUdpCleanupTimer() {
        udpCleanupTimer = lwipExecutor.scheduleAtFixedRate({
            if (!running) return@scheduleAtFixedRate
            val now = System.nanoTime() / 1_000_000_000.0
            val keysToRemove = mutableListOf<String>()
            for ((key, flow) in udpFlows) {
                // DNS flows (port 53) use a shorter timeout since they're one-shot query/response
                val timeout = if (flow.dstPort == 53) UDP_DNS_IDLE_TIMEOUT_SEC else UDP_IDLE_TIMEOUT_SEC
                if (now - flow.lastActivity > timeout) {
                    flow.close()
                    keysToRemove.add(key)
                }
            }
            for (key in keysToRemove) {
                udpFlows.remove(key)
            }
        }, 1, 1, TimeUnit.SECONDS)
    }

    // -- Connection Management --

    /** Called by LwipTcpConnection when it closes/aborts itself. */
    fun removeConnection(connId: Long) {
        tcpConnections.remove(connId)
    }

    companion object {
        private const val TAG = "LwipStack"
        private const val MAX_PACKET_POOL_SIZE = 64
        private const val MAX_UDP_FLOWS = 200
        private const val UDP_IDLE_TIMEOUT_SEC = 60.0
        private const val UDP_DNS_IDLE_TIMEOUT_SEC = 10.0

        /** Singleton for callback access. */
        @Volatile
        var instance: LwipStack? = null
            private set
    }
}
