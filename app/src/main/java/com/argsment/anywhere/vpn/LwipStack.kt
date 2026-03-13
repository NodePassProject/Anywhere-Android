package com.argsment.anywhere.vpn

import android.content.Context
import android.content.SharedPreferences
import android.os.ParcelFileDescriptor
import android.util.Log
import com.argsment.anywhere.data.model.ProxyConfiguration
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import com.argsment.anywhere.vpn.protocol.mux.MuxManager
import kotlinx.coroutines.asCoroutineDispatcher
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
    var ipv6Enabled: Boolean = false
        private set
    var dohEnabled: Boolean = false
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

    // -- Settings observation --
    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        when (key) {
            "ipv6Enabled", "bypassCountryCode", "dohEnabled" -> handleSettingsChanged()
            "routingChanged" -> handleRoutingChanged()
        }
    }

    // -- GeoIP Bypass --

    /** Returns true if traffic to the given host should bypass the tunnel. */
    fun shouldBypass(host: String): Boolean {
        if (bypassCountry == 0) return false
        return geoIpDatabase?.lookup(host) == bypassCountry
    }

    private fun loadBypassCountry() {
        val code = prefs.getString("bypassCountryCode", "") ?: ""
        bypassCountry = if (code.isEmpty()) 0 else GeoIpDatabase.packCountryCode(code)
        if (bypassCountry != 0) {
            Log.i(TAG, "[LwipStack] Bypass country: $code")
        }
    }

    private fun loadDoHSetting() {
        dohEnabled = prefs.getBoolean("dohEnabled", false)
    }

    // -- Lifecycle --

    /**
     * Starts the lwIP stack and begins reading packets from the TUN.
     *
     * @param fd          The TUN file descriptor from VpnService.establish()
     * @param config      The VLESS proxy configuration
     * @param ipv6        Whether IPv6 is enabled
     */
    fun start(fd: ParcelFileDescriptor, config: ProxyConfiguration, ipv6: Boolean = false) {
        Log.i(TAG, "[LwipStack] Starting, ipv6Enabled=$ipv6")
        instance = this
        this.tunFd = fd
        this.tunInput = FileInputStream(fd.fileDescriptor)
        this.tunOutput = FileOutputStream(fd.fileDescriptor)
        this.configuration = config
        this.ipv6Enabled = ipv6

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
            loadDoHSetting()

            // Create MuxManager when Vision+Mux is active
            if (config.muxEnabled && (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")) {
                muxManager = MuxManager(config, lwipExecutor.asCoroutineDispatcher())
            }

            domainRouter.loadRoutingConfiguration()
            domainRouter.loadBypassCountryRules()
            NativeBridge.nativeInit()
            startTimeoutTimer()
            startUdpCleanupTimer()
            startReadingPackets()
            Log.i(TAG, "[LwipStack] Started, mux=${muxManager != null}, bypass=${bypassCountry != 0}, doh=$dohEnabled")
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
    fun switchConfiguration(newConfig: ProxyConfiguration, ipv6: Boolean? = null) {
        Log.i(TAG, "[LwipStack] Switching configuration")
        lwipExecutor.execute {
            restartStack(newConfig, ipv6 ?: ipv6Enabled)
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
    private fun restartStack(config: ProxyConfiguration, ipv6: Boolean) {
        shutdownInternal()

        this.configuration = config
        this.ipv6Enabled = ipv6
        loadBypassCountry()
        loadDoHSetting()

        if (config.muxEnabled && (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")) {
            muxManager = MuxManager(config, lwipExecutor.asCoroutineDispatcher())
        }

        domainRouter.loadRoutingConfiguration()
        domainRouter.loadBypassCountryRules()
        fakeIpPool.rebuild(domainRouter)
        NativeBridge.nativeInit()
        startTimeoutTimer()
        startUdpCleanupTimer()
        // Start new read loop if TUN fd was swapped (old loop died with old fd).
        // Otherwise existing read loop continues uninterrupted.
        if (tunFdSwapped) {
            tunFdSwapped = false
            startReadingPackets()
        }
        Log.i(TAG, "[LwipStack] Restarted, mux=${muxManager != null}, bypass=${bypassCountry != 0}, doh=$dohEnabled, ipv6=$ipv6Enabled")
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

            val newIpv6 = prefs.getBoolean("ipv6Enabled", false)
            val newBypassCode = prefs.getString("bypassCountryCode", "") ?: ""
            val newBypass = if (newBypassCode.isEmpty()) 0 else GeoIpDatabase.packCountryCode(newBypassCode)
            val newDoH = prefs.getBoolean("dohEnabled", false)

            val ipv6Changed = newIpv6 != ipv6Enabled
            val bypassChanged = newBypass != bypassCountry
            val dohChanged = newDoH != dohEnabled

            if (!ipv6Changed && !bypassChanged && !dohChanged) return@execute

            if (ipv6Changed) {
                onTunnelSettingsNeedReapply?.invoke()
            }

            Log.i(TAG, "[LwipStack] Settings changed, restarting (bypass=${newBypass != 0}, ipv6=$newIpv6, doh=$newDoH)")
            restartStack(config, newIpv6)
        }
    }

    private fun handleRoutingChanged() {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute
            Log.i(TAG, "[LwipStack] Routing rules changed, restarting")
            restartStack(config, ipv6Enabled)
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

        if (isIpv6 && !ipv6Enabled) {
            return 0L
        }

        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"
        var dstHost = dstIpString
        var connectionConfig = defaultConfig
        var forceBypass = false

        if (FakeIpPool.isFakeIp(dstIpString)) {
            val entry = fakeIpPool.lookup(dstIpString)
            if (entry != null) {
                if (entry.isReject) {
                    Log.d(TAG, "[FakeIP] TCP to ${entry.domain}:$dstPort — REJECT")
                    return 0L
                }
                dstHost = entry.domain
                forceBypass = entry.isDirect
                connectionConfig = entry.configuration ?: defaultConfig
            } else {
                Log.d(TAG, "[FakeIP] TCP to $dstIpString:$dstPort — stale DNS cache (no pool entry)")
                return 0L
            }
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
        if (isIpv6 && !ipv6Enabled) {
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

        if (FakeIpPool.isFakeIp(dstIpString)) {
            val entry = fakeIpPool.lookup(dstIpString)
            if (entry != null) {
                if (entry.isReject) {
                    Log.d(TAG, "[FakeIP] UDP to ${entry.domain}:$dstPort — REJECT")
                    return
                }
                dstHost = entry.domain
                forceBypass = entry.isDirect
                flowConfig = entry.configuration ?: defaultConfig
            } else {
                Log.d(TAG, "[FakeIP] UDP to $dstIpString:$dstPort — stale DNS cache (no pool entry)")
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

        // Block DDR when DoH is disabled
        if (!dohEnabled && domain == "_dns.resolver.arpa") {
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
        // Only return fake IPv4 for A queries. AAAA queries always get NODATA
        // so apps fall back to IPv4 fake IPs. Omitting fc00::/7 from VPN routes
        // causes fake IPv6 packets to fall through to the physical network and
        // time out slowly. Returning NODATA for AAAA avoids this entirely.
        val fakeIpBytes: ByteArray? = when (qtype) {
            1 -> FakeIpPool.ipv4Bytes(offset)
            else -> null  // AAAA → always NODATA for routed domains
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
