package com.argsment.anywhere.data.network

import com.argsment.anywhere.data.model.HttpUpgradeConfiguration
import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.RealityConfiguration
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.data.model.TlsFingerprint
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.WebSocketConfiguration
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksCipher
import com.argsment.anywhere.vpn.util.base64UrlToByteArrayOrNull
import com.argsment.anywhere.vpn.util.hexToByteArrayOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

object ClashProxyParser {

    data class ParseResult(
        val configurations: List<ProxyConfiguration>,
        val skippedCount: Int
    )

    sealed class ParseError(message: String) : Exception(message) {
        class InvalidYaml(reason: String) : ParseError("Invalid Clash YAML: $reason")
        class MissingProxiesKey : ParseError("Clash YAML is missing 'proxies' key.")
    }

    fun parse(yamlString: String): ParseResult {
        val jsonStr = NativeBridge.nativeParseYaml(yamlString)
            ?: throw ParseError.InvalidYaml("Failed to parse YAML document")

        val root = runCatching { JSONObject(jsonStr) }.getOrNull()
            ?: throw ParseError.InvalidYaml("Root document is not a mapping")

        val proxies = root.optJSONArray("proxies")
            ?: throw ParseError.MissingProxiesKey()

        val configurations = mutableListOf<ProxyConfiguration>()
        var skippedCount = 0

        for (i in 0 until proxies.length()) {
            val proxy = proxies.optJSONObject(i)
            if (proxy != null) {
                val config = parseProxy(proxy)
                if (config != null) {
                    configurations.add(config)
                } else {
                    skippedCount++
                }
            } else {
                skippedCount++
            }
        }

        return ParseResult(configurations, skippedCount)
    }

    private fun parseProxy(node: JSONObject): ProxyConfiguration? {
        val proxyType = node.optString("type")
        if (proxyType == "ss") return parseShadowsocksProxy(node)
        if (proxyType == "socks5" || proxyType == "socks") return parseSocks5Proxy(node)
        if (proxyType == "trojan") return parseTrojanProxy(node)
        if (proxyType != "vless") return null

        val name = node.optString("name").takeIf { it.isNotEmpty() } ?: return null
        val server = node.optString("server").takeIf { it.isNotEmpty() } ?: return null
        val uuidString = node.optString("uuid").takeIf { it.isNotEmpty() } ?: return null
        val uuid = runCatching { UUID.fromString(uuidString) }.getOrNull() ?: return null

        val portInt = node.optInt("port", -1)
        if (portInt <= 0 || portInt > UShort.MAX_VALUE.toInt()) return null
        val port = portInt.toUShort()

        // Transport: tcp (default) or ws; skip h2/grpc
        val network = node.optString("network", "tcp")
        if (network == "h2" || network == "grpc") return null
        val transport = if (network == "ws") "ws" else "tcp"

        val encryption = node.optString("encryption", "none")
        val rawFlow = node.optString("flow", "")
        val flow: String? = rawFlow.takeIf { it.isNotEmpty() }

        // Security: reality > tls > none
        val tlsEnabled = node.optBoolean("tls", false)
        val realityOpts = node.optJSONObject("reality-opts")
        val hasReality = realityOpts != null

        val security = when {
            hasReality -> "reality"
            tlsEnabled -> "tls"
            else -> "none"
        }

        // Common TLS/Reality fields
        val serverName = node.optString("servername", "").takeIf { it.isNotEmpty() }
            ?: node.optString("sni", "").takeIf { it.isNotEmpty() }
            ?: server
        val skipCertVerify = node.optBoolean("skip-cert-verify", false)
        val clientFP = node.optString("client-fingerprint", "").takeIf { it.isNotEmpty() }
        val fingerprint = TlsFingerprint.fromRaw(mapFingerprint(clientFP))
        val alpn = node.optJSONArray("alpn")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotEmpty() } }
        }?.takeIf { it.isNotEmpty() }

        // Build TLS configuration
        var tlsConfig: TlsConfiguration? = null
        if (security == "tls") {
            tlsConfig = TlsConfiguration(
                serverName = serverName,
                alpn = alpn,
                allowInsecure = skipCertVerify,
                fingerprint = fingerprint
            )
        }

        // Build Reality configuration
        var realityConfig: RealityConfiguration? = null
        if (security == "reality" && realityOpts != null) {
            val pubKeyStr = realityOpts.optString("public-key", "")
            val shortIdStr = realityOpts.optString("short-id", "")
            val publicKey = pubKeyStr.base64UrlToByteArrayOrNull()
            if (publicKey == null || publicKey.size != 32) return null
            realityConfig = RealityConfiguration(
                serverName = serverName,
                publicKey = publicKey,
                shortId = shortIdStr.hexToByteArrayOrNull() ?: byteArrayOf(),
                fingerprint = fingerprint
            )
        }

        // Build WebSocket / HTTPUpgrade configuration
        var wsConfig: WebSocketConfiguration? = null
        var httpUpgradeConfig: HttpUpgradeConfiguration? = null
        if (transport == "ws") {
            var wsPath = "/"
            var wsHost = server
            val wsHeaders = mutableMapOf<String, String>()
            var maxEarlyData = 0
            var earlyDataHeaderName = ""
            var isHttpUpgrade = false

            node.optJSONObject("ws-opts")?.let { woNode ->
                wsPath = woNode.optString("path", "/")
                // v2ray-http-upgrade flag: treat as HTTPUpgrade instead of WebSocket
                isHttpUpgrade = woNode.optBoolean("v2ray-http-upgrade", false)
                maxEarlyData = woNode.optInt("max-early-data", 0)
                earlyDataHeaderName = woNode.optString("early-data-header-name", "")
                woNode.optJSONObject("headers")?.let { headers ->
                    for (key in headers.keys()) {
                        val value = headers.optString(key, "")
                        wsHeaders[key] = value
                        if (key == "Host") wsHost = value
                    }
                }
            }

            if (isHttpUpgrade) {
                httpUpgradeConfig = HttpUpgradeConfiguration(host = wsHost, path = wsPath, headers = wsHeaders)
            } else {
                wsConfig = WebSocketConfiguration(
                    host = wsHost,
                    path = wsPath,
                    headers = wsHeaders,
                    maxEarlyData = maxEarlyData,
                    earlyDataHeaderName = earlyDataHeaderName.ifEmpty { "Sec-WebSocket-Protocol" }
                )
            }
        }

        val effectiveTransport = if (httpUpgradeConfig != null) "httpupgrade" else transport

        return ProxyConfiguration(
            name = name,
            serverAddress = server,
            serverPort = port,
            uuid = uuid,
            encryption = encryption,
            transport = effectiveTransport,
            flow = flow,
            security = security,
            tls = tlsConfig,
            reality = realityConfig,
            websocket = wsConfig,
            httpUpgrade = httpUpgradeConfig
        )
    }

    private fun parseShadowsocksProxy(node: JSONObject): ProxyConfiguration? {
        val name = node.optString("name").takeIf { it.isNotEmpty() } ?: return null
        val server = node.optString("server").takeIf { it.isNotEmpty() } ?: return null
        val password = node.optString("password").takeIf { it.isNotEmpty() } ?: return null
        val cipher = node.optString("cipher").takeIf { it.isNotEmpty() } ?: return null

        // Validate cipher is supported
        ShadowsocksCipher.fromMethod(cipher) ?: return null

        val portInt = node.optInt("port", -1)
        if (portInt <= 0 || portInt > UShort.MAX_VALUE.toInt()) return null
        val port = portInt.toUShort()

        // Transport: tcp (default) or ws; skip h2/grpc
        val network = node.optString("network", "").takeIf { it.isNotEmpty() }
            ?: node.optString("plugin-opts-network", "tcp")
        if (network == "h2" || network == "grpc") return null
        val transport = if (network == "ws") "ws" else "tcp"

        // TLS
        val tlsEnabled = node.optBoolean("tls", false)
        val security = if (tlsEnabled) "tls" else "none"

        var tlsConfig: TlsConfiguration? = null
        if (tlsEnabled) {
            val sni = node.optString("servername", "").takeIf { it.isNotEmpty() }
                ?: node.optString("sni", "").takeIf { it.isNotEmpty() }
                ?: server
            val alpn = node.optJSONArray("alpn")?.let { arr ->
                (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotEmpty() } }
            }?.takeIf { it.isNotEmpty() }
            val clientFP = node.optString("client-fingerprint", "").takeIf { it.isNotEmpty() }
            val fingerprint = TlsFingerprint.fromRaw(mapFingerprint(clientFP))

            tlsConfig = TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                allowInsecure = node.optBoolean("skip-cert-verify", false),
                fingerprint = fingerprint
            )
        }

        // WebSocket / HTTPUpgrade
        var wsConfig: WebSocketConfiguration? = null
        var httpUpgradeConfig: HttpUpgradeConfiguration? = null
        if (transport == "ws") {
            var wsPath = "/"
            var wsHost = server
            val wsHeaders = mutableMapOf<String, String>()
            var maxEarlyData = 0
            var earlyDataHeaderName = ""
            var isHttpUpgrade = false

            node.optJSONObject("ws-opts")?.let { woNode ->
                wsPath = woNode.optString("path", "/")
                isHttpUpgrade = woNode.optBoolean("v2ray-http-upgrade", false)
                maxEarlyData = woNode.optInt("max-early-data", 0)
                earlyDataHeaderName = woNode.optString("early-data-header-name", "")
                woNode.optJSONObject("headers")?.let { headers ->
                    for (key in headers.keys()) {
                        val value = headers.optString(key, "")
                        wsHeaders[key] = value
                        if (key == "Host") wsHost = value
                    }
                }
            }

            if (isHttpUpgrade) {
                httpUpgradeConfig = HttpUpgradeConfiguration(host = wsHost, path = wsPath, headers = wsHeaders)
            } else {
                wsConfig = WebSocketConfiguration(
                    host = wsHost,
                    path = wsPath,
                    headers = wsHeaders,
                    maxEarlyData = maxEarlyData,
                    earlyDataHeaderName = earlyDataHeaderName.ifEmpty { "Sec-WebSocket-Protocol" }
                )
            }
        }

        val ssEffectiveTransport = if (httpUpgradeConfig != null) "httpupgrade" else transport

        return ProxyConfiguration(
            name = name,
            serverAddress = server,
            serverPort = port,
            uuid = UUID.randomUUID(),
            encryption = "none",
            transport = ssEffectiveTransport,
            security = security,
            tls = tlsConfig,
            websocket = wsConfig,
            httpUpgrade = httpUpgradeConfig,
            outboundProtocol = OutboundProtocol.SHADOWSOCKS,
            ssPassword = password,
            ssMethod = cipher
        )
    }

    /**
     * Parses a Clash `type: trojan` node into a TROJAN outbound. Mirrors iOS
     * `ClashProxyParser.parseTrojanProxy`: Reality, ECH, gRPC, the Trojan-Go
     * SS layer, and any transport other than bare TCP cause the node to be
     * skipped rather than silently downgraded to a different wire format.
     */
    private fun parseTrojanProxy(node: JSONObject): ProxyConfiguration? {
        val name = node.optString("name").takeIf { it.isNotEmpty() } ?: return null
        val server = node.optString("server").takeIf { it.isNotEmpty() } ?: return null
        val password = node.optString("password").takeIf { it.isNotEmpty() } ?: return null

        val portInt = node.optInt("port", -1)
        if (portInt <= 0 || portInt > UShort.MAX_VALUE.toInt()) return null
        val port = portInt.toUShort()

        val network = node.optString("network", "tcp")
        if (network != "tcp") return null

        if (node.optJSONObject("reality-opts") != null) return null
        if (node.optJSONObject("ech-opts") != null) return null
        if (node.optJSONObject("grpc-opts") != null) return null
        node.optJSONObject("ss-opts")?.let {
            if (it.optBoolean("enabled", false)) return null
        }

        val sni = node.optString("servername", "").takeIf { it.isNotEmpty() }
            ?: node.optString("sni", "").takeIf { it.isNotEmpty() }
            ?: server
        val alpn = node.optJSONArray("alpn")?.let { arr ->
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotEmpty() } }
        }?.takeIf { it.isNotEmpty() }
        val clientFP = node.optString("client-fingerprint", "").takeIf { it.isNotEmpty() }
        val fingerprint = TlsFingerprint.fromRaw(mapFingerprint(clientFP))

        val tls = TlsConfiguration(
            serverName = sni,
            alpn = alpn,
            fingerprint = fingerprint
        )

        return ProxyConfiguration(
            name = name,
            serverAddress = server,
            serverPort = port,
            uuid = UUID.randomUUID(), // placeholder, not used for Trojan
            encryption = "none",
            transport = "tcp",
            security = "tls",
            tls = tls,
            outboundProtocol = OutboundProtocol.TROJAN,
            trojanPassword = password,
            trojanTls = tls
        )
    }

    private fun parseSocks5Proxy(node: JSONObject): ProxyConfiguration? {
        val name = node.optString("name").takeIf { it.isNotEmpty() } ?: return null
        val server = node.optString("server").takeIf { it.isNotEmpty() } ?: return null

        val portInt = node.optInt("port", -1)
        if (portInt <= 0 || portInt > UShort.MAX_VALUE.toInt()) return null
        val port = portInt.toUShort()

        // Optional username/password (Clash uses snake_case in some forks)
        val username = node.optString("username", "").takeIf { it.isNotEmpty() }
            ?: node.optString("user", "").takeIf { it.isNotEmpty() }
        val password = node.optString("password", "").takeIf { it.isNotEmpty() }
            ?: node.optString("pass", "").takeIf { it.isNotEmpty() }

        return ProxyConfiguration(
            name = name,
            serverAddress = server,
            serverPort = port,
            uuid = UUID.randomUUID(), // placeholder, not used for SOCKS5
            encryption = "none",
            outboundProtocol = OutboundProtocol.SOCKS5,
            socks5Username = username,
            socks5Password = password
        )
    }

    private fun mapFingerprint(fp: String?): String = when (fp?.lowercase()) {
        "chrome" -> TlsFingerprint.CHROME_133.raw
        "firefox" -> TlsFingerprint.FIREFOX_148.raw
        "safari" -> TlsFingerprint.SAFARI_26.raw
        "ios" -> TlsFingerprint.IOS_14.raw
        "edge" -> TlsFingerprint.EDGE_85.raw
        "android" -> TlsFingerprint.ANDROID_11.raw
        "qq" -> TlsFingerprint.QQ_11.raw
        "360" -> TlsFingerprint.BROWSER_360.raw
        "random" -> TlsFingerprint.RANDOM.raw
        else -> fp ?: TlsFingerprint.CHROME_133.raw
    }
}
