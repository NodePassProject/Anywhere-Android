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
        val uuid = parseXrayUuid(uuidString) ?: return null

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

    /**
     * Parses a Clash `type: ss` node. Anywhere only supports bare Shadowsocks —
     * any plugin (obfs, v2ray-plugin, shadow-tls, restls), configured transport
     * other than plain TCP, or TLS wrapper causes the node to be skipped rather
     * than silently downgraded.
     */
    private fun parseShadowsocksProxy(node: JSONObject): ProxyConfiguration? {
        val name = node.optString("name").takeIf { it.isNotEmpty() } ?: return null
        val server = node.optString("server").takeIf { it.isNotEmpty() } ?: return null
        val password = node.optString("password").takeIf { it.isNotEmpty() } ?: return null
        val cipher = node.optString("cipher").takeIf { it.isNotEmpty() } ?: return null

        ShadowsocksCipher.fromMethod(cipher) ?: return null

        val portInt = node.optInt("port", -1)
        if (portInt <= 0 || portInt > UShort.MAX_VALUE.toInt()) return null
        val port = portInt.toUShort()

        val network = node.optString("network", "").takeIf { it.isNotEmpty() }
            ?: node.optString("plugin-opts-network", "tcp")
        if (network != "tcp") return null
        if (node.optBoolean("tls", false)) return null
        if (node.optString("plugin", "").isNotEmpty()) return null

        return ProxyConfiguration(
            name = name,
            serverAddress = server,
            serverPort = port,
            uuid = UUID.randomUUID(),
            encryption = "none",
            transport = "tcp",
            security = "none",
            outboundProtocol = OutboundProtocol.SHADOWSOCKS,
            ssPassword = password,
            ssMethod = cipher
        )
    }

    /**
     * Parses a Clash `type: trojan` node into a TROJAN outbound. Reality, ECH,
     * gRPC, the Trojan-Go SS layer, and any transport other than bare TCP
     * cause the node to be skipped rather than silently downgraded to a
     * different wire format.
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

        // Anywhere speaks SOCKS5 strictly in the clear — reject SOCKS5-over-TLS
        // nodes rather than silently downgrading them.
        if (node.optBoolean("tls", false)) return null

        // Some Clash forks use snake_case (user/pass) instead of username/password.
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

    /**
     * Parses a UUID the way Xray-core does (common/uuid/uuid.go ParseString):
     * length 32–36 is hex/standard-form decoded; length 1–30 is derived as
     * `SHA1(zero_uuid || input)[0..16]` with RFC 4122 v5 + variant bits stamped.
     * Mirrors iOS `UUID(xrayString:)`.
     */
    private fun parseXrayUuid(str: String): UUID? {
        val len = str.length
        if (len in 32..36) {
            // Try standard hyphenated form first, then 32-char hex.
            runCatching { return UUID.fromString(str) }
            if (len == 32 && str.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                val bytes = ByteArray(16) { i ->
                    val hi = Character.digit(str[i * 2], 16)
                    val lo = Character.digit(str[i * 2 + 1], 16)
                    if (hi < 0 || lo < 0) return null
                    ((hi shl 4) or lo).toByte()
                }
                return uuidFromBytes(bytes)
            }
            return null
        }
        if (len !in 1..30) return null

        // SHA-1(zero-UUID || str), take first 16 bytes, stamp v5 + variant bits.
        val md = java.security.MessageDigest.getInstance("SHA-1")
        md.update(ByteArray(16))
        md.update(str.toByteArray(Charsets.UTF_8))
        val hash = md.digest()
        val bytes = hash.copyOfRange(0, 16)
        bytes[6] = ((bytes[6].toInt() and 0x0F) or (5 shl 4)).toByte()
        bytes[8] = ((bytes[8].toInt() and 0x3F) or 0x80).toByte()
        return uuidFromBytes(bytes)
    }

    private fun uuidFromBytes(b: ByteArray): UUID {
        var msb = 0L
        var lsb = 0L
        for (i in 0..7) msb = (msb shl 8) or (b[i].toLong() and 0xFF)
        for (i in 8..15) lsb = (lsb shl 8) or (b[i].toLong() and 0xFF)
        return UUID(msb, lsb)
    }

    private fun mapFingerprint(fp: String?): String = when (fp?.lowercase()) {
        "chrome" -> TlsFingerprint.CHROME_133.raw
        "firefox" -> TlsFingerprint.FIREFOX_148.raw
        "safari" -> TlsFingerprint.SAFARI_26.raw
        "ios" -> TlsFingerprint.IOS_14.raw
        "edge" -> TlsFingerprint.EDGE_85.raw
        "random" -> TlsFingerprint.RANDOM.raw
        // Note: Android-only fingerprints (android_11/qq_11/360_7) intentionally
        // not surfaced here — iOS doesn't recognize them, so adding the mapping
        // would create asymmetric Clash-import behavior between platforms.
        else -> fp ?: TlsFingerprint.CHROME_133.raw
    }
}
