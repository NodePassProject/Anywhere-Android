package com.argsment.anywhere.data.network

import com.argsment.anywhere.data.model.HttpUpgradeConfiguration
import com.argsment.anywhere.data.model.RealityConfiguration
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.data.model.TlsFingerprint
import com.argsment.anywhere.data.model.VlessConfiguration
import com.argsment.anywhere.data.model.WebSocketConfiguration
import com.argsment.anywhere.vpn.NativeBridge
import com.argsment.anywhere.vpn.util.base64UrlToByteArrayOrNull
import com.argsment.anywhere.vpn.util.hexToByteArrayOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

object ClashProxyParser {

    data class ParseResult(
        val configurations: List<VlessConfiguration>,
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

        val configurations = mutableListOf<VlessConfiguration>()
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

    private fun parseProxy(node: JSONObject): VlessConfiguration? {
        if (node.optString("type") != "vless") return null

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

        // Build WebSocket configuration
        var wsConfig: WebSocketConfiguration? = null
        if (transport == "ws") {
            var wsPath = "/"
            var wsHost = server
            val wsHeaders = mutableMapOf<String, String>()

            node.optJSONObject("ws-opts")?.let { woNode ->
                wsPath = woNode.optString("path", "/")
                woNode.optJSONObject("headers")?.let { headers ->
                    for (key in headers.keys()) {
                        val value = headers.optString(key, "")
                        wsHeaders[key] = value
                        if (key == "Host") wsHost = value
                    }
                }
            }

            wsConfig = WebSocketConfiguration(host = wsHost, path = wsPath, headers = wsHeaders)
        }

        return VlessConfiguration(
            name = name,
            serverAddress = server,
            serverPort = port,
            uuid = uuid,
            encryption = encryption,
            transport = transport,
            flow = flow,
            security = security,
            tls = tlsConfig,
            reality = realityConfig,
            websocket = wsConfig
        )
    }

    private fun mapFingerprint(fp: String?): String = when (fp?.lowercase()) {
        "chrome" -> TlsFingerprint.CHROME_120.raw
        "firefox" -> TlsFingerprint.FIREFOX_120.raw
        "safari" -> TlsFingerprint.SAFARI_16.raw
        "ios" -> TlsFingerprint.IOS_14.raw
        "edge" -> TlsFingerprint.EDGE_106.raw
        "random" -> TlsFingerprint.RANDOM.raw
        else -> fp ?: TlsFingerprint.CHROME_120.raw
    }
}
