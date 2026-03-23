package com.argsment.anywhere.data.model

import com.argsment.anywhere.vpn.util.base64UrlToByteArrayOrNull
import com.argsment.anywhere.vpn.util.hexToByteArrayOrNull
import com.argsment.anywhere.vpn.util.toBase64Url
import com.argsment.anywhere.vpn.util.toHex
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.UUID

// =============================================================================
// TLS Fingerprint
// =============================================================================

@Serializable
enum class TlsFingerprint(val raw: String) {
    @SerialName("chrome_120") CHROME_120("chrome_120"),
    @SerialName("firefox_120") FIREFOX_120("firefox_120"),
    @SerialName("safari_16") SAFARI_16("safari_16"),
    @SerialName("ios_14") IOS_14("ios_14"),
    @SerialName("edge_106") EDGE_106("edge_106"),
    @SerialName("random") RANDOM("random");

    val displayName: String
        get() = when (this) {
            CHROME_120 -> "Chrome 120"
            FIREFOX_120 -> "Firefox 120"
            SAFARI_16 -> "Safari 16.0"
            IOS_14 -> "iOS 14"
            EDGE_106 -> "Edge 106"
            RANDOM -> "Random"
        }

    companion object {
        fun fromRaw(value: String): TlsFingerprint =
            entries.find { it.raw == value } ?: CHROME_120

        val concreteFingerprints: List<TlsFingerprint> = entries.filter { it != RANDOM }
    }
}

// =============================================================================
// TLS Configuration
// =============================================================================

@Serializable
data class TlsConfiguration(
    val serverName: String,
    val alpn: List<String>? = null,
    val allowInsecure: Boolean = false,
    val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_120
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): TlsConfiguration? {
            if (params["security"] != "tls") return null
            val sni = params["sni"] ?: serverAddress
            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val allowInsecure = params["allowInsecure"] == "1" || params["allowInsecure"] == "true"
            val fp = params["fp"] ?: "chrome_120"
            return TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                allowInsecure = allowInsecure,
                fingerprint = TlsFingerprint.fromRaw(fp)
            )
        }
    }
}

// =============================================================================
// Reality Configuration
// =============================================================================

@Serializable
data class RealityConfiguration(
    val serverName: String,
    @Serializable(with = Base64UrlByteArraySerializer::class) val publicKey: ByteArray,
    @Serializable(with = HexByteArraySerializer::class) val shortId: ByteArray,
    val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_120
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RealityConfiguration) return false
        return serverName == other.serverName &&
                publicKey.contentEquals(other.publicKey) &&
                shortId.contentEquals(other.shortId) &&
                fingerprint == other.fingerprint
    }

    override fun hashCode(): Int {
        var result = serverName.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + shortId.contentHashCode()
        result = 31 * result + fingerprint.hashCode()
        return result
    }

    companion object {
        fun parse(params: Map<String, String>): RealityConfiguration? {
            if (params["security"] != "reality") return null
            val sni = params["sni"]?.takeIf { it.isNotEmpty() }
                ?: throw ProxyError.InvalidUrl("Missing Reality parameter: sni")
            val pbk = params["pbk"]?.takeIf { it.isNotEmpty() }
                ?: throw ProxyError.InvalidUrl("Missing Reality parameter: pbk (public key)")
            val publicKey = pbk.base64UrlToByteArrayOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid Reality public key")
            if (publicKey.size != 32) throw ProxyError.InvalidUrl("Invalid Reality public key")
            val shortId = (params["sid"] ?: "").hexToByteArrayOrNull() ?: byteArrayOf()
            val fp = params["fp"] ?: "chrome_120"
            return RealityConfiguration(
                serverName = sni,
                publicKey = publicKey,
                shortId = shortId,
                fingerprint = TlsFingerprint.fromRaw(fp)
            )
        }
    }
}

// =============================================================================
// WebSocket Configuration
// =============================================================================

@Serializable
data class WebSocketConfiguration(
    val host: String,
    val path: String = "/",
    val headers: Map<String, String> = emptyMap(),
    val maxEarlyData: Int = 0,
    val earlyDataHeaderName: String = "Sec-WebSocket-Protocol",
    val heartbeatPeriod: UInt = 0u
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): WebSocketConfiguration {
            val host = params["host"] ?: serverAddress
            val path = params["path"]?.let { URLDecoder.decode(it, "UTF-8") } ?: "/"
            val maxEarlyData = params["ed"]?.toIntOrNull() ?: 0
            return WebSocketConfiguration(host = host, path = path, maxEarlyData = maxEarlyData)
        }
    }
}

// =============================================================================
// HTTP Upgrade Configuration
// =============================================================================

@Serializable
data class HttpUpgradeConfiguration(
    val host: String,
    val path: String = "/",
    val headers: Map<String, String> = emptyMap()
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): HttpUpgradeConfiguration {
            val host = params["host"] ?: serverAddress
            var path = params["path"]?.let { URLDecoder.decode(it, "UTF-8") } ?: "/"
            if (!path.startsWith("/")) path = "/$path"
            return HttpUpgradeConfiguration(host = host, path = path)
        }
    }
}

// =============================================================================
// XHTTP Mode
// =============================================================================

@Serializable
enum class XHttpMode(val raw: String) {
    @SerialName("auto") AUTO("auto"),
    @SerialName("stream-one") STREAM_ONE("stream-one"),
    @SerialName("packet-up") PACKET_UP("packet-up"),
    @SerialName("stream-up") STREAM_UP("stream-up");

    val displayName: String
        get() = when (this) {
            AUTO -> "Auto"
            STREAM_ONE -> "Stream One"
            PACKET_UP -> "Packet Up"
            STREAM_UP -> "Stream Up"
        }

    companion object {
        fun fromRaw(value: String): XHttpMode =
            entries.find { it.raw == value } ?: AUTO
    }
}

// =============================================================================
// XHTTP Configuration
// =============================================================================

@Serializable
data class XHttpConfiguration(
    val host: String,
    val path: String = "/",
    val mode: XHttpMode = XHttpMode.AUTO,
    val headers: Map<String, String> = emptyMap(),
    @SerialName("noGRPCHeader") val noGrpcHeader: Boolean = false,
    val scMaxEachPostBytes: Int = 1_000_000,
    val scMinPostsIntervalMs: Int = 30
) {
    val normalizedPath: String
        get() {
            var p = path
            if (!p.startsWith("/")) p = "/$p"
            if (!p.endsWith("/")) p = "$p/"
            return p
        }

    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): XHttpConfiguration {
            val host = params["host"] ?: serverAddress
            val path = params["path"]?.let { URLDecoder.decode(it, "UTF-8") } ?: "/"
            val mode = XHttpMode.fromRaw(params["mode"] ?: "auto")
            return XHttpConfiguration(host = host, path = path, mode = mode)
        }
    }
}

// =============================================================================
// UUID Serializer
// =============================================================================

object UuidSerializer : KSerializer<UUID> {
    override val descriptor = PrimitiveSerialDescriptor("UUID", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: UUID) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder): UUID = UUID.fromString(decoder.decodeString())
}

// =============================================================================
// ByteArray serializers (Base64URL and Hex)
// =============================================================================

object Base64UrlByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor = PrimitiveSerialDescriptor("Base64UrlByteArray", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(value.toBase64Url())
    override fun deserialize(decoder: Decoder): ByteArray =
        decoder.decodeString().base64UrlToByteArrayOrNull() ?: byteArrayOf()
}

object HexByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor = PrimitiveSerialDescriptor("HexByteArray", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(value.toHex())
    override fun deserialize(decoder: Decoder): ByteArray =
        decoder.decodeString().hexToByteArrayOrNull() ?: byteArrayOf()
}

// =============================================================================
// Outbound Protocol
// =============================================================================

@Serializable
enum class OutboundProtocol {
    @SerialName("vless") VLESS,
    @SerialName("shadowsocks") SHADOWSOCKS,
    @SerialName("naive_http11") NAIVE_HTTP11,
    @SerialName("naive_http2") NAIVE_HTTP2,
    @SerialName("naive_http3") NAIVE_HTTP3;

    val isNaive: Boolean get() = this == NAIVE_HTTP11 || this == NAIVE_HTTP2 || this == NAIVE_HTTP3
    val displayName: String
        get() = when (this) {
            VLESS -> "VLESS"
            SHADOWSOCKS -> "Shadowsocks"
            NAIVE_HTTP11 -> "HTTPS"
            NAIVE_HTTP2 -> "HTTP/2"
            NAIVE_HTTP3 -> "QUIC"
        }
}

@Serializable
enum class NaiveProtocol {
    @SerialName("http11") HTTP11,
    @SerialName("http2") HTTP2
}

// =============================================================================
// Proxy Configuration
// =============================================================================

@Serializable
data class ProxyConfiguration(
    @Serializable(with = UuidSerializer::class) val id: UUID = UUID.randomUUID(),
    val name: String,
    val serverAddress: String,
    val serverPort: UShort,
    val resolvedIP: String? = null,
    @Serializable(with = UuidSerializer::class) val uuid: UUID,
    val encryption: String,
    val transport: String = "tcp",
    val flow: String? = null,
    val security: String = "none",
    val tls: TlsConfiguration? = null,
    val reality: RealityConfiguration? = null,
    val websocket: WebSocketConfiguration? = null,
    val httpUpgrade: HttpUpgradeConfiguration? = null,
    val xhttp: XHttpConfiguration? = null,
    val testseed: List<UInt> = listOf(900u, 500u, 900u, 256u),
    val muxEnabled: Boolean = true,
    val xudpEnabled: Boolean = true,
    @Serializable(with = UuidSerializer::class) val subscriptionId: UUID? = null,
    val outboundProtocol: OutboundProtocol = OutboundProtocol.VLESS,
    val ssPassword: String? = null,
    val ssMethod: String? = null,
    val naiveUsername: String? = null,
    val naivePassword: String? = null,
    val naiveProtocol: NaiveProtocol? = null,
    val chain: List<ProxyConfiguration>? = null
) {
    val connectAddress: String get() = resolvedIP ?: serverAddress

    fun contentEquals(other: ProxyConfiguration): Boolean =
        name == other.name &&
                serverAddress == other.serverAddress &&
                serverPort == other.serverPort &&
                uuid == other.uuid &&
                encryption == other.encryption &&
                transport == other.transport &&
                flow == other.flow &&
                security == other.security &&
                tls == other.tls &&
                reality == other.reality &&
                websocket == other.websocket &&
                httpUpgrade == other.httpUpgrade &&
                xhttp == other.xhttp &&
                testseed == other.testseed &&
                muxEnabled == other.muxEnabled &&
                xudpEnabled == other.xudpEnabled &&
                outboundProtocol == other.outboundProtocol &&
                ssPassword == other.ssPassword &&
                ssMethod == other.ssMethod &&
                naiveUsername == other.naiveUsername &&
                naivePassword == other.naivePassword &&
                naiveProtocol == other.naiveProtocol &&
                chain == other.chain

    fun withChain(chain: List<ProxyConfiguration>?): ProxyConfiguration = copy(chain = chain)

    // =========================================================================
    // URL Export
    // =========================================================================

    fun toUrl(): String = when (outboundProtocol) {
        OutboundProtocol.VLESS -> toVlessUrl()
        OutboundProtocol.SHADOWSOCKS -> toShadowsocksUrl()
        OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> toNaiveUrl()
        OutboundProtocol.NAIVE_HTTP3 -> toQuicUrl()
    }

    private fun toVlessUrl(): String {
        val params = mutableListOf<String>()
        if (encryption != "none") params.add("encryption=$encryption")
        if (!flow.isNullOrEmpty()) params.add("flow=$flow")
        params.add("security=$security")
        if (transport != "tcp") params.add("type=$transport")

        // TLS parameters
        if (security == "tls" && tls != null) {
            if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
            tls.alpn?.takeIf { it.isNotEmpty() }?.let {
                params.add("alpn=${urlEncode(it.joinToString(","))}")
            }
            if (tls.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${tls.fingerprint.raw}")
        }

        // Reality parameters
        if (security == "reality" && reality != null) {
            params.add("sni=${reality.serverName}")
            params.add("pbk=${reality.publicKey.toBase64Url()}")
            if (reality.shortId.isNotEmpty()) params.add("sid=${reality.shortId.toHex()}")
            if (reality.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${reality.fingerprint.raw}")
        }

        appendTransportParams(params)
        if (!muxEnabled) params.add("mux=false")
        if (!xudpEnabled) params.add("xudp=false")
        if (testseed != listOf(900u, 500u, 900u, 256u)) {
            params.add("testseed=${testseed.joinToString(",")}")
        }

        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        val fragment = urlEncode(name)
        return "vless://${uuid.toString().lowercase()}@$serverAddress:$serverPort/$query#$fragment"
    }

    private fun toShadowsocksUrl(): String {
        val method = ssMethod ?: return "ss://invalid"
        val password = ssPassword ?: return "ss://invalid"
        val userInfo = "$method:$password"
        val encoded = java.util.Base64.getEncoder().encodeToString(userInfo.toByteArray())
            .trimEnd('=')

        val params = mutableListOf<String>()
        if (transport != "tcp") params.add("type=$transport")
        if (security != "none") params.add("security=$security")

        if (security == "tls" && tls != null) {
            if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
            tls.alpn?.takeIf { it.isNotEmpty() }?.let {
                params.add("alpn=${urlEncode(it.joinToString(","))}")
            }
            if (tls.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${tls.fingerprint.raw}")
        }

        appendTransportParams(params)

        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        val fragment = urlEncode(name)
        return "ss://$encoded@$serverAddress:$serverPort/$query#$fragment"
    }

    private fun toNaiveUrl(): String {
        val user = urlEncode(naiveUsername ?: "")
        val pass = urlEncode(naivePassword ?: "")
        val fragment = urlEncode(name)
        return "https://$user:$pass@$serverAddress:$serverPort#$fragment"
    }

    private fun toQuicUrl(): String {
        val user = urlEncode(naiveUsername ?: "")
        val pass = urlEncode(naivePassword ?: "")
        val fragment = urlEncode(name)
        return "quic://$user:$pass@$serverAddress:$serverPort#$fragment"
    }

    private fun appendTransportParams(params: MutableList<String>) {
        if (transport == "ws" && websocket != null) {
            if (websocket.host != serverAddress) params.add("host=${websocket.host}")
            if (websocket.path != "/") params.add("path=${urlEncode(websocket.path)}")
            if (websocket.maxEarlyData > 0) params.add("ed=${websocket.maxEarlyData}")
        }
        if (transport == "httpupgrade" && httpUpgrade != null) {
            if (httpUpgrade.host != serverAddress) params.add("host=${httpUpgrade.host}")
            if (httpUpgrade.path != "/") params.add("path=${urlEncode(httpUpgrade.path)}")
        }
        if (transport == "xhttp" && xhttp != null) {
            if (xhttp.host != serverAddress) params.add("host=${xhttp.host}")
            if (xhttp.path != "/") params.add("path=${urlEncode(xhttp.path)}")
            if (xhttp.mode != XHttpMode.AUTO) params.add("mode=${xhttp.mode.raw}")
        }
    }

    // =========================================================================
    // URL Parsing
    // =========================================================================

    companion object {
        fun fromUrl(url: String, naiveProtocol: OutboundProtocol? = null): ProxyConfiguration = when {
            url.startsWith("ss://") -> fromShadowsocksUrl(url)
            url.startsWith("https://") || url.startsWith("naive+https://") -> fromNaiveUrl(url, naiveProtocol)
            url.startsWith("quic://") -> fromQuicUrl(url)
            url.startsWith("vless://") -> fromVlessUrl(url)
            else -> throw ProxyError.InvalidUrl("URL must start with vless://, ss://, https://, or quic://")
        }

        private fun fromVlessUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("vless://")

            // Extract fragment (#name)
            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = URLDecoder.decode(remaining.substring(hashIndex + 1), "UTF-8")
                remaining = remaining.substring(0, hashIndex)
            }

            // Split by @ to get UUID and server info
            val atIndex = remaining.indexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator")

            val uuidString = remaining.substring(0, atIndex)
            val serverPart = remaining.substring(atIndex + 1)

            val uuid = runCatching { UUID.fromString(uuidString) }.getOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid UUID: $uuidString")

            // Separate host:port from query string
            val hostPort: String
            var queryString: String? = null
            val questionIndex = serverPart.indexOf('?')
            if (questionIndex >= 0) {
                val before = serverPart.substring(0, questionIndex)
                hostPort = if (before.endsWith("/")) before.dropLast(1) else before
                queryString = serverPart.substring(questionIndex + 1)
            } else {
                val slashIndex = serverPart.indexOf('/')
                hostPort = if (slashIndex >= 0) serverPart.substring(0, slashIndex) else serverPart
            }

            // Parse host:port (handles IPv6 bracket notation: [::1]:443)
            val (host, port) = parseHostPort(hostPort)

            // Parse query parameters
            val params = parseQueryParams(queryString)

            val encryption = params["encryption"] ?: "none"
            val flow = params["flow"]
            val security = params["security"] ?: "none"
            val transport = params["type"] ?: "tcp"

            // Parse testseed
            var testseed: List<UInt>? = null
            params["testseed"]?.let { str ->
                val values = str.split(",").mapNotNull { it.toUIntOrNull() }
                if (values.size >= 4) testseed = values.take(4)
            }

            // Parse sub-configs
            val realityConfig = if (security == "reality") RealityConfiguration.parse(params) else null
            val tlsConfig = if (security == "tls") TlsConfiguration.parse(params, host) else null
            val wsConfig = if (transport == "ws") WebSocketConfiguration.parse(params, host) else null
            val httpUpgradeConfig = if (transport == "httpupgrade") HttpUpgradeConfiguration.parse(params, host) else null
            val xhttpConfig = if (transport == "xhttp") XHttpConfiguration.parse(params, host) else null

            val muxEnabled = params["mux"]?.let { it != "false" && it != "0" } ?: true
            val xudpEnabled = params["xudp"]?.let { it != "false" && it != "0" } ?: true

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = uuid,
                encryption = encryption,
                transport = transport,
                flow = flow,
                security = security,
                tls = tlsConfig,
                reality = realityConfig,
                websocket = wsConfig,
                httpUpgrade = httpUpgradeConfig,
                xhttp = xhttpConfig,
                testseed = testseed ?: listOf(900u, 500u, 900u, 256u),
                muxEnabled = muxEnabled,
                xudpEnabled = xudpEnabled
            )
        }

        private fun fromShadowsocksUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("ss://")

            // Extract fragment (#name)
            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = URLDecoder.decode(remaining.substring(hashIndex + 1), "UTF-8")
                remaining = remaining.substring(0, hashIndex)
            }

            val method: String
            val password: String
            val host: String
            val port: UShort
            var queryString: String? = null

            val atIndex = remaining.indexOf('@')
            if (atIndex >= 0) {
                // Standard format: base64(method:password)@host:port/?params
                val userInfo = remaining.substring(0, atIndex)
                var serverPart = remaining.substring(atIndex + 1)

                // Extract query string
                val questionIndex = serverPart.indexOf('?')
                if (questionIndex >= 0) {
                    queryString = serverPart.substring(questionIndex + 1)
                    serverPart = serverPart.substring(0, questionIndex)
                }
                // Strip trailing path
                val slashIndex = serverPart.indexOf('/')
                if (slashIndex >= 0) {
                    serverPart = serverPart.substring(0, slashIndex)
                }

                // Decode base64 user info
                val decoded = try {
                    String(java.util.Base64.getDecoder().decode(padBase64(userInfo)))
                } catch (_: Exception) {
                    throw ProxyError.InvalidUrl("Invalid SS user info encoding")
                }
                val colonIndex = decoded.indexOf(':')
                if (colonIndex < 0) throw ProxyError.InvalidUrl("Invalid SS user info format")
                method = decoded.substring(0, colonIndex)
                password = decoded.substring(colonIndex + 1)

                val (h, p) = parseHostPort(serverPart)
                host = h
                port = p
            } else {
                // SIP002 format: base64(method:password@host:port)
                val decoded = try {
                    String(java.util.Base64.getDecoder().decode(padBase64(remaining)))
                } catch (_: Exception) {
                    throw ProxyError.InvalidUrl("Invalid SS URL encoding")
                }
                val colonIndex = decoded.indexOf(':')
                if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing method:password separator")
                method = decoded.substring(0, colonIndex)
                val rest = decoded.substring(colonIndex + 1)
                val lastAtIndex = rest.lastIndexOf('@')
                if (lastAtIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in decoded SS URL")
                password = rest.substring(0, lastAtIndex)
                val serverPart = rest.substring(lastAtIndex + 1)
                val (h, p) = parseHostPort(serverPart)
                host = h
                port = p
            }

            val params = parseQueryParams(queryString)
            val transport = params["type"] ?: "tcp"
            val security = params["security"] ?: "none"

            var tlsConfig: TlsConfiguration? = null
            if (security == "tls") {
                tlsConfig = TlsConfiguration.parse(params, host)
            }

            val wsConfig = if (transport == "ws") WebSocketConfiguration.parse(params, host) else null
            val httpUpgradeConfig = if (transport == "httpupgrade") HttpUpgradeConfiguration.parse(params, host) else null
            val xhttpConfig = if (transport == "xhttp") XHttpConfiguration.parse(params, host) else null

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for SS
                encryption = "none",
                transport = transport,
                security = security,
                tls = tlsConfig,
                websocket = wsConfig,
                httpUpgrade = httpUpgradeConfig,
                xhttp = xhttpConfig,
                outboundProtocol = OutboundProtocol.SHADOWSOCKS,
                ssPassword = password,
                ssMethod = method
            )
        }

        private fun fromNaiveUrl(url: String, protocolOverride: OutboundProtocol? = null): ProxyConfiguration {
            var remaining = when {
                url.startsWith("naive+https://") -> url.removePrefix("naive+https://")
                url.startsWith("https://") -> url.removePrefix("https://")
                else -> throw ProxyError.InvalidUrl("Naive URL must start with https://")
            }

            // Extract fragment (#name)
            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = URLDecoder.decode(remaining.substring(hashIndex + 1), "UTF-8")
                remaining = remaining.substring(0, hashIndex)
            }

            // Split user:pass@host:port
            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in naive URL")

            val userInfo = remaining.substring(0, atIndex)
            var serverPart = remaining.substring(atIndex + 1)

            // Strip trailing path/query
            val slashIndex = serverPart.indexOf('/')
            if (slashIndex >= 0) {
                serverPart = serverPart.substring(0, slashIndex)
            }

            // Parse user:pass
            val colonIndex = userInfo.indexOf(':')
            if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing password in naive URL (expected user:pass)")
            val username = URLDecoder.decode(userInfo.substring(0, colonIndex), "UTF-8")
            val password = URLDecoder.decode(userInfo.substring(colonIndex + 1), "UTF-8")

            // Parse host:port
            val (host, port) = parseHostPort(serverPart)

            val proto = protocolOverride ?: OutboundProtocol.NAIVE_HTTP2
            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for naive
                encryption = "none",
                outboundProtocol = proto,
                naiveUsername = username,
                naivePassword = password,
                naiveProtocol = if (proto == OutboundProtocol.NAIVE_HTTP11) NaiveProtocol.HTTP11 else NaiveProtocol.HTTP2
            )
        }

        private fun fromQuicUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("quic://")

            // Extract fragment (#name)
            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = URLDecoder.decode(remaining.substring(hashIndex + 1), "UTF-8")
                remaining = remaining.substring(0, hashIndex)
            }

            // Split user:pass@host:port
            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in quic URL")

            val userInfo = remaining.substring(0, atIndex)
            var serverPart = remaining.substring(atIndex + 1)

            // Strip trailing path/query
            val slashIndex = serverPart.indexOf('/')
            if (slashIndex >= 0) {
                serverPart = serverPart.substring(0, slashIndex)
            }

            // Parse user:pass
            val colonIndex = userInfo.indexOf(':')
            if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing password in quic URL (expected user:pass)")
            val username = URLDecoder.decode(userInfo.substring(0, colonIndex), "UTF-8")
            val password = URLDecoder.decode(userInfo.substring(colonIndex + 1), "UTF-8")

            // Parse host:port
            val (host, port) = parseHostPort(serverPart)

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for QUIC
                encryption = "none",
                outboundProtocol = OutboundProtocol.NAIVE_HTTP3,
                naiveUsername = username,
                naivePassword = password,
                naiveProtocol = NaiveProtocol.HTTP2 // placeholder
            )
        }

        // =====================================================================
        // Parsing Helpers
        // =====================================================================

        private fun parseQueryParams(queryString: String?): Map<String, String> {
            if (queryString == null) return emptyMap()
            val params = mutableMapOf<String, String>()
            queryString.split("&").forEach { param ->
                val kv = param.split("=", limit = 2)
                if (kv.size == 2) {
                    params[kv[0]] = URLDecoder.decode(kv[1], "UTF-8")
                }
            }
            return params
        }

        private fun parseHostPort(hostPort: String): Pair<String, UShort> {
            val host: String
            val portString: String
            if (hostPort.startsWith("[")) {
                val closeBracket = hostPort.indexOf(']')
                if (closeBracket < 0) throw ProxyError.InvalidUrl("Missing closing bracket for IPv6 address")
                host = hostPort.substring(1, closeBracket)
                val afterBracket = hostPort.substring(closeBracket + 1)
                if (!afterBracket.startsWith(":")) throw ProxyError.InvalidUrl("Missing port after IPv6 address")
                portString = afterBracket.removePrefix(":")
            } else {
                val colonIndex = hostPort.lastIndexOf(':')
                if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing port in server address")
                host = hostPort.substring(0, colonIndex)
                portString = hostPort.substring(colonIndex + 1)
            }
            val port = portString.toUShortOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid port: $portString")
            return Pair(host, port)
        }

        private fun padBase64(str: String): String {
            val remainder = str.length % 4
            if (remainder == 0) return str
            return str + "=".repeat(4 - remainder)
        }

        private fun urlEncode(value: String): String =
            URLEncoder.encode(value, "UTF-8")
    }
}

// =============================================================================
// Proxy Errors
// =============================================================================

sealed class ProxyError(message: String) : Exception(message) {
    class InvalidUrl(message: String) : ProxyError("Invalid URL: $message")
    class ConnectionFailed(message: String) : ProxyError("Connection failed: $message")
    class ProtocolError(message: String) : ProxyError("Protocol error: $message")
    class InvalidResponse(message: String) : ProxyError("Invalid response: $message")
    class Dropped : ProxyError("Dropped")
}
