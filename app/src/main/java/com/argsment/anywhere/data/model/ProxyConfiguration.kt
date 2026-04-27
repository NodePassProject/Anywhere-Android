package com.argsment.anywhere.data.model

import com.argsment.anywhere.vpn.util.base64UrlToByteArrayOrNull
import com.argsment.anywhere.vpn.util.hexToByteArrayOrNull
import com.argsment.anywhere.vpn.util.toBase64Url
import com.argsment.anywhere.vpn.util.toHex
import com.argsment.anywhere.vpn.protocol.shadowsocks.ShadowsocksCipher
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.UUID
import org.json.JSONObject

/**
 * Percent-decodes [s]: only `%XX` hex escapes are decoded; `+` stays literal
 * (unlike `URLDecoder.decode`, which treats `+` as a space per form-url-encoded
 * rules). VLESS/WebSocket share links follow standard URL percent-encoding, not
 * form encoding — a path like `/?ed=2048+xray` must stay byte-identical,
 * otherwise the HTTP upgrade request path differs for the same share link.
 */
internal fun percentDecode(s: String): String =
    URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")

@Serializable
enum class TlsFingerprint(val raw: String) {
    @SerialName("chrome_133") CHROME_133("chrome_133"),
    @SerialName("firefox_148") FIREFOX_148("firefox_148"),
    @SerialName("safari_26") SAFARI_26("safari_26"),
    @SerialName("ios_14") IOS_14("ios_14"),
    @SerialName("edge_85") EDGE_85("edge_85"),
    @SerialName("android_11") ANDROID_11("android_11"),
    @SerialName("qq_11") QQ_11("qq_11"),
    @SerialName("360_7") BROWSER_360("360_7"),
    @SerialName("chrome_120") CHROME_120("chrome_120"),
    @SerialName("firefox_120") FIREFOX_120("firefox_120"),
    @SerialName("safari_16") SAFARI_16("safari_16"),
    @SerialName("edge_106") EDGE_106("edge_106"),
    @SerialName("random") RANDOM("random");

    val displayName: String
        get() = when (this) {
            CHROME_133 -> "Chrome 133"
            FIREFOX_148 -> "Firefox 148"
            SAFARI_26 -> "Safari 26"
            IOS_14 -> "iOS 14"
            EDGE_85 -> "Edge 85"
            ANDROID_11 -> "Android 11"
            QQ_11 -> "QQ 11"
            BROWSER_360 -> "360 Browser"
            CHROME_120 -> "Chrome 120"
            FIREFOX_120 -> "Firefox 120"
            SAFARI_16 -> "Safari 16"
            EDGE_106 -> "Edge 106"
            RANDOM -> "Random"
        }

    companion object {
        fun fromRaw(value: String): TlsFingerprint =
            entries.find { it.raw == value } ?: CHROME_133

        /**
         * Pool used when the user picks "Random". Android-only fingerprints
         * (ANDROID_11, QQ_11, BROWSER_360) are kept in the enum for backward
         * compatibility with previously imported share links but excluded from
         * the random pool.
         */
        val concreteFingerprints: List<TlsFingerprint> = entries.filter {
            it != RANDOM && it != ANDROID_11 && it != QQ_11 && it != BROWSER_360
        }

        /**
         * Picker entries for [com.argsment.anywhere.ui.proxy.ProxyEditorScreen].
         * Excludes Android-only fingerprints from the dropdown, but `fromRaw`
         * still resolves them when imported from URLs.
         */
        val pickerFingerprints: List<TlsFingerprint> = entries.filter {
            it != ANDROID_11 && it != QQ_11 && it != BROWSER_360
        }
    }
}

/**
 * Negotiated TLS protocol version. The numeric `value` matches the on-the-wire
 * protocol version field (RFC 5246/RFC 8446).
 */
@Serializable
enum class TlsVersion(val value: Int) {
    @SerialName("tls12") TLS12(0x0303),
    @SerialName("tls13") TLS13(0x0304);

    val displayName: String
        get() = when (this) {
            TLS12 -> "TLS 1.2"
            TLS13 -> "TLS 1.3"
        }

    /** Wire-compatible version string for URL query params (e.g. "1.2", "1.3"). */
    val urlValue: String
        get() = when (this) {
            TLS12 -> "1.2"
            TLS13 -> "1.3"
        }
}

@Serializable
data class TlsConfiguration(
    val serverName: String,
    val alpn: List<String>? = null,
    val allowInsecure: Boolean = false,
    val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133,
    /** Minimum acceptable TLS version (null = no minimum, accept any). */
    val minVersion: TlsVersion? = null,
    /** Maximum acceptable TLS version (null = no maximum, accept any). */
    val maxVersion: TlsVersion? = null
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): TlsConfiguration? {
            if (params["security"] != "tls") return null
            val sni = params["sni"] ?: serverAddress
            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val allowInsecure = params["allowInsecure"] == "1" || params["allowInsecure"] == "true"
            val fp = params["fp"] ?: "chrome_133"
            val minVersion = parseTlsVersion(params["minVersion"])
            val maxVersion = parseTlsVersion(params["maxVersion"])
            return TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                allowInsecure = allowInsecure,
                fingerprint = TlsFingerprint.fromRaw(fp),
                minVersion = minVersion,
                maxVersion = maxVersion
            )
        }

        /** Parses a TLS version string ("1.0"–"1.3") into a [TlsVersion].
         *  "1.0" and "1.1" are legacy; treated as TLS 1.2 since Android does not implement deprecated versions. */
        private fun parseTlsVersion(version: String?): TlsVersion? = when (version) {
            "1.0", "1.1", "1.2" -> TlsVersion.TLS12
            "1.3" -> TlsVersion.TLS13
            else -> null
        }
    }
}

@Serializable
data class RealityConfiguration(
    val serverName: String,
    @Serializable(with = Base64UrlByteArraySerializer::class) val publicKey: ByteArray,
    @Serializable(with = HexByteArraySerializer::class) val shortId: ByteArray,
    val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133
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
            val fp = params["fp"] ?: "chrome_133"
            return RealityConfiguration(
                serverName = sni,
                publicKey = publicKey,
                shortId = shortId,
                fingerprint = TlsFingerprint.fromRaw(fp)
            )
        }
    }
}

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
            val path = params["path"]?.let { percentDecode(it) } ?: "/"
            val maxEarlyData = params["ed"]?.toIntOrNull() ?: 0
            return WebSocketConfiguration(host = host, path = path, maxEarlyData = maxEarlyData)
        }
    }
}

@Serializable
data class HttpUpgradeConfiguration(
    val host: String,
    val path: String = "/",
    val headers: Map<String, String> = emptyMap()
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): HttpUpgradeConfiguration {
            val host = params["host"] ?: serverAddress
            var path = params["path"]?.let { percentDecode(it) } ?: "/"
            if (!path.startsWith("/")) path = "/$path"
            return HttpUpgradeConfiguration(host = host, path = path)
        }
    }
}

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

/** Metadata placement for session ID, sequence numbers, and padding. */
@Serializable
enum class XHttpPlacement(val raw: String) {
    @SerialName("path") PATH("path"),
    @SerialName("query") QUERY("query"),
    @SerialName("header") HEADER("header"),
    @SerialName("cookie") COOKIE("cookie"),
    @SerialName("queryInHeader") QUERY_IN_HEADER("queryInHeader"),
    @SerialName("body") BODY("body");

    companion object {
        fun fromRaw(value: String): XHttpPlacement =
            entries.find { it.raw == value } ?: QUERY_IN_HEADER
    }
}

/** X-Padding generation method. */
@Serializable
enum class XHttpPaddingMethod(val raw: String) {
    @SerialName("repeat-x") REPEAT_X("repeat-x"),
    @SerialName("tokenish") TOKENISH("tokenish");

    companion object {
        fun fromRaw(value: String): XHttpPaddingMethod =
            entries.find { it.raw == value } ?: REPEAT_X
    }
}

@Serializable
data class XHttpConfiguration(
    val host: String,
    val path: String = "/",
    val mode: XHttpMode = XHttpMode.AUTO,
    val headers: Map<String, String> = emptyMap(),
    @SerialName("noGRPCHeader") val noGrpcHeader: Boolean = false,
    val scMaxEachPostBytes: Int = 1_000_000,
    val scMinPostsIntervalMs: Int = 30,
    val xPaddingBytesFrom: Int = 100,
    val xPaddingBytesTo: Int = 1000,
    val xPaddingObfsMode: Boolean = false,
    val xPaddingKey: String = "x_padding",
    val xPaddingHeader: String = "X-Padding",
    val xPaddingPlacement: XHttpPlacement = XHttpPlacement.QUERY_IN_HEADER,
    val xPaddingMethod: XHttpPaddingMethod = XHttpPaddingMethod.REPEAT_X,
    val uplinkHTTPMethod: String = "POST",
    val sessionPlacement: XHttpPlacement = XHttpPlacement.PATH,
    val sessionKey: String = "",
    val seqPlacement: XHttpPlacement = XHttpPlacement.PATH,
    val seqKey: String = "",
    val uplinkDataPlacement: XHttpPlacement = XHttpPlacement.BODY,
    val uplinkDataKey: String = "",
    val uplinkChunkSize: Int = 0
) {
    val normalizedPath: String
        get() {
            val pathOnly = path.split("?", limit = 2).first()
            var p = pathOnly
            if (!p.startsWith("/")) p = "/$p"
            if (!p.endsWith("/")) p = "$p/"
            return p
        }

    val normalizedQuery: String
        get() {
            val parts = path.split("?", limit = 2)
            return if (parts.size > 1) parts[1] else ""
        }

    /** Normalized session key, auto-determined by placement if not set. */
    val normalizedSessionKey: String
        get() {
            if (sessionKey.isNotEmpty()) return sessionKey
            return when (sessionPlacement) {
                XHttpPlacement.HEADER -> "X-Session"
                XHttpPlacement.COOKIE, XHttpPlacement.QUERY -> "x_session"
                else -> ""
            }
        }

    /** Normalized seq key, auto-determined by placement if not set. */
    val normalizedSeqKey: String
        get() {
            if (seqKey.isNotEmpty()) return seqKey
            return when (seqPlacement) {
                XHttpPlacement.HEADER -> "X-Seq"
                XHttpPlacement.COOKIE, XHttpPlacement.QUERY -> "x_seq"
                else -> ""
            }
        }

    fun generatePadding(): String {
        val length = (xPaddingBytesFrom..xPaddingBytesTo).random()
        return when (xPaddingMethod) {
            XHttpPaddingMethod.REPEAT_X -> "X".repeat(length)
            XHttpPaddingMethod.TOKENISH -> generateTokenishPadding(length)
        }
    }

    fun toExtraJson(): String {
        val parts = mutableListOf<String>()
        if (noGrpcHeader) parts.add("\"noGRPCHeader\":true")
        if (scMaxEachPostBytes != 1_000_000) parts.add("\"scMaxEachPostBytes\":$scMaxEachPostBytes")
        if (scMinPostsIntervalMs != 30) parts.add("\"scMinPostsIntervalMs\":$scMinPostsIntervalMs")
        if (xPaddingBytesFrom != 100) parts.add("\"xPaddingBytesFrom\":$xPaddingBytesFrom")
        if (xPaddingBytesTo != 1000) parts.add("\"xPaddingBytesTo\":$xPaddingBytesTo")
        if (xPaddingObfsMode) parts.add("\"xPaddingObfsMode\":true")
        if (xPaddingKey != "x_padding") parts.add("\"xPaddingKey\":\"$xPaddingKey\"")
        if (xPaddingHeader != "X-Padding") parts.add("\"xPaddingHeader\":\"$xPaddingHeader\"")
        if (xPaddingPlacement != XHttpPlacement.QUERY_IN_HEADER) parts.add("\"xPaddingPlacement\":\"${xPaddingPlacement.raw}\"")
        if (xPaddingMethod != XHttpPaddingMethod.REPEAT_X) parts.add("\"xPaddingMethod\":\"${xPaddingMethod.raw}\"")
        if (uplinkHTTPMethod != "POST") parts.add("\"uplinkHTTPMethod\":\"$uplinkHTTPMethod\"")
        if (sessionPlacement != XHttpPlacement.PATH) parts.add("\"sessionPlacement\":\"${sessionPlacement.raw}\"")
        if (sessionKey.isNotEmpty()) parts.add("\"sessionKey\":\"$sessionKey\"")
        if (seqPlacement != XHttpPlacement.PATH) parts.add("\"seqPlacement\":\"${seqPlacement.raw}\"")
        if (seqKey.isNotEmpty()) parts.add("\"seqKey\":\"$seqKey\"")
        if (uplinkDataPlacement != XHttpPlacement.BODY) parts.add("\"uplinkDataPlacement\":\"${uplinkDataPlacement.raw}\"")
        if (uplinkDataKey.isNotEmpty()) parts.add("\"uplinkDataKey\":\"$uplinkDataKey\"")
        if (uplinkChunkSize != 0) parts.add("\"uplinkChunkSize\":$uplinkChunkSize")
        if (headers.isNotEmpty()) {
            val headersJson = headers.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }
            parts.add("\"headers\":{$headersJson}")
        }
        return if (parts.isEmpty()) "" else "{${parts.joinToString(",")}}"
    }

    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): XHttpConfiguration {
            val host = params["host"] ?: serverAddress
            val path = params["path"]?.let { percentDecode(it) } ?: "/"
            val mode = XHttpMode.fromRaw(params["mode"] ?: "auto")
            val extra = params["extra"] ?: ""
            return if (extra.isNotBlank()) {
                fromExtraJson(host, path, mode, extra)
            } else {
                XHttpConfiguration(host = host, path = path, mode = mode)
            }
        }

        fun fromExtraJson(host: String, path: String, mode: XHttpMode, extraJson: String): XHttpConfiguration {
            if (extraJson.isBlank()) return XHttpConfiguration(host = host, path = path, mode = mode)
            return try {
                val json = org.json.JSONObject(extraJson)

                // scMaxEachPostBytes: can be int or {"from":N,"to":N}
                val scMaxEachPostBytes = json.opt("scMaxEachPostBytes").let { v ->
                    when (v) {
                        is org.json.JSONObject -> v.optInt("to", 1_000_000)
                        is Number -> v.toInt()
                        else -> 1_000_000
                    }
                }

                // scMinPostsIntervalMs: can be int or {"from":N,"to":N}
                val scMinPostsIntervalMs = json.opt("scMinPostsIntervalMs").let { v ->
                    when (v) {
                        is org.json.JSONObject -> v.optInt("to", 30)
                        is Number -> v.toInt()
                        else -> 30
                    }
                }

                // xPaddingBytes: can be int or {"from":N,"to":N}
                var xPaddingFrom = 100
                var xPaddingTo = 1000
                json.opt("xPaddingBytes")?.let { v ->
                    when (v) {
                        is org.json.JSONObject -> {
                            xPaddingFrom = v.optInt("from", 100)
                            xPaddingTo = v.optInt("to", 1000)
                        }
                        is Number -> {
                            xPaddingFrom = v.toInt()
                            xPaddingTo = v.toInt()
                        }
                    }
                }
                // Also accept flat xPaddingBytesFrom/xPaddingBytesTo keys
                if (!json.has("xPaddingBytes")) {
                    xPaddingFrom = json.optInt("xPaddingBytesFrom", xPaddingFrom)
                    xPaddingTo = json.optInt("xPaddingBytesTo", xPaddingTo)
                }

                val uplinkDataPlacement = XHttpPlacement.fromRaw(json.optString("uplinkDataPlacement", "body"))
                val defaultUplinkDataKey = when (uplinkDataPlacement) {
                    XHttpPlacement.HEADER -> "X-Data"
                    XHttpPlacement.COOKIE -> "x_data"
                    else -> ""
                }
                val defaultUplinkChunkSize = when (uplinkDataPlacement) {
                    XHttpPlacement.HEADER -> 4096
                    XHttpPlacement.COOKIE -> 3072
                    else -> 0
                }

                XHttpConfiguration(
                    host = host, path = path, mode = mode,
                    headers = json.optJSONObject("headers")?.let { h ->
                        h.keys().asSequence().associateWith { k -> h.optString(k, "") }
                    } ?: emptyMap(),
                    noGrpcHeader = json.optBoolean("noGRPCHeader", false),
                    scMaxEachPostBytes = scMaxEachPostBytes,
                    scMinPostsIntervalMs = scMinPostsIntervalMs,
                    xPaddingBytesFrom = xPaddingFrom,
                    xPaddingBytesTo = xPaddingTo,
                    xPaddingObfsMode = json.optBoolean("xPaddingObfsMode", false),
                    xPaddingKey = json.optString("xPaddingKey", "x_padding"),
                    xPaddingHeader = json.optString("xPaddingHeader", "X-Padding"),
                    xPaddingPlacement = XHttpPlacement.fromRaw(json.optString("xPaddingPlacement", "queryInHeader")),
                    xPaddingMethod = XHttpPaddingMethod.fromRaw(json.optString("xPaddingMethod", "repeat-x")),
                    uplinkHTTPMethod = json.optString("uplinkHTTPMethod", "POST"),
                    sessionPlacement = XHttpPlacement.fromRaw(json.optString("sessionPlacement", "path")),
                    sessionKey = json.optString("sessionKey", ""),
                    seqPlacement = XHttpPlacement.fromRaw(json.optString("seqPlacement", "path")),
                    seqKey = json.optString("seqKey", ""),
                    uplinkDataPlacement = uplinkDataPlacement,
                    uplinkDataKey = json.optString("uplinkDataKey", defaultUplinkDataKey),
                    uplinkChunkSize = json.optInt("uplinkChunkSize", defaultUplinkChunkSize)
                )
            } catch (_: Exception) {
                XHttpConfiguration(host = host, path = path, mode = mode)
            }
        }

        private val tokenishChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

        /**
         * Generates pseudo-random alphanumeric padding that looks like a token.
         * Target Huffman byte length: ceil(length / 0.8) to compensate for
         * HTTP/2 Huffman compression.
         */
        fun generateTokenishPadding(length: Int): String {
            val charCount = kotlin.math.ceil(length / 0.8).toInt()
            val sb = StringBuilder(charCount)
            val random = java.security.SecureRandom()
            for (i in 0 until charCount) {
                sb.append(tokenishChars[random.nextInt(tokenishChars.length)])
            }
            return sb.toString()
        }
    }
}

object UuidSerializer : KSerializer<UUID> {
    override val descriptor = PrimitiveSerialDescriptor("UUID", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: UUID) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder): UUID = UUID.fromString(decoder.decodeString())
}

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

@Serializable(with = OutboundProtocolSerializer::class)
enum class OutboundProtocol(val raw: String) {
    VLESS("vless"),
    TROJAN("trojan"),
    SHADOWSOCKS("shadowsocks"),
    SOCKS5("socks5"),
    NAIVE_HTTP11("http11"),
    NAIVE_HTTP2("http2");

    val isNaive: Boolean get() = this == NAIVE_HTTP11 || this == NAIVE_HTTP2
    val displayName: String
        get() = when (this) {
            VLESS -> "VLESS"
            TROJAN -> "Trojan"
            SHADOWSOCKS -> "Shadowsocks"
            SOCKS5 -> "SOCKS5"
            NAIVE_HTTP11 -> "HTTPS"
            NAIVE_HTTP2 -> "HTTP/2"
        }

    /**
     * Whether this protocol can embed the caller's first bytes inside its
     * outbound handshake. Only VLESS does — every other protocol opens the
     * tunnel first and the LWIP layer must forward the buffered first bytes
     * via a separate `connection.send` after connect (and ACK them back to
     * lwIP via `nativeTcpRecved`).
     *
     * Getting this wrong silently swallows the caller's first bytes for
     * non-VLESS protocols — the bytes are sent over the wire but lwIP never
     * ACKs them back to the local app, the app times out and sends RST.
     */
    val handshakeCarriesInitialData: Boolean
        get() = this == VLESS
}

object OutboundProtocolSerializer : KSerializer<OutboundProtocol> {
    override val descriptor = PrimitiveSerialDescriptor("OutboundProtocol", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: OutboundProtocol) {
        encoder.encodeString(value.raw)
    }

    override fun deserialize(decoder: Decoder): OutboundProtocol {
        val raw = decoder.decodeString()
        return when (raw) {
            "vless" -> OutboundProtocol.VLESS
            "trojan" -> OutboundProtocol.TROJAN
            "shadowsocks" -> OutboundProtocol.SHADOWSOCKS
            "socks5" -> OutboundProtocol.SOCKS5
            "http11", "naive_http11" -> OutboundProtocol.NAIVE_HTTP11
            "http2", "naive_http2" -> OutboundProtocol.NAIVE_HTTP2
            else -> throw SerializationException("Unknown outbound protocol: $raw")
        }
    }
}

@Serializable
enum class NaiveProtocol {
    @SerialName("http11") HTTP11,
    @SerialName("http2") HTTP2
}

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
    val grpc: com.argsment.anywhere.vpn.protocol.grpc.GrpcConfiguration? = null,
    val testseed: List<UInt> = listOf(900u, 500u, 900u, 256u),
    val muxEnabled: Boolean = true,
    val xudpEnabled: Boolean = true,
    @Serializable(with = UuidSerializer::class) val subscriptionId: UUID? = null,
    val outboundProtocol: OutboundProtocol = OutboundProtocol.VLESS,
    val ssPassword: String? = null,
    val ssMethod: String? = null,
    val socks5Username: String? = null,
    val socks5Password: String? = null,
    val naiveUsername: String? = null,
    val naivePassword: String? = null,
    val naiveProtocol: NaiveProtocol? = null,
    val trojanPassword: String? = null,
    /** Trojan's mandatory TLS configuration. */
    val trojanTls: TlsConfiguration? = null,
    val chain: List<ProxyConfiguration>? = null
) {
    val connectAddress: String get() = resolvedIP ?: serverAddress

    /** RFC 3986 §3.2.2: IPv6 literals must be bracketed in URL authority components. */
    private val bracketedServerAddress: String
        get() = if (serverAddress.contains(":")) "[$serverAddress]" else serverAddress

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
                grpc == other.grpc &&
                testseed == other.testseed &&
                muxEnabled == other.muxEnabled &&
                xudpEnabled == other.xudpEnabled &&
                outboundProtocol == other.outboundProtocol &&
                ssPassword == other.ssPassword &&
                ssMethod == other.ssMethod &&
                socks5Username == other.socks5Username &&
                socks5Password == other.socks5Password &&
                naiveUsername == other.naiveUsername &&
                naivePassword == other.naivePassword &&
                naiveProtocol == other.naiveProtocol &&
                trojanPassword == other.trojanPassword &&
                trojanTls == other.trojanTls &&
                chain == other.chain

    fun withChain(chain: List<ProxyConfiguration>?): ProxyConfiguration = copy(chain = chain)

    fun toUrl(): String = when (outboundProtocol) {
        OutboundProtocol.VLESS -> toVlessUrl()
        OutboundProtocol.TROJAN -> toTrojanUrl()
        OutboundProtocol.SHADOWSOCKS -> toShadowsocksUrl()
        OutboundProtocol.SOCKS5 -> toSocks5Url()
        OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> toNaiveUrl()
    }

    private fun toTrojanUrl(): String {
        // Password in userinfo (whole chunk, no user:pass split), TLS
        // sni/alpn/fp optional in query.
        val password = urlEncode(trojanPassword ?: "")
        val params = mutableListOf<String>()
        trojanTls?.let { tls ->
            if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
            tls.alpn?.takeIf { it.isNotEmpty() }?.let {
                params.add("alpn=${urlEncode(it.joinToString(","))}")
            }
            if (tls.fingerprint != TlsFingerprint.CHROME_133) {
                params.add("fp=${tls.fingerprint.raw}")
            }
        }
        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        val fragment = urlEncode(name)
        return "trojan://$password@$bracketedServerAddress:$serverPort$query#$fragment"
    }

    private fun toVlessUrl(): String {
        val params = mutableListOf<String>()
        if (encryption != "none") params.add("encryption=$encryption")
        if (!flow.isNullOrEmpty()) params.add("flow=$flow")
        params.add("security=$security")
        if (transport != "tcp") params.add("type=$transport")

        if (security == "tls" && tls != null) {
            appendTlsParams(params, tls)
        }

        if (security == "reality" && reality != null) {
            params.add("sni=${reality.serverName}")
            params.add("pbk=${reality.publicKey.toBase64Url()}")
            if (reality.shortId.isNotEmpty()) params.add("sid=${reality.shortId.toHex()}")
            if (reality.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${reality.fingerprint.raw}")
        }

        appendTransportParams(params)
        if (!muxEnabled) params.add("mux=false")
        if (!xudpEnabled) params.add("xudp=false")
        // testseed is Android-only and not exported — iOS share-links never carry it,
        // and round-trip parity matters more than expressing the local override.

        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        val fragment = urlEncode(name)
        return "vless://${uuid.toString().lowercase()}@$bracketedServerAddress:$serverPort/$query#$fragment"
    }

    private fun toShadowsocksUrl(): String {
        // Plain `ss://base64(method:password)@host:port/#name` — no
        // transport/security params. Shadowsocks runs over bare TCP.
        val method = ssMethod ?: return "ss://invalid"
        val password = ssPassword ?: return "ss://invalid"
        val userInfo = "$method:$password"
        val encoded = java.util.Base64.getEncoder().encodeToString(userInfo.toByteArray())
            .trimEnd('=')
        val fragment = urlEncode(name)
        return "ss://$encoded@$bracketedServerAddress:$serverPort/#$fragment"
    }

    /**
     * Emits TLS query params (sni, alpn, fp, allowInsecure, minVersion, maxVersion).
     */
    private fun appendTlsParams(params: MutableList<String>, tls: TlsConfiguration) {
        if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
        tls.alpn?.takeIf { it.isNotEmpty() }?.let {
            params.add("alpn=${urlEncode(it.joinToString(","))}")
        }
        if (tls.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${tls.fingerprint.raw}")
        if (tls.allowInsecure) params.add("allowInsecure=1")
        tls.minVersion?.let { params.add("minVersion=${it.urlValue}") }
        tls.maxVersion?.let { params.add("maxVersion=${it.urlValue}") }
    }

    private fun toNaiveUrl(): String {
        val user = urlEncode(naiveUsername ?: "")
        val pass = urlEncode(naivePassword ?: "")
        val fragment = urlEncode(name)
        return "https://$user:$pass@$bracketedServerAddress:$serverPort#$fragment"
    }

    private fun toSocks5Url(): String {
        val fragment = urlEncode(name)
        val userInfo = if (!socks5Username.isNullOrEmpty()) {
            val user = urlEncode(socks5Username)
            val pass = urlEncode(socks5Password ?: "")
            "$user:$pass@"
        } else {
            ""
        }
        return "socks5://$userInfo$bracketedServerAddress:$serverPort#$fragment"
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
        if (transport == "grpc" && grpc != null) {
            if (grpc.serviceName.isNotEmpty()) params.add("serviceName=${urlEncode(grpc.serviceName)}")
            if (grpc.authority.isNotEmpty()) params.add("authority=${urlEncode(grpc.authority)}")
            if (grpc.multiMode) params.add("mode=multi")
        }
    }

    companion object {
        /** URL scheme prefixes [fromUrl] recognises. */
        val parsableUrlPrefixes = listOf(
            "vless://", "trojan://", "ss://",
            "socks5://", "socks://", "https://"
        )

        /** Whether [fromUrl] can parse [url]. */
        fun canParseUrl(url: String): Boolean =
            parsableUrlPrefixes.any { url.startsWith(it) }

        fun fromUrl(url: String, naiveProtocol: OutboundProtocol? = null): ProxyConfiguration = when {
            url.startsWith("ss://") -> fromShadowsocksUrl(url)
            url.startsWith("socks5://") || url.startsWith("socks://") -> fromSocks5Url(url)
            url.startsWith("https://") -> fromNaiveUrl(url, naiveProtocol)
            url.startsWith("vless://") -> fromVlessUrl(url)
            url.startsWith("trojan://") -> fromTrojanUrl(url)
            else -> throw ProxyError.InvalidUrl("URL must start with vless://, trojan://, ss://, socks5://, or https://")
        }

        /**
         * Parses a Trojan URL. Format:
         * `trojan://password@host:port?sni=...&alpn=h2%2Chttp%2F1.1&fp=chrome_133#name`
         * TLS is mandatory — there is no plaintext Trojan variant on the wire.
         */
        private fun fromTrojanUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("trojan://")

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            var queryString: String? = null
            val qIndex = remaining.indexOf('?')
            if (qIndex >= 0) {
                queryString = remaining.substring(qIndex + 1)
                remaining = remaining.substring(0, qIndex)
            }

            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in trojan URL")

            val userInfo = remaining.substring(0, atIndex)
            var serverPart = remaining.substring(atIndex + 1)
            if (serverPart.endsWith("/")) serverPart = serverPart.dropLast(1)
            val slashIdx = serverPart.indexOf('/')
            if (slashIdx >= 0) serverPart = serverPart.substring(0, slashIdx)

            // Whole userinfo is the password (trojan-gfw spec — no user:pass split).
            val password = percentDecode(userInfo)

            val (host, port) = parseHostPort(serverPart)
            val params = parseQueryParams(queryString)

            val sni = params["sni"]?.takeIf { it.isNotEmpty() }
                ?: params["peer"]?.takeIf { it.isNotEmpty() }
                ?: host

            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val fp = params["fp"] ?: "chrome_133"
            val tls = TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                fingerprint = TlsFingerprint.fromRaw(fp)
            )

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
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

        private fun fromVlessUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("vless://")

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator")

            val uuidString = remaining.substring(0, atIndex)
            val serverPart = remaining.substring(atIndex + 1)

            val uuid = runCatching { UUID.fromString(uuidString) }.getOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid UUID: $uuidString")

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

            val (host, port) = parseHostPort(hostPort)
            val params = parseQueryParams(queryString)

            val encryption = params["encryption"] ?: "none"
            val flow = params["flow"]
            val security = params["security"] ?: "none"
            val transport = params["type"] ?: "tcp"

            var testseed: List<UInt>? = null
            params["testseed"]?.let { str ->
                val values = str.split(",").mapNotNull { it.toUIntOrNull() }
                if (values.size >= 4) testseed = values.take(4)
            }

            val realityConfig = if (security == "reality") RealityConfiguration.parse(params) else null
            val tlsConfig = if (security == "tls") TlsConfiguration.parse(params, host) else null
            val wsConfig = if (transport == "ws") WebSocketConfiguration.parse(params, host) else null
            val httpUpgradeConfig = if (transport == "httpupgrade") HttpUpgradeConfiguration.parse(params, host) else null
            val xhttpConfig = if (transport == "xhttp") {
                // Fall back to TLS/Reality SNI for XHTTP host
                val xhttpHost = params["host"]
                    ?: tlsConfig?.serverName ?: realityConfig?.serverName ?: host
                XHttpConfiguration.parse(params + ("host" to xhttpHost), host)
            } else null
            val grpcConfig = if (transport == "grpc") {
                com.argsment.anywhere.vpn.protocol.grpc.GrpcConfiguration.parse(params)
            } else null

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
                grpc = grpcConfig,
                testseed = testseed ?: listOf(900u, 500u, 900u, 256u),
                muxEnabled = muxEnabled,
                xudpEnabled = xudpEnabled
            )
        }

        private fun fromShadowsocksUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("ss://")

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            val method: String
            val password: String
            val host: String
            val port: UShort

            val atIndex = remaining.indexOf('@')
            if (atIndex >= 0) {
                // SIP002 format: userinfo@host:port. The userinfo may be
                // either literal method:password or base64(method:password).
                val userInfo = remaining.substring(0, atIndex)
                var serverPart = remaining.substring(atIndex + 1)

                val questionIndex = serverPart.indexOf('?')
                if (questionIndex >= 0) {
                    serverPart = serverPart.substring(0, questionIndex)
                }
                val slashIndex = serverPart.indexOf('/')
                if (slashIndex >= 0) {
                    serverPart = serverPart.substring(0, slashIndex)
                }

                val parsed = decodeShadowsocksUserInfo(userInfo)
                method = parsed.first
                password = parsed.second

                val (h, p) = parseHostPort(serverPart)
                host = h
                port = p
            } else {
                // Legacy format: base64(method:password@host:port).
                val decoded = decodeBase64Text(remaining)
                    ?: throw ProxyError.InvalidUrl("Invalid SS URL encoding")
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

            if (ShadowsocksCipher.fromMethod(method) == null) {
                throw ProxyError.InvalidUrl("Unsupported SS method: $method")
            }

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for SS
                encryption = "none",
                transport = "tcp",
                security = "none",
                outboundProtocol = OutboundProtocol.SHADOWSOCKS,
                ssPassword = password,
                ssMethod = method
            )
        }

        private fun fromNaiveUrl(url: String, protocolOverride: OutboundProtocol? = null): ProxyConfiguration {
            var remaining = when {
                url.startsWith("https://") -> url.removePrefix("https://")
                else -> throw ProxyError.InvalidUrl("Naive URL must start with https://")
            }

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in naive URL")

            val userInfo = remaining.substring(0, atIndex)
            var serverPart = remaining.substring(atIndex + 1)

            val slashIndex = serverPart.indexOf('/')
            if (slashIndex >= 0) {
                serverPart = serverPart.substring(0, slashIndex)
            }

            val colonIndex = userInfo.indexOf(':')
            if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing password in naive URL (expected user:pass)")
            val username = percentDecode(userInfo.substring(0, colonIndex))
            val password = percentDecode(userInfo.substring(colonIndex + 1))

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

        /**
         * Parse a SOCKS5 URL into configuration.
         * Format: socks5://user:pass@host:port#name  or  socks5://host:port#name
         */
        private fun fromSocks5Url(url: String): ProxyConfiguration {
            var remaining = when {
                url.startsWith("socks5://") -> url.removePrefix("socks5://")
                url.startsWith("socks://") -> url.removePrefix("socks://")
                else -> throw ProxyError.InvalidUrl("SOCKS5 URL must start with socks5:// or socks://")
            }

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            var username: String? = null
            var password: String? = null
            val serverPart: String
            val atIndex = remaining.lastIndexOf('@')
            if (atIndex >= 0) {
                val userInfo = remaining.substring(0, atIndex)
                serverPart = remaining.substring(atIndex + 1).let { rest ->
                    val slashIndex = rest.indexOf('/')
                    if (slashIndex >= 0) rest.substring(0, slashIndex) else rest
                }
                val colonIndex = userInfo.indexOf(':')
                if (colonIndex >= 0) {
                    username = percentDecode(userInfo.substring(0, colonIndex))
                    password = percentDecode(userInfo.substring(colonIndex + 1))
                } else {
                    username = percentDecode(userInfo)
                }
            } else {
                val slashIndex = remaining.indexOf('/')
                serverPart = if (slashIndex >= 0) remaining.substring(0, slashIndex) else remaining
            }

            val (host, port) = parseHostPort(serverPart)

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for SOCKS5
                encryption = "none",
                outboundProtocol = OutboundProtocol.SOCKS5,
                socks5Username = username,
                socks5Password = password
            )
        }

        private fun parseQueryParams(queryString: String?): Map<String, String> {
            if (queryString == null) return emptyMap()
            val params = mutableMapOf<String, String>()
            queryString.split("&").forEach { param ->
                val kv = param.split("=", limit = 2)
                if (kv.size == 2) {
                    params[kv[0]] = percentDecode(kv[1])
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

        private fun decodeShadowsocksUserInfo(userInfo: String): Pair<String, String> {
            val colonIndex = userInfo.indexOf(':')
            if (colonIndex >= 0) {
                return Pair(userInfo.substring(0, colonIndex), percentDecode(userInfo.substring(colonIndex + 1)))
            }

            val decoded = decodeBase64Text(userInfo)
                ?: throw ProxyError.InvalidUrl("Invalid SS user info encoding")
            val decodedColonIndex = decoded.indexOf(':')
            if (decodedColonIndex < 0) throw ProxyError.InvalidUrl("Invalid SS user info format")
            return Pair(decoded.substring(0, decodedColonIndex), decoded.substring(decodedColonIndex + 1))
        }

        private fun decodeBase64Text(value: String): String? {
            val padded = padBase64(value)
            val bytes = runCatching {
                java.util.Base64.getUrlDecoder().decode(padded)
            }.getOrElse {
                runCatching { java.util.Base64.getDecoder().decode(padded) }.getOrNull()
            } ?: return null
            return String(bytes, Charsets.UTF_8)
        }

        private fun urlEncode(value: String): String =
            URLEncoder.encode(value, "UTF-8").replace("+", "%20")
    }
}

sealed class ProxyError(message: String) : Exception(message) {
    class InvalidUrl(message: String) : ProxyError("Invalid URL: $message")
    class ConnectionFailed(message: String) : ProxyError("Connection failed: $message")
    class ProtocolError(message: String) : ProxyError("Protocol error: $message")
    class InvalidResponse(message: String) : ProxyError("Invalid response: $message")
    class Dropped : ProxyError("Dropped")
}
