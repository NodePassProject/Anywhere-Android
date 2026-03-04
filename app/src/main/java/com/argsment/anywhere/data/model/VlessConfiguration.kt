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
                ?: throw VlessError.InvalidUrl("Missing Reality parameter: sni")
            val pbk = params["pbk"]?.takeIf { it.isNotEmpty() }
                ?: throw VlessError.InvalidUrl("Missing Reality parameter: pbk (public key)")
            val publicKey = pbk.base64UrlToByteArrayOrNull()
                ?: throw VlessError.InvalidUrl("Invalid Reality public key")
            if (publicKey.size != 32) throw VlessError.InvalidUrl("Invalid Reality public key")
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
    @SerialName("packet-up") PACKET_UP("packet-up");

    val displayName: String
        get() = when (this) {
            AUTO -> "Auto"
            STREAM_ONE -> "Stream One"
            PACKET_UP -> "Packet Up"
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
// VLESS Configuration
// =============================================================================

@Serializable
data class VlessConfiguration(
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
    @Serializable(with = UuidSerializer::class) val subscriptionId: UUID? = null
) {
    val connectAddress: String get() = resolvedIP ?: serverAddress

    fun contentEquals(other: VlessConfiguration): Boolean =
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
                xudpEnabled == other.xudpEnabled

    companion object {
        fun fromUrl(url: String): VlessConfiguration {
            if (!url.startsWith("vless://")) {
                throw VlessError.InvalidUrl("URL must start with vless://")
            }

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
            if (atIndex < 0) throw VlessError.InvalidUrl("Missing @ separator")

            val uuidString = remaining.substring(0, atIndex)
            val serverPart = remaining.substring(atIndex + 1)

            val uuid = runCatching { UUID.fromString(uuidString) }.getOrNull()
                ?: throw VlessError.InvalidUrl("Invalid UUID: $uuidString")

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
            val host: String
            val portString: String
            if (hostPort.startsWith("[")) {
                val closeBracket = hostPort.indexOf(']')
                if (closeBracket < 0) throw VlessError.InvalidUrl("Missing closing bracket for IPv6 address")
                host = hostPort.substring(1, closeBracket)
                val afterBracket = hostPort.substring(closeBracket + 1)
                if (!afterBracket.startsWith(":")) throw VlessError.InvalidUrl("Missing port after IPv6 address")
                portString = afterBracket.removePrefix(":")
            } else {
                val colonIndex = hostPort.lastIndexOf(':')
                if (colonIndex < 0) throw VlessError.InvalidUrl("Missing port in server address")
                host = hostPort.substring(0, colonIndex)
                portString = hostPort.substring(colonIndex + 1)
            }

            val port = portString.toUShortOrNull()
                ?: throw VlessError.InvalidUrl("Invalid port: $portString")

            // Parse query parameters
            val params = mutableMapOf<String, String>()
            queryString?.split("&")?.forEach { param ->
                val kv = param.split("=", limit = 2)
                if (kv.size == 2) {
                    params[kv[0]] = URLDecoder.decode(kv[1], "UTF-8")
                }
            }

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

            return VlessConfiguration(
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
    }
}

// =============================================================================
// VLESS Errors
// =============================================================================

sealed class VlessError(message: String) : Exception(message) {
    class InvalidUrl(message: String) : VlessError("Invalid VLESS URL: $message")
    class ConnectionFailed(message: String) : VlessError("Connection failed: $message")
    class ProtocolError(message: String) : VlessError("Protocol error: $message")
    class InvalidResponse(message: String) : VlessError("Invalid response: $message")
    class Dropped : VlessError("Dropped")
}
