package com.argsment.anywhere.data.network

import android.util.Base64
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.vpn.protocol.tls.CertificatePolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object SubscriptionFetcher {

    data class Result(
        val configurations: List<ProxyConfiguration>,
        val name: String?,
        val upload: Long?,
        val download: Long?,
        val total: Long?,
        val expire: Long?
    )

    sealed class FetchError(message: String) : Exception(message) {
        class InvalidUrl : FetchError("Invalid subscription URL.")
        class NoConfigurations : FetchError("No valid configurations found in subscription.")
        class NetworkError(message: String) : FetchError("Network error: $message")
    }

    suspend fun fetch(
        urlString: String,
        allowInsecure: Boolean = CertificatePolicy.allowInsecure,
        remnawaveHWID: String? = null
    ): Result = withContext(Dispatchers.IO) {
        val url = runCatching { URL(urlString) }.getOrNull()
            ?: throw FetchError.InvalidUrl()

        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.setRequestProperty("User-Agent", "Anywhere")
            if (remnawaveHWID != null) {
                connection.setRequestProperty("x-hwid", remnawaveHWID)
            }
            connection.connectTimeout = 30_000
            connection.readTimeout = 30_000

            // Accept self-signed certificates only when the caller has indicated allowInsecure.
            if (connection is HttpsURLConnection && allowInsecure) {
                val trustAllManager = object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
                connection.sslSocketFactory = sslContext.socketFactory
                connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }

            val responseCode = try {
                connection.responseCode
            } catch (e: Exception) {
                throw FetchError.NetworkError(e.message ?: "Unknown error")
            }

            if (responseCode !in 200..299) {
                throw FetchError.NetworkError("HTTP $responseCode")
            }

            val data = connection.inputStream.readBytes()

            val profileTitle = parseProfileTitle(connection)
            val userInfo = parseSubscriptionUserInfo(connection)

            // Decode body: try base64 first, fall back to raw UTF-8
            val bodyString: String
            val decoded = runCatching {
                Base64.decode(data, Base64.DEFAULT)
            }.getOrNull()
            val decodedString = decoded?.let { String(it, Charsets.UTF_8) }

            val parsablePrefixes = ProxyConfiguration.parsableUrlPrefixes

            bodyString = if (decodedString != null && parsablePrefixes.any { decodedString.contains(it) }) {
                decodedString
            } else {
                String(data, Charsets.UTF_8)
            }

            if (bodyString.contains("proxies:")) {
                val result = ClashProxyParser.parse(bodyString)
                if (result.configurations.isEmpty()) throw FetchError.NoConfigurations()
                return@withContext Result(
                    configurations = result.configurations,
                    name = profileTitle,
                    upload = userInfo.upload,
                    download = userInfo.download,
                    total = userInfo.total,
                    expire = userInfo.expire
                )
            }

            val configurations = bodyString
                .lines()
                .map { it.trim() }
                .filter { line -> parsablePrefixes.any { line.startsWith(it) } }
                .mapNotNull { runCatching { ProxyConfiguration.fromUrl(it) }.getOrNull() }

            if (configurations.isEmpty()) throw FetchError.NoConfigurations()

            Result(
                configurations = configurations,
                name = profileTitle,
                upload = userInfo.upload,
                download = userInfo.download,
                total = userInfo.total,
                expire = userInfo.expire
            )
        } finally {
            connection.disconnect()
        }
    }

    private fun parseProfileTitle(connection: HttpURLConnection): String? {
        val value = connection.getHeaderField("profile-title") ?: return null
        val decoded = if (value.startsWith("base64:")) {
            val encoded = value.removePrefix("base64:")
            runCatching {
                String(Base64.decode(encoded, Base64.DEFAULT), Charsets.UTF_8)
            }.getOrNull()
        } else {
            value
        }
        // Servers commonly send an empty `Profile-Title: base64:` for unnamed
        // subscriptions. Treat blank results as missing so the call site falls
        // back to the URL host instead of an empty string.
        return decoded?.takeIf { it.isNotBlank() }
    }

    data class UserInfo(
        val upload: Long? = null,
        val download: Long? = null,
        val total: Long? = null,
        val expire: Long? = null
    )

    private fun parseSubscriptionUserInfo(connection: HttpURLConnection): UserInfo {
        val value = connection.getHeaderField("subscription-userinfo") ?: return UserInfo()

        var upload: Long? = null
        var download: Long? = null
        var total: Long? = null
        var expire: Long? = null

        for (part in value.split(";")) {
            val trimmed = part.trim()
            val kv = trimmed.split("=", limit = 2)
            if (kv.size != 2) continue
            val key = kv[0].trim()
            val v = kv[1].trim()

            when (key) {
                "upload" -> upload = v.toLongOrNull()
                "download" -> download = v.toLongOrNull()
                "total" -> total = v.toLongOrNull()
                "expire" -> expire = v.toLongOrNull()?.let { it * 1000 }
            }
        }

        return UserInfo(upload, download, total, expire)
    }
}
