package com.argsment.anywhere.vpn.util

import android.util.Base64

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToByteArray(): ByteArray {
    val hex = replace(" ", "")
    require(hex.length % 2 == 0) { "Hex string must have even length" }
    return ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

fun String.hexToByteArrayOrNull(): ByteArray? = runCatching { hexToByteArray() }.getOrNull()

fun ByteArray.toBase64Url(): String =
    Base64.encodeToString(this, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

fun String.base64UrlToByteArray(): ByteArray =
    Base64.decode(this, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

fun String.base64UrlToByteArrayOrNull(): ByteArray? =
    runCatching { base64UrlToByteArray() }.getOrNull()
