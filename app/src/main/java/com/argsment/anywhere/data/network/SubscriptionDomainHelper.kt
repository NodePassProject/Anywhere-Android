package com.argsment.anywhere.data.network

/**
 * Mirrors iOS `SubscriptionDomainHelper` — allow-lists of subscription domains
 * that trigger special handling:
 *
 *  - [shouldDisableProxyEditing] locks individual proxies inside a subscription
 *    from being edited or deleted (users should re-subscribe instead).
 *  - [shouldRequireRemnawaveHWID] marks Remnawave-panel subscriptions whose
 *    endpoints require the device identifier as an `x-hwid` header.
 */
object SubscriptionDomainHelper {
    private val domainsShouldDisableProxyEditing: List<String> = listOf(
        "sub.example.com",
        "sub.cdnjst.org"
    )

    private val domainsRequireRemnawaveHWID: List<String> = listOf(
        "sub.example.com",
        "sub.cdnjst.org"
    )

    fun shouldDisableProxyEditing(url: String): Boolean =
        domainsShouldDisableProxyEditing.any { url.startsWith("https://$it/") }

    fun shouldRequireRemnawaveHWID(url: String): Boolean =
        domainsRequireRemnawaveHWID.any { url.startsWith("https://$it/") }
}
