package com.argsment.anywhere.data.model

data class TunnelSettings(
    val address: String = "10.8.0.2",
    val prefixLength: Int = 24,
    val gateway: String = "10.8.0.1",
    val dnsServers: List<String> = listOf("1.1.1.1", "1.0.0.1"),
    val mtu: Int = 1400,
    val ipv6Enabled: Boolean = false,
    val ipv6Address: String = "fd00::2",
    val ipv6PrefixLength: Int = 64,
    val bypassRoutes: List<String> = listOf(
        "10.0.0.0/8",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16"
    )
)
