package com.argsment.anywhere.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class DomainRuleType {
    @SerialName("domain") DOMAIN,
    @SerialName("domainSuffix") DOMAIN_SUFFIX,
    @SerialName("domainKeyword") DOMAIN_KEYWORD,
    @SerialName("ipCIDR") IP_CIDR,
    @SerialName("ipCIDR6") IP_CIDR6
}

@Serializable
data class DomainRule(
    val type: DomainRuleType,
    val value: String
)
