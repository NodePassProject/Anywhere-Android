package com.argsment.anywhere.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class DomainRuleType {
    @SerialName("domain") DOMAIN,
    @SerialName("domainSuffix") DOMAIN_SUFFIX,
    @SerialName("domainKeyword") DOMAIN_KEYWORD
}

@Serializable
data class DomainRule(
    val type: DomainRuleType,
    val value: String
)
