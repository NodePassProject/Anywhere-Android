package com.argsment.anywhere.data.model

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/**
 * Integer-backed rule type. Legacy string payloads
 * ("domain", "domainKeyword", "domainSuffix", "ipCIDR", "ipCIDR6")
 * are decoded for backward compatibility.
 */
@Serializable(with = DomainRuleTypeSerializer::class)
enum class DomainRuleType(val rawValue: Int) {
    IP_CIDR(0),
    IP_CIDR6(1),
    DOMAIN_SUFFIX(2),
    DOMAIN_KEYWORD(3);

    companion object {
        fun fromRawValue(value: Int): DomainRuleType? = entries.firstOrNull { it.rawValue == value }

        fun fromLegacyString(value: String): DomainRuleType? = when (value) {
            "ipCIDR" -> IP_CIDR
            "ipCIDR6" -> IP_CIDR6
            "domain", "domainSuffix" -> DOMAIN_SUFFIX
            "domainKeyword" -> DOMAIN_KEYWORD
            else -> null
        }
    }
}

private object DomainRuleTypeSerializer : KSerializer<DomainRuleType> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("DomainRuleType", PrimitiveKind.INT)

    override fun serialize(encoder: Encoder, value: DomainRuleType) {
        encoder.encodeInt(value.rawValue)
    }

    override fun deserialize(decoder: Decoder): DomainRuleType {
        if (decoder is JsonDecoder) {
            val element = decoder.decodeJsonElement()
            if (element is JsonPrimitive) {
                element.intOrNull?.let { return DomainRuleType.fromRawValue(it) ?: error("Unknown rule type: $it") }
                return DomainRuleType.fromLegacyString(element.content)
                    ?: error("Unknown rule type: ${element.content}")
            }
        }
        return DomainRuleType.fromRawValue(decoder.decodeInt()) ?: error("Unknown rule type")
    }
}

@Serializable
data class DomainRule(
    val type: DomainRuleType,
    val value: String
)
