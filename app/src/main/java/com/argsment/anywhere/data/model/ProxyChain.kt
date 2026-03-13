package com.argsment.anywhere.data.model

import kotlinx.serialization.Serializable
import java.util.UUID

/**
 * A named, ordered sequence of proxy configurations forming a chain.
 *
 * When selected as the working configuration:
 * - The **last** proxy in [proxyIds] is the exit proxy (talks to the target).
 * - All preceding proxies form the intermediate chain (tunneled through in order).
 */
@Serializable
data class ProxyChain(
    @Serializable(with = UuidSerializer::class) val id: UUID = UUID.randomUUID(),
    var name: String,
    val proxyIds: List<@Serializable(with = UuidSerializer::class) UUID> = emptyList()
)
