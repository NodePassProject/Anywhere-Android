package com.argsment.anywhere.data.model

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class Subscription(
    @Serializable(with = UuidSerializer::class) val id: UUID = UUID.randomUUID(),
    val name: String,
    val url: String,
    val lastUpdate: Long? = null,
    val upload: Long? = null,
    val download: Long? = null,
    val total: Long? = null,
    val expire: Long? = null,
    val collapsed: Boolean = false,
    /** Whether the user manually renamed this subscription — prevents auto-overwrite on update. Mirrors iOS. */
    val isNameCustomized: Boolean = false
)
