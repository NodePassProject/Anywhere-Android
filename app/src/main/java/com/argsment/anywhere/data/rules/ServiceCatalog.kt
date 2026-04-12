package com.argsment.anywhere.data.rules

import android.content.Context
import com.argsment.anywhere.data.model.DomainRule

/**
 * Bundled list of built-in service rule sets loaded from Rules.db metadata.
 *
 * Swift counterpart: [Shared/Catalog/ServiceCatalog.swift].
 */
class ServiceCatalog private constructor(
    val supportedServices: List<String>,
    private val db: RulesDatabase
) {
    fun rules(for_: String): List<DomainRule> = db.loadRules(for_)

    companion object {
        @Volatile private var instance: ServiceCatalog? = null

        fun get(context: Context): ServiceCatalog {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                val db = RulesDatabase.get(context)
                val catalog = ServiceCatalog(
                    supportedServices = db.loadStringArray("supportedServices"),
                    db = db
                )
                instance = catalog
                return catalog
            }
        }
    }
}
