package com.argsment.anywhere.data.rules

import android.content.Context
import com.argsment.anywhere.data.model.DomainRule
import java.util.Locale

/**
 * Country-bypass catalog: supported country codes + language → country suggestion,
 * plus domain rules per country. All data loaded from Rules.db metadata/rules.
 */
class CountryBypassCatalog private constructor(
    val supportedCountryCodes: List<String>,
    private val languageToCountry: Map<String, String>,
    private val db: RulesDatabase
) {
    fun suggestedCountryCode(locale: Locale = Locale.getDefault()): String? {
        val lang = locale.language.takeIf { it.isNotEmpty() } ?: return null
        return languageToCountry[lang]
    }

    fun rules(countryCode: String): List<DomainRule> = db.loadRules(countryCode)

    companion object {
        @Volatile private var instance: CountryBypassCatalog? = null

        fun get(context: Context): CountryBypassCatalog {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                val db = RulesDatabase.get(context)
                val catalog = CountryBypassCatalog(
                    supportedCountryCodes = db.loadStringArray("supportedCountryCodes"),
                    languageToCountry = db.loadStringMap("languageToCountry"),
                    db = db
                )
                instance = catalog
                return catalog
            }
        }
    }
}
