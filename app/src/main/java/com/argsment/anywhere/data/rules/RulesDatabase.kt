package com.argsment.anywhere.data.rules

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import com.argsment.anywhere.data.model.DomainRule
import com.argsment.anywhere.data.model.DomainRuleType
import com.argsment.anywhere.vpn.util.AnywhereLogger
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Read-only SQLite database for bundled routing rules.
 *
 * Tables:
 *  - `rules(source, type, value)` — domain/IP rules keyed by source name
 *  - `metadata(key, value)` — JSON-encoded lists and mappings
 */
class RulesDatabase private constructor(private val db: SQLiteDatabase?) {

    fun loadRules(source: String): List<DomainRule> {
        val db = db ?: return emptyList()
        val out = mutableListOf<DomainRule>()
        db.rawQuery("SELECT type, value FROM rules WHERE source = ?", arrayOf(source)).use { c ->
            while (c.moveToNext()) {
                val type = DomainRuleType.fromRawValue(c.getInt(0)) ?: continue
                val value = c.getString(1) ?: continue
                out.add(DomainRule(type, value))
            }
        }
        return out
    }

    fun loadMetadata(key: String): String? {
        val db = db ?: return null
        db.rawQuery("SELECT value FROM metadata WHERE key = ?", arrayOf(key)).use { c ->
            return if (c.moveToNext()) c.getString(0) else null
        }
    }

    fun loadStringArray(key: String): List<String> {
        val json = loadMetadata(key) ?: return emptyList()
        return runCatching {
            val arr = JSONArray(json)
            List(arr.length()) { arr.getString(it) }
        }.getOrElse { emptyList() }
    }

    fun loadStringMap(key: String): Map<String, String> {
        val json = loadMetadata(key) ?: return emptyMap()
        return runCatching {
            val obj = JSONObject(json)
            buildMap(obj.length()) {
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    put(k, obj.getString(k))
                }
            }
        }.getOrElse { emptyMap() }
    }

    companion object {
        private val logger = AnywhereLogger("RulesDatabase")
        private const val DB_NAME = "Rules.db"
        private const val VERSION_FILE = "Rules.db.version"

        @Volatile private var instance: RulesDatabase? = null

        fun get(context: Context): RulesDatabase {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                val created = open(context.applicationContext)
                instance = created
                return created
            }
        }

        private fun open(context: Context): RulesDatabase {
            val target = File(context.filesDir, DB_NAME)
            val versionMarker = File(context.filesDir, VERSION_FILE)
            val assetSize: Long = try {
                context.assets.openFd(DB_NAME).use { it.length }
            } catch (_: Exception) { -1L }
            val currentVersion = assetSize.toString()
            val storedVersion = runCatching { versionMarker.readText() }.getOrNull()

            if (!target.exists() || storedVersion != currentVersion || target.length() != assetSize) {
                try {
                    context.assets.open(DB_NAME).use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                    versionMarker.writeText(currentVersion)
                } catch (e: Exception) {
                    logger.error("Failed to stage Rules.db from assets: $e")
                    return RulesDatabase(null)
                }
            }

            return try {
                val db = SQLiteDatabase.openDatabase(
                    target.absolutePath,
                    null,
                    SQLiteDatabase.OPEN_READONLY
                )
                RulesDatabase(db)
            } catch (e: Exception) {
                logger.error("Failed to open Rules.db: $e")
                RulesDatabase(null)
            }
        }
    }
}
