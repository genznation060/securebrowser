package com.example.data

import android.content.Context
import android.content.SharedPreferences
import com.example.security.UrlSecurityValidator
import org.json.JSONArray
import org.json.JSONObject

/**
 * Thread-safe persistent storage for browser configuration and domain allowlist.
 */
class SecurityStorage(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "secure_browse_security_storage"
        private const val KEY_CONFIG = "browser_config_json"
        private const val KEY_ALLOWLIST = "allowlist_rules_json"
        private const val KEY_FIRST_LAUNCH = "is_first_launch_done"

        @Volatile
        private var INSTANCE: SecurityStorage? = null

        fun getInstance(context: Context): SecurityStorage {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SecurityStorage(context).also { INSTANCE = it }
            }
        }
    }

    init {
        ensureDefaultRules()
    }

    private fun ensureDefaultRules() {
        if (!prefs.getBoolean(KEY_FIRST_LAUNCH, false)) {
            // Seed default approved domains requested in specifications
            val initialRules = listOf(
                AllowlistRule(
                    domain = "google.com",
                    allowSubdomains = true,
                    description = "Default Search Engine & Web Tools"
                ),
                AllowlistRule(
                    domain = "wikipedia.org",
                    allowSubdomains = true,
                    description = "Encyclopedia & Academic Reference"
                ),
                AllowlistRule(
                    domain = "youtube.com",
                    allowSubdomains = true,
                    description = "Approved Educational Media"
                )
            )
            saveRules(initialRules)
            saveConfig(BrowserConfig())
            prefs.edit().putBoolean(KEY_FIRST_LAUNCH, true).apply()
        }
    }

    @Synchronized
    fun getRules(): List<AllowlistRule> {
        val jsonStr = prefs.getString(KEY_ALLOWLIST, null) ?: return emptyList()
        return try {
            val array = JSONArray(jsonStr)
            val list = mutableListOf<AllowlistRule>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                list.add(AllowlistRule.fromJsonObject(obj))
            }
            list
        } catch (e: Exception) {
            emptyList()
        }
    }

    @Synchronized
    fun saveRules(rules: List<AllowlistRule>) {
        val array = JSONArray()
        rules.forEach { array.put(it.toJsonObject()) }
        prefs.edit().putString(KEY_ALLOWLIST, array.toString()).apply()
    }

    @Synchronized
    fun addRule(rule: AllowlistRule): Boolean {
        val cleanDomain = UrlSecurityValidator.sanitizeDomainRule(rule.domain)
        if (cleanDomain.isBlank()) return false

        val current = getRules().toMutableList()
        if (current.any { it.normalizedDomain() == cleanDomain }) {
            return false // Already exists
        }

        current.add(rule.copy(domain = cleanDomain))
        saveRules(current)
        return true
    }

    @Synchronized
    fun removeRule(domain: String): Boolean {
        val clean = UrlSecurityValidator.sanitizeDomainRule(domain)
        val current = getRules().toMutableList()
        val removed = current.removeAll { it.normalizedDomain() == clean }
        if (removed) {
            saveRules(current)
        }
        return removed
    }

    @Synchronized
    fun updateRule(updated: AllowlistRule) {
        val clean = updated.normalizedDomain()
        val current = getRules().map {
            if (it.normalizedDomain() == clean) updated else it
        }
        saveRules(current)
    }

    @Synchronized
    fun getConfig(): BrowserConfig {
        val jsonStr = prefs.getString(KEY_CONFIG, null) ?: return BrowserConfig()
        return try {
            BrowserConfig.fromJsonObject(JSONObject(jsonStr))
        } catch (e: Exception) {
            BrowserConfig()
        }
    }

    @Synchronized
    fun saveConfig(config: BrowserConfig) {
        prefs.edit().putString(KEY_CONFIG, config.toJsonObject().toString()).apply()
    }

    /**
     * Exports the current allowlist to an indented JSON string for backup/export.
     */
    @Synchronized
    fun exportAllowlistJson(): String {
        val array = JSONArray()
        getRules().forEach { array.put(it.toJsonObject()) }
        val root = JSONObject().apply {
            put("version", 1)
            put("exportedAt", System.currentTimeMillis())
            put("rules", array)
        }
        return root.toString(2)
    }

    /**
     * Imports allowlist rules from a JSON backup string.
     * Returns Pair(isSuccess, importedCount).
     */
    @Synchronized
    fun importAllowlistJson(jsonStr: String): Pair<Boolean, Int> {
        return try {
            val root = JSONObject(jsonStr)
            val rulesArray = root.optJSONArray("rules") ?: JSONArray(jsonStr)
            val importedList = mutableListOf<AllowlistRule>()
            for (i in 0 until rulesArray.length()) {
                val obj = rulesArray.getJSONObject(i)
                val rule = AllowlistRule.fromJsonObject(obj)
                if (rule.normalizedDomain().isNotBlank()) {
                    importedList.add(rule)
                }
            }

            if (importedList.isNotEmpty()) {
                // Merge or replace
                val current = getRules().toMutableList()
                var addedCount = 0
                for (rule in importedList) {
                    val idx = current.indexOfFirst { it.normalizedDomain() == rule.normalizedDomain() }
                    if (idx != -1) {
                        current[idx] = rule
                    } else {
                        current.add(rule)
                        addedCount++
                    }
                }
                saveRules(current)
                Pair(true, importedList.size)
            } else {
                Pair(false, 0)
            }
        } catch (e: Exception) {
            Pair(false, 0)
        }
    }
}
