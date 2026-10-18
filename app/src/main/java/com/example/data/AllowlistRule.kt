package com.example.data

import com.example.security.UrlSecurityValidator
import org.json.JSONObject

/**
 * Model representing an administrator-approved domain entry.
 */
data class AllowlistRule(
    val domain: String,
    val allowSubdomains: Boolean = true,
    val description: String = "",
    val enabled: Boolean = true,
    val createdAt: Long = System.currentTimeMillis()
) {
    /**
     * Normalized domain for robust hostname comparison.
     */
    fun normalizedDomain(): String {
        return UrlSecurityValidator.sanitizeDomainRule(domain)
    }

    fun toJsonObject(): JSONObject {
        return JSONObject().apply {
            put("domain", domain)
            put("allowSubdomains", allowSubdomains)
            put("description", description)
            put("enabled", enabled)
            put("createdAt", createdAt)
        }
    }

    companion object {
        fun fromJsonObject(json: JSONObject): AllowlistRule {
            return AllowlistRule(
                domain = json.optString("domain", "").trim(),
                allowSubdomains = json.optBoolean("allowSubdomains", true),
                description = json.optString("description", ""),
                enabled = json.optBoolean("enabled", true),
                createdAt = json.optLong("createdAt", System.currentTimeMillis())
            )
        }
    }
}
