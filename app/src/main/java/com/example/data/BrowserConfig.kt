package com.example.data

import org.json.JSONObject

/**
 * Application-wide browser policy and security configuration.
 */
data class BrowserConfig(
    val homepage: String = "https://www.google.com",
    val enforceHttpsOnly: Boolean = true,
    val enableJavaScript: Boolean = true,
    val blockPopups: Boolean = true,
    val kioskModeActive: Boolean = false,
    val adminPinHash: String = "",
    val adminSalt: String = "",
    val lastUpdated: Long = System.currentTimeMillis()
) {
    fun toJsonObject(): JSONObject {
        return JSONObject().apply {
            put("homepage", homepage)
            put("enforceHttpsOnly", enforceHttpsOnly)
            put("enableJavaScript", enableJavaScript)
            put("blockPopups", blockPopups)
            put("kioskModeActive", kioskModeActive)
            put("adminPinHash", adminPinHash)
            put("adminSalt", adminSalt)
            put("lastUpdated", lastUpdated)
        }
    }

    companion object {
        fun fromJsonObject(json: JSONObject): BrowserConfig {
            return BrowserConfig(
                homepage = json.optString("homepage", "https://www.google.com"),
                enforceHttpsOnly = json.optBoolean("enforceHttpsOnly", true),
                enableJavaScript = json.optBoolean("enableJavaScript", true),
                blockPopups = json.optBoolean("blockPopups", true),
                kioskModeActive = json.optBoolean("kioskModeActive", false),
                adminPinHash = json.optString("adminPinHash", ""),
                adminSalt = json.optString("adminSalt", ""),
                lastUpdated = json.optLong("lastUpdated", System.currentTimeMillis())
            )
        }
    }
}
