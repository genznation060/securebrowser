package com.example.security

import android.net.Uri
import com.example.data.AllowlistRule
import java.net.URI
import java.util.Locale

/**
 * Result of validating a URL against administrator-configured security policies.
 */
sealed class ValidationResult {
    data class Allowed(val normalizedUrl: String) : ValidationResult()
    data class Blocked(
        val targetUrl: String,
        val reason: BlockReason,
        val detail: String
    ) : ValidationResult()
}

enum class BlockReason {
    UNAPPROVED_DOMAIN,
    SUBDOMAIN_DISALLOWED,
    CLEARTEXT_HTTP_BLOCKED,
    UNSUPPORTED_SCHEME,
    MALFORMED_URL,
    SSL_CERTIFICATE_INVALID
}

/**
 * High-assurance URL and hostname validator.
 * Enforces strict domain allowlists, prevents lookalike attacks,
 * and restricts URL schemes.
 */
class UrlSecurityValidator(
    private val allowlistSupplier: () -> List<AllowlistRule>,
    private val isHttpsOnlySupplier: () -> Boolean = { true }
) {

    companion object {
        private val ALLOWED_SCHEMES = setOf("https", "http")
        
        /**
         * Normalizes a hostname by lowercasing, stripping leading/trailing whitespace,
         * trailing dots, and ports.
         */
        fun normalizeHostname(rawHost: String?): String? {
            if (rawHost.isNullOrBlank()) return null
            var host = rawHost.trim().lowercase(Locale.ROOT)
            
            // Remove port if present
            val colonIdx = host.indexOf(':')
            if (colonIdx != -1) {
                host = host.substring(0, colonIdx)
            }
            
            // Remove trailing dot (FQDN dot)
            while (host.endsWith(".")) {
                host = host.dropLast(1)
            }
            
            return if (host.isBlank()) null else host
        }

        /**
         * Cleans and normalizes domain rule inputs (e.g. from user/admin input).
         */
        fun sanitizeDomainRule(input: String): String {
            var domain = input.trim().lowercase(Locale.ROOT)
            // Strip scheme if admin accidentally pasted https://
            if (domain.startsWith("https://")) {
                domain = domain.removePrefix("https://")
            } else if (domain.startsWith("http://")) {
                domain = domain.removePrefix("http://")
            }
            // Strip any path or query
            val slashIdx = domain.indexOf('/')
            if (slashIdx != -1) {
                domain = domain.substring(0, slashIdx)
            }
            // Strip port
            val colonIdx = domain.indexOf(':')
            if (colonIdx != -1) {
                domain = domain.substring(0, colonIdx)
            }
            // Strip wildcard prefix if user wrote *.example.com
            if (domain.startsWith("*.")) {
                domain = domain.removePrefix("*.")
            }
            while (domain.endsWith(".")) {
                domain = domain.dropLast(1)
            }
            return domain
        }
    }

    /**
     * Validates a URL string against the current security policies and allowlist.
     */
    fun validateUrl(rawUrl: String?): ValidationResult {
        if (rawUrl.isNullOrBlank()) {
            return ValidationResult.Blocked("", BlockReason.MALFORMED_URL, "URL cannot be empty")
        }

        // Allow initial internal blank page only if explicitly configured
        if (rawUrl.equals("about:blank", ignoreCase = true)) {
            return ValidationResult.Allowed("about:blank")
        }

        // Parse URI securely
        val uri: Uri = try {
            Uri.parse(rawUrl.trim())
        } catch (e: Exception) {
            return ValidationResult.Blocked(rawUrl, BlockReason.MALFORMED_URL, "Malformed URL format")
        }

        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme)) {
            return ValidationResult.Blocked(
                rawUrl,
                BlockReason.UNSUPPORTED_SCHEME,
                "Protocol '${scheme ?: "none"}' is not supported. Only secure HTTPS is permitted."
            )
        }

        // Enforce HTTPS if configured (default is true)
        val enforceHttps = isHttpsOnlySupplier()
        if (scheme == "http" && enforceHttps) {
            return ValidationResult.Blocked(
                rawUrl,
                BlockReason.CLEARTEXT_HTTP_BLOCKED,
                "Cleartext HTTP is blocked by security policy. Only HTTPS connections are permitted."
            )
        }

        // Extract and validate host
        val host = normalizeHostname(uri.host)
        if (host == null) {
            return ValidationResult.Blocked(
                rawUrl,
                BlockReason.MALFORMED_URL,
                "No valid host found in URL"
            )
        }

        // Perform strict allowlist matching against active rules
        val activeRules = allowlistSupplier().filter { it.enabled }
        val matchingRule = findMatchingRule(host, activeRules)

        return if (matchingRule != null) {
            ValidationResult.Allowed(rawUrl)
        } else {
            // Check if it was blocked because subdomain was disallowed
            val exactRuleWithoutSubdomains = activeRules.firstOrNull { rule ->
                !rule.allowSubdomains && host.endsWith(".${rule.normalizedDomain()}")
            }
            if (exactRuleWithoutSubdomains != null) {
                ValidationResult.Blocked(
                    rawUrl,
                    BlockReason.SUBDOMAIN_DISALLOWED,
                    "Subdomains of '${exactRuleWithoutSubdomains.domain}' are disallowed."
                )
            } else {
                ValidationResult.Blocked(
                    rawUrl,
                    BlockReason.UNAPPROVED_DOMAIN,
                    "Domain '$host' is not in the administrator allowlist."
                )
            }
        }
    }

    /**
     * Matches a normalized hostname against an active rule.
     * Prevents lookalikes (e.g. google.com.attacker.com or notgoogle.com).
     */
    fun findMatchingRule(host: String, rules: List<AllowlistRule>): AllowlistRule? {
        val normalizedHost = normalizeHostname(host) ?: return null

        for (rule in rules) {
            val ruleDomain = rule.normalizedDomain()
            if (ruleDomain.isBlank()) continue

            if (normalizedHost == ruleDomain) {
                return rule
            }

            if (rule.allowSubdomains) {
                // Must strictly end with "." + ruleDomain
                // e.g. "www.google.com".endsWith(".google.com") -> TRUE
                // "notgoogle.com".endsWith(".google.com") -> FALSE
                // "attacker.com.google.com".endsWith(".google.com") -> TRUE
                // "google.com.attacker.com".endsWith(".google.com") -> FALSE
                if (normalizedHost.endsWith(".$ruleDomain")) {
                    return rule
                }
            }
        }
        return null
    }

    /**
     * Checks if a host is allowed (quick check for resource / child requests).
     */
    fun isHostAllowed(host: String?): Boolean {
        if (host.isNullOrBlank()) return false
        val normalized = normalizeHostname(host) ?: return false
        val activeRules = allowlistSupplier().filter { it.enabled }
        return findMatchingRule(normalized, activeRules) != null
    }
}
