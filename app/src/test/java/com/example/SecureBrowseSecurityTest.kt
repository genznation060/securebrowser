package com.example

import com.example.admin.AdminAuthManager
import com.example.data.AllowlistRule
import com.example.data.BrowserConfig
import com.example.security.BlockReason
import com.example.security.UrlSecurityValidator
import com.example.security.ValidationResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecureBrowseSecurityTest {

    private lateinit var sampleRules: List<AllowlistRule>
    private lateinit var validator: UrlSecurityValidator

    @Before
    fun setUp() {
        sampleRules = listOf(
            AllowlistRule(domain = "google.com", allowSubdomains = true, description = "Google"),
            AllowlistRule(domain = "wikipedia.org", allowSubdomains = true, description = "Wikipedia"),
            AllowlistRule(domain = "youtube.com", allowSubdomains = true, description = "YouTube"),
            AllowlistRule(domain = "internal-portal.corp", allowSubdomains = false, description = "Exact only")
        )
        validator = UrlSecurityValidator(
            allowlistSupplier = { sampleRules },
            isHttpsOnlySupplier = { true }
        )
    }

    @Test
    fun testApprovedExactDomainsAllowed() {
        val r1 = validator.validateUrl("https://google.com")
        assertTrue("google.com should be allowed", r1 is ValidationResult.Allowed)

        val r2 = validator.validateUrl("https://wikipedia.org/wiki/Android")
        assertTrue("wikipedia.org should be allowed", r2 is ValidationResult.Allowed)

        val r3 = validator.validateUrl("https://youtube.com/watch?v=123")
        assertTrue("youtube.com should be allowed", r3 is ValidationResult.Allowed)
    }

    @Test
    fun testApprovedSubdomainsAllowed() {
        val r1 = validator.validateUrl("https://www.google.com")
        assertTrue("www.google.com should be allowed", r1 is ValidationResult.Allowed)

        val r2 = validator.validateUrl("https://en.wikipedia.org/wiki/Main_Page")
        assertTrue("en.wikipedia.org should be allowed", r2 is ValidationResult.Allowed)

        val r3 = validator.validateUrl("https://m.youtube.com")
        assertTrue("m.youtube.com should be allowed", r3 is ValidationResult.Allowed)

        val r4 = validator.validateUrl("https://deep.nested.sub.google.com/search?q=test")
        assertTrue("deep.nested.sub.google.com should be allowed", r4 is ValidationResult.Allowed)
    }

    @Test
    fun testDisallowedSubdomainBlocked() {
        val exactAllowed = validator.validateUrl("https://internal-portal.corp/dashboard")
        assertTrue("Exact internal-portal.corp allowed", exactAllowed is ValidationResult.Allowed)

        val subBlocked = validator.validateUrl("https://sub.internal-portal.corp")
        assertTrue("Subdomain of internal-portal.corp must be blocked", subBlocked is ValidationResult.Blocked)
        assertEquals(BlockReason.SUBDOMAIN_DISALLOWED, (subBlocked as ValidationResult.Blocked).reason)
    }

    @Test
    fun testUnapprovedDomainsBlocked() {
        val r1 = validator.validateUrl("https://example.com")
        assertTrue("example.com must be blocked", r1 is ValidationResult.Blocked)
        assertEquals(BlockReason.UNAPPROVED_DOMAIN, (r1 as ValidationResult.Blocked).reason)

        val r2 = validator.validateUrl("https://facebook.com")
        assertTrue("facebook.com must be blocked", r2 is ValidationResult.Blocked)
        assertEquals(BlockReason.UNAPPROVED_DOMAIN, (r2 as ValidationResult.Blocked).reason)
    }

    @Test
    fun testLookalikeAndSuffixAttacksBlocked() {
        // Lookalike attacker domain ending with google.com
        val r1 = validator.validateUrl("https://notgoogle.com")
        assertTrue("notgoogle.com must be blocked", r1 is ValidationResult.Blocked)

        val r2 = validator.validateUrl("https://evilgoogle.com")
        assertTrue("evilgoogle.com must be blocked", r2 is ValidationResult.Blocked)

        // Attacker domain using google.com as subdomain of attacker.com
        val r3 = validator.validateUrl("https://google.com.attacker.com")
        assertTrue("google.com.attacker.com must be blocked", r3 is ValidationResult.Blocked)
        assertEquals(BlockReason.UNAPPROVED_DOMAIN, (r3 as ValidationResult.Blocked).reason)

        val r4 = validator.validateUrl("https://google.com.fake.org/login")
        assertTrue("google.com.fake.org must be blocked", r4 is ValidationResult.Blocked)
    }

    @Test
    fun testHttpsEnforcedAndHttpBlockedByDefault() {
        val rHttp = validator.validateUrl("http://google.com")
        assertTrue("Cleartext HTTP must be blocked by default", rHttp is ValidationResult.Blocked)
        assertEquals(BlockReason.CLEARTEXT_HTTP_BLOCKED, (rHttp as ValidationResult.Blocked).reason)

        // When HTTPS-only is disabled, http to approved domain is allowed
        val permissiveValidator = UrlSecurityValidator(
            allowlistSupplier = { sampleRules },
            isHttpsOnlySupplier = { false }
        )
        val rHttpPermissive = permissiveValidator.validateUrl("http://google.com")
        assertTrue("HTTP allowed when HTTPS-only disabled", rHttpPermissive is ValidationResult.Allowed)
    }

    @Test
    fun testDangerousSchemesBlocked() {
        val dangerousUrls = listOf(
            "javascript:alert(document.cookie)",
            "file:///etc/hosts",
            "content://com.android.providers.media/images",
            "data:text/html,<h1>Hacked</h1>",
            "blob:https://evil.com/uuid",
            "intent://browser#Intent;scheme=http;package=com.android.chrome;end",
            "market://details?id=com.evil.app",
            "chrome://settings"
        )

        for (url in dangerousUrls) {
            val result = validator.validateUrl(url)
            assertTrue("Dangerous scheme $url must be blocked", result is ValidationResult.Blocked)
            assertEquals(
                "Scheme $url should have UNSUPPORTED_SCHEME reason",
                BlockReason.UNSUPPORTED_SCHEME,
                (result as ValidationResult.Blocked).reason
            )
        }
    }

    @Test
    fun testHostnameNormalization() {
        assertEquals("google.com", UrlSecurityValidator.normalizeHostname("google.com"))
        assertEquals("google.com", UrlSecurityValidator.normalizeHostname("GOOGLE.COM"))
        assertEquals("google.com", UrlSecurityValidator.normalizeHostname("  google.com.  "))
        assertEquals("google.com", UrlSecurityValidator.normalizeHostname("google.com:443"))
        assertEquals("sub.example.com", UrlSecurityValidator.normalizeHostname("sub.example.com:8443"))
        assertNull(UrlSecurityValidator.normalizeHostname(""))
        assertNull(UrlSecurityValidator.normalizeHostname("   "))
    }

    @Test
    fun testDomainSanitization() {
        assertEquals("example.com", UrlSecurityValidator.sanitizeDomainRule("https://example.com/path"))
        assertEquals("example.com", UrlSecurityValidator.sanitizeDomainRule("http://example.com:80/"))
        assertEquals("example.com", UrlSecurityValidator.sanitizeDomainRule("*.example.com"))
        assertEquals("example.com", UrlSecurityValidator.sanitizeDomainRule(" EXAMPLE.COM. "))
    }

    @Test
    fun testAdminPinHashingAndSalting() {
        val pin = "1234"
        val salt = AdminAuthManager.generateRandomSalt()
        val hash1 = AdminAuthManager.hashPinWithSalt(pin, salt)
        val hash2 = AdminAuthManager.hashPinWithSalt(pin, salt)
        val hashDifferentPin = AdminAuthManager.hashPinWithSalt("5678", salt)

        assertEquals("Same PIN and salt produce identical hash", hash1, hash2)
        assertFalse("Different PIN produces different hash", hash1 == hashDifferentPin)

        val salt2 = AdminAuthManager.generateRandomSalt()
        val hashDifferentSalt = AdminAuthManager.hashPinWithSalt(pin, salt2)
        assertFalse("Different salt produces different hash", hash1 == hashDifferentSalt)
    }

    @Test
    fun testAllowlistRuleSerialization() {
        val rule = AllowlistRule("test.org", false, "Test Description", true, 1000L)
        val json = rule.toJsonObject()
        val restored = AllowlistRule.fromJsonObject(json)

        assertEquals(rule.domain, restored.domain)
        assertEquals(rule.allowSubdomains, restored.allowSubdomains)
        assertEquals(rule.description, restored.description)
        assertEquals(rule.enabled, restored.enabled)
        assertEquals(rule.createdAt, restored.createdAt)
    }

    @Test
    fun testBrowserConfigSerialization() {
        val config = BrowserConfig(
            homepage = "https://wikipedia.org",
            enforceHttpsOnly = true,
            enableJavaScript = true,
            kioskModeActive = true,
            adminPinHash = "abcdef",
            adminSalt = "123456"
        )
        val json = config.toJsonObject()
        val restored = BrowserConfig.fromJsonObject(json)

        assertEquals(config.homepage, restored.homepage)
        assertEquals(config.enforceHttpsOnly, restored.enforceHttpsOnly)
        assertEquals(config.enableJavaScript, restored.enableJavaScript)
        assertEquals(config.kioskModeActive, restored.kioskModeActive)
        assertEquals(config.adminPinHash, restored.adminPinHash)
        assertEquals(config.adminSalt, restored.adminSalt)
    }
}
