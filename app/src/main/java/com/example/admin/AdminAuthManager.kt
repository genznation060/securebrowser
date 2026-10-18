package com.example.admin

import android.content.Context
import com.example.data.SecurityStorage
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale

/**
 * Manages administrator authentication using salted SHA-256 cryptographic hashing.
 * Enforces brute-force delay throttling and local session tracking.
 *
 * NOTE: Local PIN authentication provides application-level access control.
 * It does not protect against physical memory dumping or substitute for
 * Android Enterprise hardware-backed Knox/SEAndroid encryption.
 */
class AdminAuthManager(context: Context) {

    private val storage = SecurityStorage.getInstance(context)

    companion object {
        private const val MAX_ATTEMPTS_BEFORE_LOCKOUT = 5
        private const val LOCKOUT_DURATION_MS = 30_000L // 30 seconds
        private const val SESSION_TIMEOUT_MS = 5 * 60 * 1000L // 5 minutes

        @Volatile
        private var lastAuthenticatedTimestamp: Long = 0L

        @Volatile
        private var failedAttemptCount: Int = 0

        @Volatile
        private var lockoutUntilTimestamp: Long = 0L

        /**
         * Computes salted SHA-256 hash formatted in hexadecimal.
         */
        fun hashPinWithSalt(pin: String, saltHex: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val input = "$saltHex:$pin"
            val hashBytes = digest.digest(input.toByteArray(Charsets.UTF_8))
            return hashBytes.joinToString("") { "%02x".format(it) }
        }

        /**
         * Generates a cryptographically secure random 16-byte salt as hex string.
         */
        fun generateRandomSalt(): String {
            val random = SecureRandom()
            val saltBytes = ByteArray(16)
            random.nextBytes(saltBytes)
            return saltBytes.joinToString("") { "%02x".format(it) }
        }
    }

    /**
     * Checks if an admin PIN has been initialized.
     */
    fun isPinConfigured(): Boolean {
        val config = storage.getConfig()
        return config.adminPinHash.isNotBlank() && config.adminSalt.isNotBlank()
    }

    /**
     * Checks if an active authenticated session is currently valid.
     */
    fun isSessionActive(): Boolean {
        val now = System.currentTimeMillis()
        return (now - lastAuthenticatedTimestamp) < SESSION_TIMEOUT_MS
    }

    fun endSession() {
        lastAuthenticatedTimestamp = 0L
    }

    /**
     * Sets or updates the administrator PIN.
     */
    fun setupPin(newPin: String): Boolean {
        if (newPin.length < 4) return false

        val salt = generateRandomSalt()
        val hash = hashPinWithSalt(newPin, salt)
        val config = storage.getConfig().copy(
            adminPinHash = hash,
            adminSalt = salt,
            lastUpdated = System.currentTimeMillis()
        )
        storage.saveConfig(config)
        lastAuthenticatedTimestamp = System.currentTimeMillis()
        failedAttemptCount = 0
        lockoutUntilTimestamp = 0L
        return true
    }

    /**
     * Authenticates an entered PIN.
     * Returns true if correct, false otherwise.
     * Throws SecurityException if locked out due to brute-force throttling.
     */
    fun authenticate(pin: String): Boolean {
        val now = System.currentTimeMillis()
        if (now < lockoutUntilTimestamp) {
            val remainingSec = ((lockoutUntilTimestamp - now) / 1000).coerceAtLeast(1)
            throw SecurityException("Too many incorrect attempts. Please wait $remainingSec seconds.")
        }

        val config = storage.getConfig()
        if (config.adminPinHash.isBlank() || config.adminSalt.isBlank()) {
            return false
        }

        val computedHash = hashPinWithSalt(pin, config.adminSalt)
        // Constant-time equals to mitigate timing attacks
        val isMatch = MessageDigest.isEqual(
            computedHash.toByteArray(Charsets.UTF_8),
            config.adminPinHash.toByteArray(Charsets.UTF_8)
        )

        if (isMatch) {
            failedAttemptCount = 0
            lockoutUntilTimestamp = 0L
            lastAuthenticatedTimestamp = System.currentTimeMillis()
            return true
        } else {
            failedAttemptCount++
            if (failedAttemptCount >= MAX_ATTEMPTS_BEFORE_LOCKOUT) {
                lockoutUntilTimestamp = System.currentTimeMillis() + LOCKOUT_DURATION_MS
                failedAttemptCount = 0
            }
            return false
        }
    }
}
