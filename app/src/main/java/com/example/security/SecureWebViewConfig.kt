package com.example.security

import android.annotation.SuppressLint
import android.os.Build
import android.webkit.WebSettings
import android.webkit.WebView
import com.example.data.BrowserConfig

/**
 * Hardened security configuration for Android WebView.
 * Enables modern web execution (SPAs, React, Angular, Vue) while strictly
 * locking down file, content, mixed-content, and bridge attack vectors.
 */
object SecureWebViewConfig {

    @SuppressLint("SetJavaScriptEnabled")
    fun applySecurityPolicies(webView: WebView, config: BrowserConfig) {
        val settings = webView.settings

        // JavaScript support (Configurable, enabled by default for modern web/SPAs)
        settings.javaScriptEnabled = config.enableJavaScript

        // Modern DOM storage for Single-Page Applications
        settings.domStorageEnabled = config.enableJavaScript

        // File and local storage restrictions (Prevent local file exfiltration)
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.allowFileAccessFromFileURLs = false
        settings.allowUniversalAccessFromFileURLs = false

        // Mixed Content Security: Strictly block unencrypted HTTP sub-resources on HTTPS pages
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW

        // Window & Popup Security
        settings.setSupportMultipleWindows(false)
        settings.javaScriptCanOpenWindowsAutomatically = !config.blockPopups

        // Privacy & Credentials: Do not retain sensitive user form autofill
        settings.saveFormData = false

        // Built-in Google Safe Browsing
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            settings.safeBrowsingEnabled = true
        }

        // Cache mode & Responsive viewport
        settings.cacheMode = WebSettings.LOAD_DEFAULT
        settings.useWideViewPort = true
        settings.loadWithOverviewMode = true
        settings.builtInZoomControls = true
        settings.displayZoomControls = false

        // Remove legacy insecure reflection interfaces
        webView.removeJavascriptInterface("searchBoxJavaBridge_")
        webView.removeJavascriptInterface("accessibility")
        webView.removeJavascriptInterface("accessibilityTraversal")
    }
}
