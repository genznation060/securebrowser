package com.example.security

import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Build
import android.util.Log
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient

interface NavigationSecurityListener {
    fun onNavigationAllowed(url: String)
    fun onNavigationBlocked(url: String, reason: BlockReason, detail: String)
    fun onPageLoadingStarted(url: String?)
    fun onPageLoadingFinished(url: String?)
    fun onSslErrorEncountered(url: String, detail: String)
    fun onRendererCrashed()
}

/**
 * Hardened WebViewClient enforcing strict URL validation, blocking unapproved
 * navigations, and terminating invalid SSL certificate attempts.
 */
class SecureWebViewClient(
    private val validator: UrlSecurityValidator,
    private val listener: NavigationSecurityListener
) : WebViewClient() {

    companion object {
        private const val TAG = "SecureWebViewClient"
    }

    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        if (request == null || request.url == null) return false
        val url = request.url.toString()
        return handleUrlNavigation(view, url, isForMainFrame = request.isForMainFrame)
    }

    @Deprecated("Deprecated in Java")
    override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean {
        if (url == null) return false
        return handleUrlNavigation(view, url, isForMainFrame = true)
    }

    private fun handleUrlNavigation(view: WebView?, url: String, isForMainFrame: Boolean): Boolean {
        // Validate URL against administrator allowlist and security policy
        val result = validator.validateUrl(url)

        return when (result) {
            is ValidationResult.Allowed -> {
                listener.onNavigationAllowed(result.normalizedUrl)
                false // Allow WebView to proceed with navigation internally
            }
            is ValidationResult.Blocked -> {
                Log.w(TAG, "Blocked navigation to: $url (Reason: ${result.reason}, Detail: ${result.detail})")
                // Prevent WebView from following the link or redirect
                view?.stopLoading()
                listener.onNavigationBlocked(result.targetUrl, result.reason, result.detail)
                true // Navigation intercepted and blocked
            }
        }
    }

    override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
        super.onPageStarted(view, url, favicon)
        listener.onPageLoadingStarted(url)

        // Defense-in-depth: Re-check server redirects
        if (url != null && !url.equals("about:blank", ignoreCase = true)) {
            val result = validator.validateUrl(url)
            if (result is ValidationResult.Blocked) {
                Log.w(TAG, "Intercepted unapproved server redirect: $url")
                view?.stopLoading()
                listener.onNavigationBlocked(result.targetUrl, result.reason, result.detail)
            }
        }
    }

    override fun onPageFinished(view: WebView?, url: String?) {
        super.onPageFinished(view, url)
        listener.onPageLoadingFinished(url)
    }

    /**
     * CRITICAL SECURITY IMPLEMENTATION:
     * NEVER call handler.proceed()! Doing so permits Man-In-The-Middle (MITM) attacks.
     * All SSL/TLS certificate failures must be cancelled immediately.
     */
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        val failingUrl = error?.url ?: view?.url ?: "Unknown URL"
        val errorDescription = getSslErrorMessage(error)
        Log.e(TAG, "SSL certificate validation failed for: $failingUrl. Error: $errorDescription")

        // Strictly cancel the connection
        handler?.cancel()

        listener.onSslErrorEncountered(failingUrl, errorDescription)
    }

    private fun getSslErrorMessage(error: SslError?): String {
        if (error == null) return "Unknown SSL Error"
        return when (error.primaryError) {
            SslError.SSL_EXPIRED -> "The SSL certificate has expired."
            SslError.SSL_IDMISMATCH -> "Hostname does not match the certificate."
            SslError.SSL_UNTRUSTED -> "The certificate authority (CA) is untrusted."
            SslError.SSL_NOTYETVALID -> "The SSL certificate is not yet valid."
            SslError.SSL_DATE_INVALID -> "The date of the certificate is invalid."
            else -> "Generic SSL validation failure (Code: ${error.primaryError})."
        }
    }

    override fun onRenderProcessGone(view: WebView?, detail: RenderProcessGoneDetail?): Boolean {
        Log.e(TAG, "WebView render process died. Did crash: ${detail?.didCrash()}")
        listener.onRendererCrashed()
        // Returning true informs the system that the application handled the crash gracefully
        return true
    }

    override fun onReceivedError(
        view: WebView?,
        request: WebResourceRequest?,
        error: WebResourceError?
    ) {
        super.onReceivedError(view, request, error)
        if (request?.isForMainFrame == true) {
            val description = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                error?.description?.toString() ?: "Network error"
            } else {
                "Network error"
            }
            Log.w(TAG, "Main-frame loading error: $description on ${request.url}")
        }
    }
}
