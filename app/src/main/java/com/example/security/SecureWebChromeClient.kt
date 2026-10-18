package com.example.security

import android.os.Message
import android.util.Log
import android.webkit.WebChromeClient
import android.webkit.WebView

interface ChromeProgressListener {
    fun onProgressChanged(progress: Int)
    fun onReceivedTitle(title: String?)
    fun onPopupAttemptBlocked()
}

/**
 * Hardened WebChromeClient that reports loading progress, blocks unapproved
 * popup windows, and prevents unauthorized system interactions.
 */
class SecureWebChromeClient(
    private val listener: ChromeProgressListener
) : WebChromeClient() {

    companion object {
        private const val TAG = "SecureChromeClient"
    }

    override fun onProgressChanged(view: WebView?, newProgress: Int) {
        super.onProgressChanged(view, newProgress)
        listener.onProgressChanged(newProgress)
    }

    override fun onReceivedTitle(view: WebView?, title: String?) {
        super.onReceivedTitle(view, title)
        listener.onReceivedTitle(title)
    }

    /**
     * Intercepts window.open() or target="_blank" popup attempts.
     * Denies creation of untracked subsidiary windows to prevent security escapes.
     */
    override fun onCreateWindow(
        view: WebView?,
        isDialog: Boolean,
        isUserGesture: Boolean,
        resultMsg: Message?
    ): Boolean {
        Log.w(TAG, "Blocked popup / window creation attempt (isDialog=$isDialog, isUserGesture=$isUserGesture)")
        listener.onPopupAttemptBlocked()
        return false // Return false to indicate the app does not support opening new windows
    }
}
