package com.example

import android.content.Intent
import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.webkit.WebView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.example.admin.AdminActivity
import com.example.data.BrowserConfig
import com.example.data.SecurityStorage
import com.example.databinding.ActivityMainBinding
import com.example.kiosk.KioskManager
import com.example.security.BlockReason
import com.example.security.ChromeProgressListener
import com.example.security.NavigationSecurityListener
import com.example.security.SecureWebChromeClient
import com.example.security.SecureWebViewClient
import com.example.security.SecureWebViewConfig
import com.example.security.UrlSecurityValidator
import com.example.security.ValidationResult

class MainActivity : AppCompatActivity(), NavigationSecurityListener, ChromeProgressListener {

    private lateinit var binding: ActivityMainBinding
    private lateinit var storage: SecurityStorage
    private lateinit var validator: UrlSecurityValidator
    private lateinit var kioskManager: KioskManager
    private lateinit var config: BrowserConfig

    private var currentLoadedUrl: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        storage = SecurityStorage.getInstance(this)
        kioskManager = KioskManager(this)
        config = storage.getConfig()

        initValidator()
        initWebView()
        initNavigationControls()
        handleBackNavigation()

        // Load homepage on startup
        loadHomepage()
    }

    override fun onResume() {
        super.onResume()
        // Reload storage config in case admin changed policies
        config = storage.getConfig()
        initValidator()
        SecureWebViewConfig.applySecurityPolicies(binding.webView, config)
        updateKioskBadge()
        updateNavigationButtons()
    }

    private fun initValidator() {
        validator = UrlSecurityValidator(
            allowlistSupplier = { storage.getRules() },
            isHttpsOnlySupplier = { config.enforceHttpsOnly }
        )
    }

    private fun initWebView() {
        SecureWebViewConfig.applySecurityPolicies(binding.webView, config)

        binding.webView.webViewClient = SecureWebViewClient(validator, this)
        binding.webView.webChromeClient = SecureWebChromeClient(this)
    }

    private fun initNavigationControls() {
        // Back Button
        binding.btnBack.setOnClickListener {
            hideErrorOverlays()
            if (binding.webView.canGoBack()) {
                binding.webView.goBack()
            }
        }

        // Forward Button
        binding.btnForward.setOnClickListener {
            hideErrorOverlays()
            if (binding.webView.canGoForward()) {
                binding.webView.goForward()
            }
        }

        // Home Button
        binding.btnHome.setOnClickListener {
            loadHomepage()
        }

        // Refresh Button
        binding.btnRefresh.setOnClickListener {
            hideErrorOverlays()
            val current = binding.webView.url
            if (!current.isNullOrBlank()) {
                navigateToUrl(current)
            } else {
                loadHomepage()
            }
        }

        // Go Button
        binding.btnGo.setOnClickListener {
            triggerUrlNavigation()
        }

        // URL Edit Text Enter/Go Action
        binding.editUrlInput.setOnEditorActionListener { _, actionId, event ->
            if (actionId == EditorInfo.IME_ACTION_GO ||
                (event != null && event.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN)
            ) {
                triggerUrlNavigation()
                true
            } else {
                false
            }
        }

        // Admin Shortcut Button
        binding.btnAdminShortcut.setOnClickListener {
            openAdminPanel()
        }

        // Blocked Screen Action Buttons
        binding.btnBlockedGoHome.setOnClickListener {
            loadHomepage()
        }

        binding.btnBlockedAdminPanel.setOnClickListener {
            openAdminPanel()
        }

        // SSL Error Return Home Button
        binding.btnSslReturnHome.setOnClickListener {
            loadHomepage()
        }
    }

    private fun triggerUrlNavigation() {
        hideKeyboard()
        val rawInput = binding.editUrlInput.text?.toString()?.trim().orEmpty()
        if (rawInput.isBlank()) {
            Toast.makeText(this, R.string.url_hint, Toast.LENGTH_SHORT).show()
            return
        }

        // Prepend https:// if no protocol entered
        val fullUrl = if (!rawInput.startsWith("http://", ignoreCase = true) &&
            !rawInput.startsWith("https://", ignoreCase = true)
        ) {
            "https://$rawInput"
        } else {
            rawInput
        }

        navigateToUrl(fullUrl)
    }

    private fun navigateToUrl(targetUrl: String) {
        val result = validator.validateUrl(targetUrl)
        when (result) {
            is ValidationResult.Allowed -> {
                hideErrorOverlays()
                binding.webView.loadUrl(result.normalizedUrl)
            }
            is ValidationResult.Blocked -> {
                binding.webView.stopLoading()
                showBlockedScreen(result.targetUrl, result.reason, result.detail)
            }
        }
    }

    fun loadHomepage() {
        hideErrorOverlays()
        val homepageUrl = config.homepage
        navigateToUrl(homepageUrl)
    }

    private fun showBlockedScreen(targetUrl: String, reason: BlockReason, detail: String) {
        binding.txtBlockedTargetUrl.text = targetUrl
        val reasonMessage = when (reason) {
            BlockReason.UNAPPROVED_DOMAIN -> getString(R.string.reason_unapproved_domain, detail)
            BlockReason.SUBDOMAIN_DISALLOWED -> getString(R.string.reason_subdomain_disallowed, detail)
            BlockReason.CLEARTEXT_HTTP_BLOCKED -> getString(R.string.reason_http_blocked)
            BlockReason.UNSUPPORTED_SCHEME -> getString(R.string.reason_unsupported_scheme, detail)
            BlockReason.SSL_CERTIFICATE_INVALID -> getString(R.string.reason_ssl_error, detail)
            BlockReason.MALFORMED_URL -> detail
        }
        binding.txtBlockedReasonDetail.text = reasonMessage
        binding.layoutBlockedScreen.visibility = View.VISIBLE
        binding.layoutSslErrorScreen.visibility = View.GONE
        binding.editUrlInput.setText(targetUrl)
    }

    private fun showSslErrorScreen(failingUrl: String, errorDetails: String) {
        binding.txtSslErrorDetail.text = getString(R.string.reason_ssl_error, errorDetails)
        binding.layoutSslErrorScreen.visibility = View.VISIBLE
        binding.layoutBlockedScreen.visibility = View.GONE
        binding.editUrlInput.setText(failingUrl)
    }

    private fun hideErrorOverlays() {
        binding.layoutBlockedScreen.visibility = View.GONE
        binding.layoutSslErrorScreen.visibility = View.GONE
    }

    private fun updateKioskBadge() {
        val isLocked = kioskManager.isLockTaskActive(this)
        if (isLocked) {
            binding.txtModeBadge.text = getString(R.string.mode_kiosk_badge)
            binding.txtModeBadge.setBackgroundResource(R.drawable.bg_badge_kiosk)
        } else {
            binding.txtModeBadge.text = getString(R.string.mode_normal_badge)
            binding.txtModeBadge.setBackgroundResource(R.drawable.bg_card)
        }
    }

    private fun updateNavigationButtons() {
        binding.btnBack.isEnabled = binding.webView.canGoBack() || binding.layoutBlockedScreen.visibility == View.VISIBLE
        binding.btnBack.alpha = if (binding.btnBack.isEnabled) 1.0f else 0.4f

        binding.btnForward.isEnabled = binding.webView.canGoForward()
        binding.btnForward.alpha = if (binding.btnForward.isEnabled) 1.0f else 0.4f
    }

    private fun handleBackNavigation() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (binding.layoutBlockedScreen.visibility == View.VISIBLE ||
                    binding.layoutSslErrorScreen.visibility == View.VISIBLE
                ) {
                    loadHomepage()
                    return
                }

                if (binding.webView.canGoBack()) {
                    binding.webView.goBack()
                    return
                }

                // If in Kiosk Mode, intercept back navigation to prevent exiting to OS launcher
                if (kioskManager.isLockTaskActive(this@MainActivity)) {
                    Toast.makeText(this@MainActivity, "Kiosk Mode is active. Use Admin panel to exit.", Toast.LENGTH_SHORT).show()
                    return
                }

                // Normal browser mode: finish activity
                isEnabled = false
                onBackPressedDispatcher.onBackPressed()
            }
        })
    }

    private fun openAdminPanel() {
        val intent = Intent(this, AdminActivity::class.java)
        startActivity(intent)
    }

    private fun hideKeyboard() {
        val imm = getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager
        currentFocus?.let {
            imm.hideSoftInputFromWindow(it.windowToken, 0)
        }
    }

    // --- NavigationSecurityListener Implementation ---

    override fun onNavigationAllowed(url: String) {
        currentLoadedUrl = url
        runOnUiThread {
            hideErrorOverlays()
            binding.editUrlInput.setText(url)
            updateNavigationButtons()
        }
    }

    override fun onNavigationBlocked(url: String, reason: BlockReason, detail: String) {
        runOnUiThread {
            showBlockedScreen(url, reason, detail)
            updateNavigationButtons()
        }
    }

    override fun onPageLoadingStarted(url: String?) {
        runOnUiThread {
            binding.progressLoading.visibility = View.VISIBLE
            url?.let {
                binding.editUrlInput.setText(it)
            }
            updateNavigationButtons()
        }
    }

    override fun onPageLoadingFinished(url: String?) {
        runOnUiThread {
            binding.progressLoading.visibility = View.GONE
            url?.let {
                currentLoadedUrl = it
                binding.editUrlInput.setText(it)
            }
            updateNavigationButtons()
        }
    }

    override fun onSslErrorEncountered(url: String, detail: String) {
        runOnUiThread {
            showSslErrorScreen(url, detail)
            updateNavigationButtons()
        }
    }

    override fun onRendererCrashed() {
        runOnUiThread {
            Toast.makeText(this, R.string.reason_renderer_crashed, Toast.LENGTH_LONG).show()
            initWebView()
            loadHomepage()
        }
    }

    // --- ChromeProgressListener Implementation ---

    override fun onProgressChanged(progress: Int) {
        runOnUiThread {
            binding.progressLoading.progress = progress
            if (progress >= 100) {
                binding.progressLoading.visibility = View.GONE
            } else {
                binding.progressLoading.visibility = View.VISIBLE
            }
        }
    }

    override fun onReceivedTitle(title: String?) {
        // Optionally update header or subtitle
    }

    override fun onPopupAttemptBlocked() {
        runOnUiThread {
            Toast.makeText(this, "Popup window blocked by security policy.", Toast.LENGTH_SHORT).show()
        }
    }
}
