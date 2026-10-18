package com.example.admin

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.webkit.CookieManager
import android.webkit.WebStorage
import android.webkit.WebView
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.R
import com.example.data.AllowlistRule
import com.example.data.SecurityStorage
import com.example.databinding.ActivityAdminBinding
import com.example.kiosk.KioskManager
import com.example.security.UrlSecurityValidator
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText

class AdminActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAdminBinding
    private lateinit var storage: SecurityStorage
    private lateinit var authManager: AdminAuthManager
    private lateinit var kioskManager: KioskManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAdminBinding.inflate(layoutInflater)
        setContentView(binding.root)

        storage = SecurityStorage.getInstance(this)
        authManager = AdminAuthManager(this)
        kioskManager = KioskManager(this)

        setupToolbar()

        // Check if admin session is active
        if (!authManager.isSessionActive()) {
            promptAdminAuthentication()
        } else {
            initUi()
        }
    }

    private fun setupToolbar() {
        binding.adminToolbar.setNavigationOnClickListener {
            finish()
        }
    }

    private fun promptAdminAuthentication() {
        val isConfigured = authManager.isPinConfigured()
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_admin_auth, null)
        val txtTitle = dialogView.findViewById<TextView>(R.id.txt_auth_dialog_title)
        val txtMsg = dialogView.findViewById<TextView>(R.id.txt_auth_dialog_message)
        val editPin = dialogView.findViewById<TextInputEditText>(R.id.edit_pin_input)
        val editConfirm = dialogView.findViewById<TextInputEditText>(R.id.edit_pin_confirm)
        val layoutConfirm = dialogView.findViewById<View>(R.id.layout_pin_confirm)
        val txtError = dialogView.findViewById<TextView>(R.id.txt_auth_error)

        if (!isConfigured) {
            txtTitle.text = getString(R.string.admin_pin_setup_prompt)
            txtMsg.text = getString(R.string.admin_pin_setup_prompt)
            layoutConfirm.visibility = View.VISIBLE
        } else {
            txtTitle.text = getString(R.string.admin_auth_title)
            txtMsg.text = getString(R.string.admin_pin_prompt)
            layoutConfirm.visibility = View.GONE
        }

        val dialog = AlertDialog.Builder(this)
            .setView(dialogView)
            .setCancelable(false)
            .setPositiveButton(if (isConfigured) R.string.btn_authenticate else R.string.btn_save, null)
            .setNegativeButton(R.string.btn_cancel) { _, _ -> finish() }
            .create()

        dialog.setOnShowListener {
            val submitBtn = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            submitBtn.setOnClickListener {
                val enteredPin = editPin.text?.toString().orEmpty()

                if (!isConfigured) {
                    val confirmPin = editConfirm.text?.toString().orEmpty()
                    if (enteredPin.length < 4) {
                        txtError.text = getString(R.string.admin_pin_too_short)
                        txtError.visibility = View.VISIBLE
                        return@setOnClickListener
                    }
                    if (enteredPin != confirmPin) {
                        txtError.text = getString(R.string.admin_pin_mismatch)
                        txtError.visibility = View.VISIBLE
                        return@setOnClickListener
                    }
                    authManager.setupPin(enteredPin)
                    Toast.makeText(this, R.string.admin_pin_updated, Toast.LENGTH_SHORT).show()
                    dialog.dismiss()
                    initUi()
                } else {
                    try {
                        if (authManager.authenticate(enteredPin)) {
                            dialog.dismiss()
                            initUi()
                        } else {
                            txtError.text = getString(R.string.admin_pin_incorrect)
                            txtError.visibility = View.VISIBLE
                        }
                    } catch (se: SecurityException) {
                        txtError.text = se.message
                        txtError.visibility = View.VISIBLE
                    }
                }
            }
        }
        dialog.show()
    }

    private fun initUi() {
        loadBrowserConfig()
        renderKioskStatus()
        refreshAllowlistUi()
        bindActionListeners()
    }

    private fun renderKioskStatus() {
        val isOwner = kioskManager.isDeviceOwner()
        val isLocked = kioskManager.isLockTaskActive(this)

        binding.txtDeviceOwnerStatus.text = if (isOwner) {
            getString(R.string.kiosk_status_owner, getString(R.string.kiosk_owner_active))
        } else {
            getString(R.string.kiosk_status_owner, getString(R.string.kiosk_owner_inactive))
        }

        binding.txtLockTaskStatus.text = if (isLocked) {
            getString(R.string.kiosk_mode_active)
        } else {
            getString(R.string.kiosk_mode_inactive)
        }

        binding.btnToggleKiosk.text = if (isLocked) {
            getString(R.string.btn_exit_kiosk)
        } else {
            getString(R.string.btn_enter_kiosk)
        }
    }

    private fun loadBrowserConfig() {
        val config = storage.getConfig()
        binding.editHomepageUrl.setText(config.homepage)
        binding.switchHttpsOnly.isChecked = config.enforceHttpsOnly
        binding.switchJavascript.isChecked = config.enableJavaScript
    }

    private fun refreshAllowlistUi() {
        val rules = storage.getRules()
        binding.containerRulesList.removeAllViews()
        binding.txtAllowlistHeader.text = "Approved Domains (${rules.size})"

        if (rules.isEmpty()) {
            binding.txtEmptyAllowlist.visibility = View.VISIBLE
            return
        } else {
            binding.txtEmptyAllowlist.visibility = View.GONE
        }

        val inflater = LayoutInflater.from(this)
        for (rule in rules) {
            val itemView = inflater.inflate(R.layout.item_domain_rule, binding.containerRulesList, false)
            val txtDomain = itemView.findViewById<TextView>(R.id.txt_domain_name)
            val txtSub = itemView.findViewById<TextView>(R.id.txt_subdomain_status)
            val txtDesc = itemView.findViewById<TextView>(R.id.txt_rule_description)
            val switchEnabled = itemView.findViewById<MaterialSwitch>(R.id.switch_rule_enabled)
            val btnDelete = itemView.findViewById<ImageButton>(R.id.btn_delete_rule)

            txtDomain.text = rule.domain
            txtSub.text = if (rule.allowSubdomains) {
                "Subdomains allowed (*.${rule.normalizedDomain()})"
            } else {
                "Exact domain only (${rule.normalizedDomain()})"
            }

            if (rule.description.isNotBlank()) {
                txtDesc.text = rule.description
                txtDesc.visibility = View.VISIBLE
            } else {
                txtDesc.visibility = View.GONE
            }

            switchEnabled.isChecked = rule.enabled
            switchEnabled.setOnCheckedChangeListener { _, isChecked ->
                storage.updateRule(rule.copy(enabled = isChecked))
            }

            btnDelete.setOnClickListener {
                AlertDialog.Builder(this)
                    .setTitle("Remove Domain")
                    .setMessage("Remove '${rule.domain}' from allowlist?")
                    .setPositiveButton(R.string.btn_delete) { _, _ ->
                        storage.removeRule(rule.domain)
                        refreshAllowlistUi()
                        Toast.makeText(this, getString(R.string.domain_deleted, rule.domain), Toast.LENGTH_SHORT).show()
                    }
                    .setNegativeButton(R.string.btn_cancel, null)
                    .show()
            }

            binding.containerRulesList.addView(itemView)
        }
    }

    private fun bindActionListeners() {
        binding.btnSaveHomepage.setOnClickListener {
            val newHomepage = binding.editHomepageUrl.text?.toString()?.trim().orEmpty()
            if (newHomepage.isBlank()) {
                Toast.makeText(this, "Homepage cannot be empty", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val sanitized = if (!newHomepage.startsWith("http://") && !newHomepage.startsWith("https://")) {
                "https://$newHomepage"
            } else {
                newHomepage
            }
            val updated = storage.getConfig().copy(
                homepage = sanitized,
                lastUpdated = System.currentTimeMillis()
            )
            storage.saveConfig(updated)
            binding.editHomepageUrl.setText(sanitized)
            Toast.makeText(this, "Homepage updated to: $sanitized", Toast.LENGTH_SHORT).show()
        }

        binding.switchHttpsOnly.setOnCheckedChangeListener { _, isChecked ->
            val updated = storage.getConfig().copy(
                enforceHttpsOnly = isChecked,
                lastUpdated = System.currentTimeMillis()
            )
            storage.saveConfig(updated)
        }

        binding.switchJavascript.setOnCheckedChangeListener { _, isChecked ->
            val updated = storage.getConfig().copy(
                enableJavaScript = isChecked,
                lastUpdated = System.currentTimeMillis()
            )
            storage.saveConfig(updated)
        }

        binding.btnAddDomain.setOnClickListener {
            showAddDomainDialog()
        }

        binding.btnToggleKiosk.setOnClickListener {
            if (kioskManager.isLockTaskActive(this)) {
                kioskManager.exitKioskMode(this)
                Toast.makeText(this, R.string.kiosk_stopped, Toast.LENGTH_SHORT).show()
            } else {
                kioskManager.enterKioskMode(this)
                Toast.makeText(this, R.string.kiosk_started, Toast.LENGTH_SHORT).show()
            }
            renderKioskStatus()
        }

        binding.btnShowAdbCommand.setOnClickListener {
            showAdbInstructionsDialog()
        }

        binding.btnExportAllowlist.setOnClickListener {
            val json = storage.exportAllowlistJson()
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("SecureBrowse Allowlist", json)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, R.string.export_success, Toast.LENGTH_LONG).show()
        }

        binding.btnImportAllowlist.setOnClickListener {
            showImportDialog()
        }

        binding.btnChangeAdminPin.setOnClickListener {
            showChangePinDialog()
        }

        binding.btnClearBrowsingData.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Clear Browsing Data")
                .setMessage("This will remove all cached web data, DOM storage, and cookies.")
                .setPositiveButton("Clear") { _, _ ->
                    clearBrowsingData()
                }
                .setNegativeButton(R.string.btn_cancel, null)
                .show()
        }
    }

    private fun showAddDomainDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_add_domain, null)
        val editDomain = dialogView.findViewById<TextInputEditText>(R.id.edit_domain_input)
        val checkSubdomains = dialogView.findViewById<CheckBox>(R.id.checkbox_allow_subdomains)
        val editDesc = dialogView.findViewById<TextInputEditText>(R.id.edit_domain_description)

        AlertDialog.Builder(this)
            .setView(dialogView)
            .setPositiveButton(R.string.btn_add) { _, _ ->
                val rawDomain = editDomain.text?.toString()?.trim().orEmpty()
                val clean = UrlSecurityValidator.sanitizeDomainRule(rawDomain)

                if (clean.isBlank() || !clean.contains(".")) {
                    Toast.makeText(this, R.string.domain_invalid, Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                val rule = AllowlistRule(
                    domain = clean,
                    allowSubdomains = checkSubdomains.isChecked,
                    description = editDesc.text?.toString()?.trim().orEmpty(),
                    enabled = true
                )

                if (storage.addRule(rule)) {
                    refreshAllowlistUi()
                    Toast.makeText(this, getString(R.string.domain_added, clean), Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, getString(R.string.domain_already_exists, clean), Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(R.string.btn_cancel, null)
            .show()
    }

    private fun showImportDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_import_allowlist, null)
        val editJson = dialogView.findViewById<TextInputEditText>(R.id.edit_json_input)

        AlertDialog.Builder(this)
            .setView(dialogView)
            .setPositiveButton("Import") { _, _ ->
                val json = editJson.text?.toString()?.trim().orEmpty()
                val (success, count) = storage.importAllowlistJson(json)
                if (success) {
                    refreshAllowlistUi()
                    Toast.makeText(this, getString(R.string.import_success, count), Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, R.string.import_error, Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton(R.string.btn_cancel, null)
            .show()
    }

    private fun showChangePinDialog() {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_admin_auth, null)
        val txtTitle = dialogView.findViewById<TextView>(R.id.txt_auth_dialog_title)
        val txtMsg = dialogView.findViewById<TextView>(R.id.txt_auth_dialog_message)
        val editPin = dialogView.findViewById<TextInputEditText>(R.id.edit_pin_input)
        val editConfirm = dialogView.findViewById<TextInputEditText>(R.id.edit_pin_confirm)
        val layoutConfirm = dialogView.findViewById<View>(R.id.layout_pin_confirm)
        val txtError = dialogView.findViewById<TextView>(R.id.txt_auth_error)

        txtTitle.text = "Update Administrator PIN"
        txtMsg.text = "Enter a new PIN (minimum 4 digits)"
        layoutConfirm.visibility = View.VISIBLE

        val dialog = AlertDialog.Builder(this)
            .setView(dialogView)
            .setPositiveButton(R.string.btn_save, null)
            .setNegativeButton(R.string.btn_cancel, null)
            .create()

        dialog.setOnShowListener {
            val btn = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            btn.setOnClickListener {
                val newPin = editPin.text?.toString().orEmpty()
                val confirmPin = editConfirm.text?.toString().orEmpty()
                if (newPin.length < 4) {
                    txtError.text = getString(R.string.admin_pin_too_short)
                    txtError.visibility = View.VISIBLE
                    return@setOnClickListener
                }
                if (newPin != confirmPin) {
                    txtError.text = getString(R.string.admin_pin_mismatch)
                    txtError.visibility = View.VISIBLE
                    return@setOnClickListener
                }
                authManager.setupPin(newPin)
                Toast.makeText(this, R.string.admin_pin_updated, Toast.LENGTH_SHORT).show()
                dialog.dismiss()
            }
        }
        dialog.show()
    }

    private fun showAdbInstructionsDialog() {
        val command = KioskManager.getAdbProvisioningCommand(this)
        AlertDialog.Builder(this)
            .setTitle("Provision Device Owner via ADB")
            .setMessage("On a newly factory-reset or test device with developer options enabled, run:\n\n$command\n\nNote: If accounts already exist on the device, Android prevents setting Device Owner until the device is reset.")
            .setPositiveButton("Copy Command") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("ADB Command", command)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "ADB command copied to clipboard", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun clearBrowsingData() {
        try {
            WebView(this).clearCache(true)
            CookieManager.getInstance().removeAllCookies(null)
            CookieManager.getInstance().flush()
            WebStorage.getInstance().deleteAllData()
            Toast.makeText(this, R.string.data_cleared, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Error clearing data: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
