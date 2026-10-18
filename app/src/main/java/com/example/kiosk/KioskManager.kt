package com.example.kiosk

import android.app.Activity
import android.app.ActivityManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.UserManager
import android.util.Log
import com.example.MainActivity
import com.example.data.SecurityStorage

/**
 * Encapsulates Android Enterprise Device Owner and Lock Task Mode functionality.
 */
class KioskManager(private val context: Context) {

    private val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val adminComponent = ComponentName(context, SecureDeviceAdminReceiver::class.java)
    private val storage = SecurityStorage.getInstance(context)

    companion object {
        private const val TAG = "KioskManager"
        
        fun getAdbProvisioningCommand(context: Context): String {
            val pkg = context.packageName
            val receiver = SecureDeviceAdminReceiver::class.java.name
            return "adb shell dpm set-device-owner $pkg/$receiver"
        }
    }

    /**
     * Checks if this application is provisioned as the Android Enterprise Device Owner.
     */
    fun isDeviceOwner(): Boolean {
        return dpm.isDeviceOwnerApp(context.packageName)
    }

    /**
     * Checks if Lock Task Mode is permitted by the Device Owner policy.
     */
    fun isLockTaskPermitted(): Boolean {
        return dpm.isLockTaskPermitted(context.packageName)
    }

    /**
     * Checks if the device is currently running inside Lock Task Mode.
     */
    fun isLockTaskActive(activity: Activity): Boolean {
        val am = activity.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        return am.lockTaskModeState != ActivityManager.LOCK_TASK_MODE_NONE
    }

    /**
     * Configures dedicated device policies when granted Device Owner privileges.
     */
    fun configureKioskPolicies() {
        if (!isDeviceOwner()) {
            Log.w(TAG, "Cannot configure kiosk policies: app is not Device Owner")
            return
        }

        try {
            // Whitelist this package for Lock Task Mode
            dpm.setLockTaskPackages(adminComponent, arrayOf(context.packageName))

            // On Android 9 (API 28)+, set lock task features (restrict status bar, home button, notifications)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val features = DevicePolicyManager.LOCK_TASK_FEATURE_NONE
                dpm.setLockTaskFeatures(adminComponent, features)
            }

            // Set as default home launcher
            val filter = IntentFilter(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                addCategory(Intent.CATEGORY_DEFAULT)
            }
            val activityComponent = ComponentName(context, MainActivity::class.java)
            dpm.addPersistentPreferredActivity(adminComponent, filter, activityComponent)

            // Prevent factory reset, safe boot, or account additions
            dpm.addUserRestriction(adminComponent, UserManager.DISALLOW_SAFE_BOOT)
            dpm.addUserRestriction(adminComponent, UserManager.DISALLOW_FACTORY_RESET)
            dpm.addUserRestriction(adminComponent, UserManager.DISALLOW_ADD_USER)

            Log.i(TAG, "Dedicated kiosk policies successfully applied by Device Owner")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to apply kiosk policies", e)
        }
    }

    /**
     * Enters Lock Task Mode (kiosk lockdown).
     */
    fun enterKioskMode(activity: Activity) {
        if (isDeviceOwner()) {
            configureKioskPolicies()
        }

        try {
            activity.startLockTask()
            val config = storage.getConfig().copy(kioskModeActive = true)
            storage.saveConfig(config)
            Log.i(TAG, "startLockTask() executed successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Lock Task Mode", e)
        }
    }

    /**
     * Exits Lock Task Mode.
     * Controlled administrator exit procedure.
     */
    fun exitKioskMode(activity: Activity) {
        try {
            activity.stopLockTask()
            val config = storage.getConfig().copy(kioskModeActive = false)
            storage.saveConfig(config)
            Log.i(TAG, "stopLockTask() executed successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop Lock Task Mode", e)
        }
    }
}
