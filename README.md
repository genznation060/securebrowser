# SecureBrowse: Restricted Enterprise Kiosk Browser for Android

SecureBrowse is a restricted Android web browser designed for kiosk, educational, and enterprise dedicated-device environments. It enforces strict website allowlisting, blocks all unapproved domains, supports modern JavaScript Single-Page Applications (React, Angular, Vue), and integrates Android Enterprise Lock Task Mode.

---

## 1. Key Capabilities & Architecture

- **Strict Domain Allowlist**: Only administrator-approved domains and their authorized subdomains can be accessed. All unapproved hostnames, protocols, and redirects are blocked before navigation begins.
- **Lookalike & Subdomain Protection**: Robust hostname parsing prevents lookalike domain attacks (e.g. `google.com.attacker.com` or `evilgoogle.com` targeting `google.com`).
- **HTTPS Enforcement**: Cleartext HTTP traffic is blocked by default with `android:usesCleartextTraffic="false"`.
- **Zero-Bypass SSL/TLS Validation**: Invalid, expired, self-signed, or mismatched SSL certificates are cancelled immediately via `handler.cancel()`. SSL checks are never bypassed.
- **Popup & New Window Interception**: Subsidiary windows and popups (`window.open()`, `target="_blank"`) are intercepted to prevent security escapes.
- **Modern JavaScript Support**: Enables modern JavaScript execution and DOM storage for complex SPAs while strictly keeping local file access (`allowFileAccess = false`) and content access disabled.
- **Dual Operating Modes**:
  1. *Normal Browser Mode*: For setup, testing, and evaluation on personal devices.
  2. *Locked Kiosk Mode*: Fully managed dedicated device lockdown using Android Enterprise `DevicePolicyManager` and `LockTaskMode`.
- **Protected Administrator Console**: Salted SHA-256 PIN authentication with brute-force lockout throttling protects settings, rule management, and JSON backup/restore.

---

## 2. Operating Modes & Security Boundaries

### Normal Mode (Unmanaged / Testing)
- Operates as a standard browser application on personal Android devices.
- Uses Android Screen Pinning when kiosk lockdown is tested without Device Owner privileges.
- **Important Limitation**: A standard Android browser app cannot prevent users from opening other browsers installed on an unmanaged personal device (such as Chrome or Samsung Internet). Device-wide lockdown requires Android Enterprise Device Owner provisioning.

### Dedicated Kiosk Mode (Android Enterprise Device Owner)
- When provisioned as the **Device Owner** via ADB or QR provisioning during device setup:
  - The browser is registered in `dpm.setLockTaskPackages()`.
  - Android Lock Task Mode pins SecureBrowse to the foreground.
  - The Home button, Recent Apps overview, Notifications shade, and Settings access are suppressed.
  - SecureBrowse is set as the default persistent home launcher (`Intent.CATEGORY_HOME`).
  - Safe boot and factory reset can be disallowed.
- **Administrator Exit Procedure**:
  1. Tap the **Admin** button in the top navigation bar.
  2. Enter the administrator PIN.
  3. In the Kiosk Mode section, tap **Exit Kiosk Lockdown** (`dpm.stopLockTask()`).

---

## 3. Building and Running the Application

### Prerequisites
- Android Studio Ladybug / Meerkat (or newer)
- Android SDK 34+ (compileSdk 36, minSdk 24)
- JDK 17 or JDK 21

### Step-by-Step Build Instructions

1. **Open Project**:
   - Open Android Studio.
   - Select **File > Open** and select the project directory.

2. **Sync Gradle**:
   - Allow Android Studio to sync Gradle dependencies.

3. **Build Debug APK via Gradle**:
   Run from the terminal:
   ```bash
   gradle assembleDebug
   ```
   Or inside Android Studio: **Build > Build Bundle(s) / APK(s) > Build APK(s)**.

4. **Debug APK Location**:
   Upon compilation, the debug APK is generated at:
   ```
   app/build/outputs/apk/debug/app-debug.apk
   ```

5. **Generate Signed Release APK**:
   In Android Studio, select **Build > Generate Signed Bundle / APK > APK**, choose your keystore, and select the `release` build variant. Or run:
   ```bash
   gradle assembleRelease
   ```

6. **Install on Device via ADB**:
   ```bash
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```

---

## 4. Provisioning a Dedicated Kiosk Device (Device Owner)

To achieve true kiosk lockdown where users cannot exit to system settings or launch other applications, provision the app as **Device Owner**:

### Option A: Via ADB (Recommended for Testing Devices)
1. Factory reset the Android test device (or remove all user accounts under **Settings > Accounts**).
2. Enable **Developer Options** and **USB Debugging**.
3. Connect the device via USB and install the APK:
   ```bash
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```
4. Set SecureBrowse as the Device Owner using the package and receiver:
   ```bash
   adb shell dpm set-device-owner com.aistudio.securebrowse.kpvxza/com.example.kiosk.SecureDeviceAdminReceiver
   ```
5. You will see the confirmation message:
   `Success: Device owner set to package com.aistudio.securebrowse.kpvxza`
6. Open SecureBrowse. The Kiosk status card will now display **PROVISIONED (Full Device Owner)**.

### Option B: Via Android Enterprise QR Provisioning (Production Deployment)
During the initial "Welcome" screen on a factory-reset device, tap the screen 6 times in the same spot to launch the QR scanner, then scan a provisioning payload referencing your hosted APK URL and checksum:
```json
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.aistudio.securebrowse.kpvxza/com.example.kiosk.SecureDeviceAdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": "https://your-server.com/securebrowse.apk",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": "<SHA-256-CHECKSUM>",
  "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": false
}
```

---

## 5. Security Architecture & Threat Model

| Security Vector | Implementation in SecureBrowse |
|---|---|
| **Host Matching** | Strips port/path, enforces lowercase comparison, matches exact or `.` + domain |
| **Lookalike Protection** | Blocks suffix masquerades (e.g. `google.com.attacker.com` is denied) |
| **Cleartext HTTP** | Blocked via `android:usesCleartextTraffic="false"` and validator policy |
| **Dangerous Schemes** | `javascript:`, `file:`, `content:`, `intent:`, `data:` explicitly blocked |
| **SSL/TLS Tampering** | `onReceivedSslError` invokes `handler.cancel()`; bypass strictly forbidden |
| **Popups & Iframes** | Window creation rejected in WebChromeClient; frame navigations validated |
| **Credential Security** | Admin PIN hashed with salted SHA-256 (`SecureRandom` 16-byte salt) |
| **Brute-Force Guard** | 30-second lockout throttle after 5 consecutive incorrect attempts |
| **Renderer Crashes** | Handled in `onRenderProcessGone` with safe reload to avoid app crashes |

### Honest Security Disclosures & Limitations
1. **Device-Wide vs Application-Level**: A browser allowlist operates strictly inside SecureBrowse. It does not filter network packets generated by other applications or the Android OS unless the device is locked into Dedicated Device Kiosk mode.
2. **Third-Party CDN Dependencies**: Modern websites frequently load external resources (fonts, stylesheets, CDNs). While SecureBrowse blocks unapproved user navigation, cross-origin resources needed by approved sites function smoothly. For air-gapped or military-grade filtering, network-level DNS or proxy firewall management is recommended alongside SecureBrowse.
3. **Local PIN Scope**: Local PIN protection safeguards app configuration from casual tampering. Hardware-level tamper resistance requires Android Enterprise device encryption.
