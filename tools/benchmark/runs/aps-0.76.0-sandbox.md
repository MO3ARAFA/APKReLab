# APK ReLab report: app.passwordstore

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 179 finding(s) in total; 17 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| MEDIUM | 8 |
| LOW | 9 |

**OWASP Mobile Top 10 (2024) coverage**

- M9 Insecure Data Storage: 8
- M8 Security Misconfiguration: 6
- M4 Insufficient Input/Output Validation: 2
- M5 Insecure Communication: 1

### Findings

#### 1. [LOW] No network security config referenced

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: MEDIUM | Rule: manifest-network-security-config
- Priority: 17/100 (P4)
- Why flagged: No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Add a network_security_config.xml with cleartextTrafficPermitted="false" as the base config (and certificate pinning if the app always talks to the same backend).

#### 2. [MEDIUM] Exported activity without a permission: app.passwordstore.ui.crypto.DecryptActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 3. [MEDIUM] Exported activity without a permission: androidx.compose.ui.tooling.PreviewActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `app.passwordstore.util.services.ClipboardService`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 451)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 5. [LOW] Data copied to clipboard

- Location: `app.passwordstore.util.services.ClipboardService$clearClipboard$1$2`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 84)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 6. [LOW] Data copied to clipboard

- Location: `app.passwordstore.util.services.ClipboardService$clearClipboard$1`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 146)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 7. [LOW] Data copied to clipboard

- Location: `app.passwordstore.ui.crypto.BasePGPActivity`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 156)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 8. [MEDIUM] QR/barcode input reaches a sensitive sink

- Location: `app.passwordstore.ui.crypto.PasswordDialog$$ExternalSyntheticLambda1`
- CWE: CWE-20 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: This class scans QR/barcodes and also calls a sensitive API (Landroid/content/Context;->startActivity). A malicious QR code is attacker-controlled input; if it is used unvalidated, it can open arbitrary URLs/intents or inject SQL/commands.  (around line 116)
- Risk scenario: Data from an Intent, deep link, QR code or server is trusted without checks, so it can steer the app into unintended screens, URLs or file operations.
- Fix: Treat the scanned text as untrusted: validate scheme/host against an allow-list, never pass it straight to WebView/Intent/SQL.

#### 9. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `app.passwordstore.ui.crypto.DecryptActivity$$ExternalSyntheticLambda1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 320)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 10. [LOW] Credential stored in plain SharedPreferences

- Location: `app.passwordstore.ui.crypto.DecryptActivity$$ExternalSyntheticLambda1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW | Rule: fintech-unencrypted-storage | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: A value under the key "proxy_password" is written with SharedPreferences.Editor.putString(), and this class never touches EncryptedSharedPreferences or the Android Keystore. Plain SharedPreferences XML is readable on a rooted device, from an adb backup, or from any app sharing the same Linux UID (shared UID apps) - for a PIN, API key or session token that's a direct credential-theft path.  (around line 427) NOTE: this class never opens a preferences file itself (no getSharedPreferences / getDefaultSharedPreferences), so the SharedPreferences object is provided from outside (dependency injection, a field or a parameter) and may be EncryptedSharedPreferences: check where it is created before trusting this finding.
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Move this key to androidx.security.crypto.EncryptedSharedPreferences, or better, keep it only in the Android Keystore (StrongBox/TEE-backed where available) and never serialize it to disk in cleartext.

#### 11. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `app.passwordstore.ui.git.config.GitConfigActivity$$ExternalSyntheticLambda0`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 340)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 12. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `app.passwordstore.ui.dialogs.DicewarePasswordGeneratorDialogFragment`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 151)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 13. [LOW] Dynamic receiver registered without export flag

- Location: `app.passwordstore.Application`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1312)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 14. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `logcat.LogcatKt`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 2593)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 15. [LOW] Keyboard cache: sensitive input field (x3)

- Location: `res/66.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/66.xml]  The same applies to 2 more layout(s): res/J7.xml, res/fu.xml.
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 16. [MEDIUM] Password screen not protected against tapjacking (x6)

- Location: `res/Hs.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0a01f5") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 26: devices below Android 12 do not block touches through overlays.  [res/Hs.xml]  The same applies to 5 more layout(s): res/KD.xml, res/Rm.xml, res/b2.xml, res/l6.xml, res/pJ.xml.
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 17. [MEDIUM] Untrusted input is used as a file path

- Location: `app.passwordstore.ui.crypto.BasePGPActivity`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: Data from Intent.getStringExtra() (through field DecryptActivity.relativeParentPath$delegate:Ljava/lang/Object; (written in DecryptActivity.<init>()V)) reaches FileInputStream.<init>() in method BasePGPActivity.getPGPIdentifiers(Ljava/lang/String;)Ljava/util/ArrayList;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

### Remediation guide

One entry per weakness type found above.

#### CWE-319 - Cleartext Transmission of Sensitive Information

OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK

Risk: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.

Vulnerable:

```kotlin
<application android:usesCleartextTraffic="true" ...>
val url = "http://api.example.com/login"   // plain HTTP
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />   <!-- every domain may use plain HTTP -->
</network-security-config>
```

Secure:

```kotlin
<application android:usesCleartextTraffic="false" android:networkSecurityConfig="@xml/network_security_config" ...>
val url = "https://api.example.com/login"   // TLS
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
<!-- only if one legacy host really needs HTTP: scope it to that host, never to base-config -->
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">legacy.example.com</domain>
</domain-config>
```

References: [CWE-319 (MITRE)](https://cwe.mitre.org/data/definitions/319.html) | [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-926 - Improper Export of Android Application Components

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.

Vulnerable:

```kotlin
<activity android:name=".AdminActivity" android:exported="true" />
<permission android:name="com.example.PERM" android:protectionLevel="normal" />   <!-- any app can request it -->
<provider android:name=".Db" android:exported="true" android:readPermission="com.example.READ" />   <!-- writes are open -->
```

Secure:

```kotlin
<activity android:name=".AdminActivity" android:exported="false" />
<!-- if another app must call it: android:permission="com.example.PERM" with protectionLevel="signature", and validate every extra -->
<permission android:name="com.example.PERM" android:protectionLevel="signature" />
<provider android:name=".Db" android:exported="true" android:readPermission="com.example.READ" android:writePermission="com.example.WRITE" />
```

References: [CWE-926 (MITRE)](https://cwe.mitre.org/data/definitions/926.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-927 - Use of Implicit Intent for Sensitive Communication

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.

Vulnerable:

```kotlin
sendBroadcast(Intent("com.example.TOKEN").putExtra("token", t))
PendingIntent.getActivity(this, 0, intent, 0)
```

Secure:

```kotlin
sendBroadcast(Intent("com.example.TOKEN").setPackage(packageName).putExtra("token", t))
PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
```

References: [CWE-927 (MITRE)](https://cwe.mitre.org/data/definitions/927.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM

Risk: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.

Vulnerable:

```kotlin
webSettings.allowFileAccessFromFileURLs = true
<provider android:exported="true" android:grantUriPermissions="true" ... />   <!-- every path can be handed out -->
```

Secure:

```kotlin
webSettings.allowFileAccessFromFileURLs = false
webSettings.allowUniversalAccessFromFileURLs = false
<provider android:exported="false" android:grantUriPermissions="false" ...>
    <grant-uri-permission android:pathPrefix="/shared/" />   <!-- only the paths that must be shared -->
</provider>
```

References: [CWE-200 (MITRE)](https://cwe.mitre.org/data/definitions/200.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-20 - Improper Input Validation

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: Data from an Intent, deep link, QR code or server is trusted without checks, so it can steer the app into unintended screens, URLs or file operations.

Vulnerable:

```kotlin
val url = intent.getStringExtra("url"); webView.loadUrl(url!!)
```

Secure:

```kotlin
val url = intent.getStringExtra("url")
val u = url?.let { Uri.parse(it) }
if (u?.scheme == "https" && u.host in ALLOWED_HOSTS) webView.loadUrl(url) else finish()
```

References: [CWE-20 (MITRE)](https://cwe.mitre.org/data/definitions/20.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-312 - Cleartext Storage of Sensitive Information

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.

Vulnerable:

```kotlin
prefs.edit().putString("password", password).apply()
db.execSQL("INSERT INTO users(pin) VALUES ('" + pin + "')")
```

Secure:

```kotlin
// store a token (not the password) and encrypt it with a Keystore-backed AES-GCM key
val sealed = keystoreCipher.encrypt(token.toByteArray())     // see CWE-321 sample for the key
prefs.edit().putString("token", Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
// database: SQLCipher or per-field encryption; never keep the password itself
```

References: [CWE-312 (MITRE)](https://cwe.mitre.org/data/definitions/312.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-524 - Use of Cache Containing Sensitive Information

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.

Vulnerable:

```kotlin
<EditText android:inputType="text" />   <!-- password-like field with suggestions on -->
```

Secure:

```kotlin
<EditText android:inputType="textPassword|textNoSuggestions" android:importantForAutofill="no" />
```

References: [CWE-524 (MITRE)](https://cwe.mitre.org/data/definitions/524.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-1021 - Improper Restriction of Rendered UI Layers or Frames (Tapjacking)

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.

Vulnerable:

```kotlin
<EditText android:inputType="textPassword" ... />   <!-- no filterTouchesWhenObscured -->
```

Secure:

```kotlin
<LinearLayout android:filterTouchesWhenObscured="true" ...>
// or, API 31+: window.setHideOverlayWindows(true)  (needs HIDE_OVERLAY_WINDOWS)
```

References: [CWE-1021 (MITRE)](https://cwe.mitre.org/data/definitions/1021.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-22 - Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE

Risk: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).

Vulnerable:

```kotlin
val out = File(dir, entry.name)            // entry.name may contain ../
```

Secure:

```kotlin
val out = File(dir, entry.name).canonicalFile
if (!out.path.startsWith(dir.canonicalPath + File.separator)) throw SecurityException("bad path")
```

References: [CWE-22 (MITRE)](https://cwe.mitre.org/data/definitions/22.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)


