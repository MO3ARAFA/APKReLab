# APK ReLab report: eu.faircode.netguard

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 43 finding(s) in total; 19 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.

### Summary

| Severity | Count |
|---|---|
| MEDIUM | 11 |
| LOW | 8 |

**OWASP Mobile Top 10 (2024) coverage**

- M4 Insufficient Input/Output Validation: 6
- M8 Security Misconfiguration: 4
- M5 Insecure Communication: 3
- M9 Insecure Data Storage: 3
- M10 Insufficient Cryptography: 2
- Not mapped: 1

### Findings

#### 1. [MEDIUM] Exported activity without a permission: eu.faircode.netguard.ActivitySettings

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 2. [MEDIUM] Exported activity without a permission: eu.faircode.netguard.ActivityForwardApproval

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 3. [MEDIUM] Exported service without a permission: eu.faircode.netguard.ServiceExternal

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [MEDIUM] Exported receiver without a permission: eu.faircode.netguard.ReceiverPackageRemoved

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This receiver is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [LOW] Code loaded from another app's package context

- Location: `d0.g`
- CWE: CWE-94 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: package-context-code | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: createPackageContext() is called with CONTEXT_INCLUDE_CODE, and no signature check of the target package is visible. Any app installed under that package name runs its code inside this process.  (around line 161)
- Risk scenario: Code loaded at runtime from a writable, downloaded or attacker-reachable location executes with the app's permissions, so replacing that file means running the attacker's code.
- Fix: Do not load code from other apps. If you must, verify the package signature with PackageManager.checkSignatures / signing certificates first and drop CONTEXT_IGNORE_SECURITY.

#### 6. [LOW] Hardcoded cleartext URL

- Location: `eu.faircode.netguard.ActivityPro$1`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://www.netguard.me/#). Traffic to it can be read or modified on the network.  (around line 124)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 7. [LOW] Data copied to clipboard

- Location: `eu.faircode.netguard.AdapterRule$15$1`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 229)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 8. [MEDIUM] Possible SQL built by string concatenation

- Location: `eu.faircode.netguard.DatabaseHelper`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 426)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 9. [LOW] Weak hash: SHA-1

- Location: `eu.faircode.netguard.Util`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 1159)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 10. [MEDIUM] Weak hash: MD5

- Location: `eu.faircode.netguard.Util`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 4800)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 11. [LOW] Data copied to clipboard

- Location: `eu.faircode.netguard.ActivityPro$3`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 91)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 12. [LOW] Data copied to clipboard

- Location: `eu.faircode.netguard.ActivityLog$4$1`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 202)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 13. [LOW] Native libraries not analysed (1 .so)

- Location: `lib/`
- Confidence: HIGH | Rule: native-coverage
- Priority: 20/100 (P4)
- Why flagged: This APK contains native libraries (libnetguard.so). APKReLab analyses Java / Kotlin (dex) code only: data handed to native methods is not followed.
- Fix: Review the native code separately (e.g. strings / imports of the .so, a disassembler) and check what the app passes to its JNI methods.

#### 14. [MEDIUM] Network Security Config: cleartext permitted

- Location: `res/8G.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-cleartext
- Priority: 45/100 (P2)
- Why flagged: network_security_config.xml allows plain HTTP (cleartextTrafficPermitted=true) in base-config, i.e. for every domain the app talks to. Traffic can be read and modified on the network (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set cleartextTrafficPermitted="false" in base-config and use HTTPS everywhere. If one legacy host really needs HTTP, allow it in a domain-config for that host only.

#### 15. [MEDIUM] Network Security Config: trusts user-installed CAs

- Location: `res/8G.xml`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-user-ca
- Priority: 45/100 (P2)
- Why flagged: The config trusts certificates the user installed in: base-config (every domain). A proxy such as Burp/mitmproxy (or malware that installs a CA) can then decrypt this app's HTTPS traffic (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Trust only the system CAs (src="system") in release builds; keep user CAs inside <debug-overrides> only.

#### 16. [LOW] Untrusted input chooses the server the app contacts

- Location: `eu.faircode.netguard.ServiceExternal`
- CWE: CWE-918 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE / MASVS-NETWORK | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 12/100 (P4)
- Why flagged: Data from SharedPreferences.getString() reaches URL.<init>() in method ServiceExternal.onHandleIntent(Landroid/content/Intent;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The source is SharedPreferences, which only an attacker with root or a tampered backup can change: treat this as a lead, not as a confirmed flaw.
- Risk scenario: When a deep link, Intent extra or web page decides which host the app connects to, an attacker can point it at an internal service, a server that logs the app's headers and tokens, or a cleartext endpoint.
- Fix: Allow-list the host (and use https) before opening the connection; resolve a small id to a fixed URL on your side.

#### 17. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `eu.faircode.netguard.ActivityDns$4`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: Data from Intent.getData() reaches ContentResolver.openOutputStream() in method ActivityDns$4.doInBackground([Ljava/lang/Object;)Ljava/lang/Throwable;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  Also matched by: taint-flow (merged).
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 18. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `eu.faircode.netguard.ActivityLog$8`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: Data from Intent.getData() reaches ContentResolver.openOutputStream() in method ActivityLog$8.doInBackground([Ljava/lang/Object;)Ljava/lang/Throwable;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  Also matched by: taint-flow (merged).
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 19. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `eu.faircode.netguard.ActivitySettings$14`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: Data from Intent.getData() reaches ContentResolver.openOutputStream() in method ActivitySettings$14.doInBackground([Ljava/lang/Object;)Ljava/lang/Throwable;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  Also matched by: taint-flow (merged).
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

### Remediation guide

One entry per weakness type found above.

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

#### CWE-94 - Improper Control of Generation of Code (Code Injection)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: Code loaded at runtime from a writable, downloaded or attacker-reachable location executes with the app's permissions, so replacing that file means running the attacker's code.

Vulnerable:

```kotlin
DexClassLoader(File(getExternalFilesDir(null), "plugin.dex").path, optDir, null, classLoader)
```

Secure:

```kotlin
// ship the code in the APK, or download it over HTTPS, verify a signature, and keep it in app-private storage (read-only after verification)
val f = File(filesDir, "plugin.dex"); verifySignature(f); f.setReadOnly()
```

References: [CWE-94 (MITRE)](https://cwe.mitre.org/data/definitions/94.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-89 - Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE

Risk: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.

Vulnerable:

```kotlin
db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
```

Secure:

```kotlin
db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))   // bound parameter
// ContentProvider.query: pass selection with ? and selectionArgs, never concatenate them
```

References: [CWE-89 (MITRE)](https://cwe.mitre.org/data/definitions/89.html) | [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-328 - Use of Weak Hash

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.

Vulnerable:

```kotlin
MessageDigest.getInstance("SHA-1").digest(data)
```

Secure:

```kotlin
MessageDigest.getInstance("SHA-256").digest(data)
// passwords: use a slow KDF (PBKDF2WithHmacSHA256 with 600000+ iterations, Argon2id, scrypt)
```

References: [CWE-328 (MITRE)](https://cwe.mitre.org/data/definitions/328.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-295 - Improper Certificate Validation

OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK

Risk: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.

Vulnerable:

```kotlin
object : X509TrustManager {
    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { }   // accepts everything
    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) { }
    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
<!-- res/xml/network_security_config.xml: trusts any CA the user (or malware) installed -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

Secure:

```kotlin
// use the platform trust store (do not override TrustManager at all)
val client = OkHttpClient.Builder()
    .certificatePinner(CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAA...=")      // optional: pin to your own backend
        .build())
    .build()
// WebView: in onReceivedSslError call handler.cancel(), never handler.proceed()

<!-- network_security_config.xml: system CAs only in release; user CAs only for the debugging proxy -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-30">
            <pin digest="SHA-256">CURRENT_KEY_PIN_BASE64=</pin>
            <pin digest="SHA-256">BACKUP_KEY_PIN_BASE64=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

References: [CWE-295 (MITRE)](https://cwe.mitre.org/data/definitions/295.html) | [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | [Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-918 - Server-Side Request Forgery (SSRF)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE / MASVS-NETWORK

Risk: When a deep link, Intent extra or web page decides which host the app connects to, an attacker can point it at an internal service, a server that logs the app's headers and tokens, or a cleartext endpoint.

Vulnerable:

```kotlin
val url = intent.getStringExtra("endpoint")
val conn = URL(url).openConnection()      // host chosen by the caller
```

Secure:

```kotlin
val id = intent.getStringExtra("endpoint")
val url = ENDPOINTS[id] ?: return          // fixed allow-list, https only
val conn = URL(url).openConnection()
```

References: [CWE-918 (MITRE)](https://cwe.mitre.org/data/definitions/918.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-73 - External Control of File Name or Path

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE

Risk: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.

Vulnerable:

```kotlin
val uri = intent.getParcelableExtra<Uri>("uri"); contentResolver.openInputStream(uri!!)
```

Secure:

```kotlin
val uri = intent.getParcelableExtra<Uri>("uri")
if (uri?.scheme == "content" && uri.authority in ALLOWED_AUTHORITIES) contentResolver.openInputStream(uri)
```

References: [CWE-73 (MITRE)](https://cwe.mitre.org/data/definitions/73.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)


