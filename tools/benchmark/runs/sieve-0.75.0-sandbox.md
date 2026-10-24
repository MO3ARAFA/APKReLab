# APK ReLab report: com.mwr.example.sieve

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 33 finding(s) in total; 29 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 7 |
| MEDIUM | 16 |
| LOW | 4 |

**OWASP Mobile Top 10 (2024) coverage**

- M8 Security Misconfiguration: 13
- M4 Insufficient Input/Output Validation: 7
- M9 Insecure Data Storage: 5
- M5 Insecure Communication: 2
- Not mapped: 2

### Findings

#### 1. [CRITICAL] Debuggable build

- Location: `AndroidManifest.xml`
- CWE: CWE-489 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-RESILIENCE | Confidence: HIGH | Rule: manifest-debuggable
- Priority: 90/100 (P1)
- Why flagged: android:debuggable="true" is set. Anyone with the APK (or USB access to the device) can attach a debugger, set breakpoints, dump memory, or step through the logic - including past client-side checks.
- Risk scenario: A debuggable app lets anyone attach a debugger, run code inside the process and read its private data; WebView debugging exposes pages and JS state over USB. android:testOnly marks a test build that may carry relaxed checks and must not be shipped.
- Fix: Remove android:debuggable, or make sure it is only true in debug build variants and never in what you ship/test for release.

#### 2. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 3. [LOW] No network security config referenced

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: MEDIUM | Rule: manifest-network-security-config
- Priority: 17/100 (P4)
- Why flagged: No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Add a network_security_config.xml with cleartextTrafficPermitted="false" as the base config (and certificate pinning if the app always talks to the same backend).

#### 4. [MEDIUM] Exported activity without a permission: .FileSelectActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [MEDIUM] Exported activity without a permission: .PWList

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [MEDIUM] Exported service without a permission: .AuthService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 7. [MEDIUM] Exported service without a permission: .CryptoService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 8. [HIGH] Exported provider without a permission: .DBContentProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 70/100 (P1)
- Why flagged: This provider is exported (usable by other apps) and declares no android:permission. A ContentProvider exported with no permission can let any app on the device query/insert/update/delete its data; if it builds file paths or SQL from the incoming Uri, that's also a path-traversal / SQL-injection surface.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 9. [HIGH] Exported provider without a permission: .FileBackupProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 70/100 (P1)
- Why flagged: This provider is exported (usable by other apps) and declares no android:permission. A ContentProvider exported with no permission can let any app on the device query/insert/update/delete its data; if it builds file paths or SQL from the incoming Uri, that's also a path-traversal / SQL-injection surface.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 10. [LOW] Low minSdkVersion (8)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-min-sdk
- Priority: 12/100 (P4)
- Why flagged: Supporting API < 23 (Android 6) means the app can run on devices without runtime permission prompts and with older TLS/cipher defaults.
- Fix: Raise minSdkVersion if the user base allows it; otherwise double check that sensitive permissions and network calls are still handled safely on the oldest supported devices.

#### 11. [MEDIUM] Old targetSdkVersion (17)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-target-sdk
- Priority: 27/100 (P3)
- Why flagged: The app targets API 17, so Android keeps legacy behaviour for it: user-installed CAs are trusted by default (easier HTTPS interception), cleartext HTTP is allowed by default, components with an intent-filter are exported by default and PendingIntents are mutable by default, and newer privacy / storage protections do not apply to it.
- Fix: Raise targetSdkVersion to a current API level and re-test; this is the cheapest way to get many OS-level protections.

#### 12. [MEDIUM] Data copied to clipboard

- Location: `com.mwr.example.sieve.PWList`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: The app puts data on the system clipboard close to credential-like names. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 504)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 13. [CRITICAL] TLS certificate validation disabled

- Location: `com.mwr.example.sieve.NetBackupHandler$1`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-trustmanager | Scope: APP
- Priority: 90/100 (P1)
- Why flagged: This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.  (around line 55)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.

#### 14. [HIGH] ContentProvider.openFile builds a path from the URI

- Location: `com.mwr.example.sieve.FileBackupProvider`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: provider-openfile-segment | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: openFile() creates a File from the URI (getPath) without canonicalising it. A caller can pass an encoded ../ in the URI to reach any file the app can open, and the mode argument is not restricted to read-only, so the same bug can overwrite files.  (around line 141)  Also matched by: androgoat-checks (merged).  Also matched by: taint-flow (merged).  Also matched by: taint-flow (merged).
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Resolve the file inside a fixed directory, call getCanonicalPath() and check it still starts with that directory, and reject modes other than "r" unless writing is intended.

#### 15. [MEDIUM] Sensitive value written to SQLite (plaintext)

- Location: `com.mwr.example.sieve.PWDBHelper`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: An SQL statement in this class creates or fills a table with a credential-like column. SQLite files are unencrypted and readable on rooted devices or from a backup.  (around line 39)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords in SQLite; if you must keep sensitive columns use SQLCipher or encrypt the values with a Keystore key.

#### 16. [MEDIUM] Sensitive data stored in plain SQLite (x2)

- Location: `com.mwr.example.sieve.PWDBHelper`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: sqlite-unencrypted | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "Passwords" (CREATE TABLE). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 41)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 17. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `com.mwr.example.sieve.SettingsActivity`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: Data from Intent.getStringExtra() reaches ContentResolver.openInputStream() in method restoreFromFile(): the caller picks the URI the app reads, so a file:// URI makes the app read its own private files. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 1108)
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 18. [HIGH] Untrusted input reaches an SQL statement (x3)

- Location: `com.mwr.example.sieve.DBContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: Data from a ContentProvider method parameter (other apps can call it when the provider is exported) reaches SQLiteDatabase.delete() in method delete(): the table or the WHERE clause contains the input. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way.  (around line 120)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 19. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `com.mwr.example.sieve.AuthService`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 367)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 20. [MEDIUM] Credentials may be written to the log

- Location: `com.mwr.example.sieve.MainLoginActivity`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: log-credential-object | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: This method builds a log message with a StringBuilder and writes it with Log.d(). Credential-like field(s) read into the message: workingPassword. Logcat can be read over adb and, on older Android versions, by other apps.  (around line 382)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Remove the log call or log only a non-sensitive id; never put a login/credential object in a message, and strip debug logging from release builds (R8 -assumenosideeffects).

#### 21. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_add_entry.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080006") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 8: devices below Android 12 do not block touches through overlays.  [res/layout/activity_add_entry.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 22. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_main_login.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080011") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 8: devices below Android 12 do not block touches through overlays.  [res/layout/activity_main_login.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 23. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_pin.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080015") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 8: devices below Android 12 do not block touches through overlays.  [res/layout/activity_pin.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 24. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_short_login.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080027") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 8: devices below Android 12 do not block touches through overlays.  [res/layout/activity_short_login.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 25. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_welcome.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f08002b") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 8: devices below Android 12 do not block touches through overlays.  [res/layout/activity_welcome.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 26. [HIGH] Untrusted input reaches an SQL statement

- Location: `com.mwr.example.sieve.DBContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: Data from a ContentProvider method parameter reaches SQLiteDatabase.delete() in method DBContentProvider.delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. 2 flows of this kind end in this method.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 27. [HIGH] Untrusted input reaches an SQL statement

- Location: `com.mwr.example.sieve.DBContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: Data from a ContentProvider method parameter reaches SQLiteQueryBuilder.query() in method DBContentProvider.query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 28. [HIGH] Untrusted input reaches an SQL statement

- Location: `com.mwr.example.sieve.DBContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: Data from a ContentProvider method parameter reaches SQLiteDatabase.update() in method DBContentProvider.update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. 2 flows of this kind end in this method.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 29. [LOW] Untrusted input chooses the file or content URI the app opens

- Location: `com.mwr.example.sieve.SettingsActivity`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: Data from Intent.getStringExtra() in onActivityResult reaches ContentResolver.openInputStream() in method SettingsActivity.restoreFromFile(Ljava/lang/String;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. The Intent is the result that an activity this app started handed back to onActivityResult (a file picker, the camera, one of its own screens), not an input that another app sends to a component of this app. It is attacker-controlled only if the app starts an implicit Intent that another app can answer, or the activity it calls is untrusted (low confidence); check which activity is started and whether the Intent is explicit. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

### Remediation guide

One entry per weakness type found above.

#### CWE-489 - Active Debug Code

OWASP: M8 Security Misconfiguration | MASVS: MASVS-RESILIENCE

Risk: A debuggable app lets anyone attach a debugger, run code inside the process and read its private data; WebView debugging exposes pages and JS state over USB. android:testOnly marks a test build that may carry relaxed checks and must not be shipped.

Vulnerable:

```kotlin
<application android:debuggable="true" android:testOnly="true" ...>
WebView.setWebContentsDebuggingEnabled(true)
```

Secure:

```kotlin
<!-- release builds are not debuggable by default: remove android:debuggable and android:testOnly -->
if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)
```

References: [CWE-489 (MITRE)](https://cwe.mitre.org/data/definitions/489.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-530 - Exposure of Backup File to an Unauthorized Control Sphere

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.

Vulnerable:

```kotlin
<application android:allowBackup="true" ...>
```

Secure:

```kotlin
<application android:allowBackup="false" android:dataExtractionRules="@xml/data_extraction_rules" ...>
<!-- or keep backup and exclude secrets with fullBackupContent / dataExtractionRules -->
```

References: [CWE-530 (MITRE)](https://cwe.mitre.org/data/definitions/530.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-532 - Insertion of Sensitive Information into Log File

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.

Vulnerable:

```kotlin
Log.d("Login", "user=" + user + " password=" + password)
```

Secure:

```kotlin
if (BuildConfig.DEBUG) Log.d("Login", "login attempt")      // never log credentials or tokens
// release builds: strip logs with R8 (-assumenosideeffects class android.util.Log { *; })
```

References: [CWE-532 (MITRE)](https://cwe.mitre.org/data/definitions/532.html) | [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


