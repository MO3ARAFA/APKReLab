# APK ReLab report: com.m2049r.xmrwallet

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 224 finding(s) in total; 26 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| HIGH | 2 |
| MEDIUM | 10 |
| LOW | 14 |

**OWASP Mobile Top 10 (2024) coverage**

- M8 Security Misconfiguration: 6
- M10 Insufficient Cryptography: 6
- M5 Insecure Communication: 3
- M3 Insecure Authentication/Authorization: 3
- M9 Insecure Data Storage: 3
- M4 Insufficient Input/Output Validation: 3
- Not mapped: 1
- M1 Improper Credential Usage: 1

### Findings

#### 1. [HIGH] Cleartext (plain HTTP) traffic allowed

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: manifest-cleartext-traffic
- Priority: 70/100 (P1)
- Why flagged: android:usesCleartextTraffic="true" lets the app make plain HTTP requests. Anyone sharing the network (public Wi-Fi, a compromised router) can read or tamper with that traffic.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set usesCleartextTraffic to "false" and use HTTPS everywhere; if a few hosts genuinely need HTTP, scope that with a network security config instead of a blanket allow.

#### 2. [MEDIUM] Deep link entry point: com.m2049r.xmrwallet.LoginActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 38/100 (P3)
- Why flagged: This activity can be opened from a browser/other apps via monero, bitcoin://. Anything in the link (path, query, fragment) is attacker-controlled input, and a custom scheme with no host can be claimed by any other installed app (link hijacking).
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 3. [MEDIUM] Exported activity without a permission: com.m2049r.xmrwallet.LoginActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [LOW] Low minSdkVersion (21)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-min-sdk
- Priority: 12/100 (P4)
- Why flagged: Supporting API < 23 (Android 6) means the app can run on devices without runtime permission prompts and with older TLS/cipher defaults.
- Fix: Raise minSdkVersion if the user base allows it; otherwise double check that sensitive permissions and network calls are still handled safely on the oldest supported devices.

#### 5. [LOW] Weak hash: SHA-1

- Location: `org.xbill.DNS.NSEC3Record`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 205)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 6. [LOW] Weak hash: SHA-1

- Location: `org.xbill.DNS.DNSSEC`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 1426)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 7. [LOW] HTTP client built without certificate pinning

- Location: `com.m2049r.xmrwallet.util.NetCipherHelper`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 183)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 8. [LOW] HTTP client built without certificate pinning

- Location: `com.m2049r.xmrwallet.util.NetCipherHelper$Request`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 180)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 9. [LOW] Shared external storage used

- Location: `com.m2049r.xmrwallet.util.LegacyStorageHelper`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 599)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 10. [LOW] Data copied to clipboard

- Location: `com.m2049r.xmrwallet.util.Helper`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 213)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 11. [LOW] RSA with PKCS#1 v1.5 padding ("RSA/ECB/PKCS1Padding") (x2)

- Location: `com.m2049r.xmrwallet.util.KeyStoreHelper`
- CWE: CWE-780 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-cipher | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: PKCS#1 v1.5 encryption padding is vulnerable to padding-oracle (Bleichenbacher-style) attacks when decryption errors are observable.  (around line 359)
- Risk scenario: PKCS#1 v1.5 padding is vulnerable to padding-oracle attacks (Bleichenbacher) when error behaviour leaks.
- Fix: Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding.

#### 12. [MEDIUM] PBKDF2 with a low iteration count (2048)

- Location: `com.m2049r.xmrwallet.util.ledger.Monero`
- CWE: CWE-916 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-pbkdf2-iterations | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: PBEKeySpec is created with only 2048 iterations. A key (or stored password hash) derived from a password with so few iterations can be brute-forced very quickly.  (around line 10848)
- Risk scenario: A low iteration count lets an attacker who gets the hash (or the encrypted blob) try billions of guesses per second on a GPU.
- Fix: Use at least 100,000 iterations of PBKDF2WithHmacSHA256 (OWASP currently recommends 600,000), or a memory-hard KDF such as Argon2 / scrypt.

#### 13. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `com.m2049r.xmrwallet.LoginActivity`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 1988)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 14. [HIGH] Hardcoded credential: JWT

- Location: `com.m2049r.xmrwallet.service.shift.provider.exolix.ExolixApiImpl`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-known-formats | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: A string matching the JWT format is embedded in the code ("eyJhbGci…"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.  (around line 38)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.

#### 15. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `com.m2049r.xmrwallet.service.WalletService`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 647)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 16. [MEDIUM] Insecure TLS protocol requested: "TLSV1"

- Location: `info.guardianproject.netcipher.NetCipher`
- CWE: CWE-327 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: tls-protocol-version
- Priority: 45/100 (P2)
- Why flagged: SSLContext.getInstance("TLSV1") is used. "TLSV1" pins an old protocol version (TLSv1/TLSv1.1 are deprecated and disabled by many servers as of 2021).  (around line 532)
- Risk scenario: A network attacker can push the connection down to SSLv3 / TLSv1.0 / TLSv1.1, which have known attacks, and read or change the traffic.
- Fix: Use SSLContext.getInstance("TLSv1.3") (fall back to "TLSv1.2" only if you must support very old peers), or omit explicit protocol selection and rely on the platform default on modern API levels.

#### 17. [MEDIUM] Insecure TLS protocol requested: "TLSV1"

- Location: `info.guardianproject.netcipher.client.StrongBuilderBase`
- CWE: CWE-327 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: tls-protocol-version
- Priority: 45/100 (P2)
- Why flagged: SSLContext.getInstance("TLSV1") is used. "TLSV1" pins an old protocol version (TLSv1/TLSv1.1 are deprecated and disabled by many servers as of 2021).  (around line 548)
- Risk scenario: A network attacker can push the connection down to SSLv3 / TLSv1.0 / TLSv1.1, which have known attacks, and read or change the traffic.
- Fix: Use SSLContext.getInstance("TLSv1.3") (fall back to "TLSv1.2" only if you must support very old peers), or omit explicit protocol selection and rely on the platform default on modern API levels.

#### 18. [MEDIUM] Shell command execution

- Location: `info.guardianproject.netcipher.proxy.TorServiceUtils`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 49)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 19. [LOW] Dynamic receiver registered without export flag

- Location: `info.guardianproject.netcipher.proxy.OrbotHelper`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 970)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 20. [MEDIUM] Weak host validation of a Uri (x2)

- Location: `info.guardianproject.netcipher.proxy.OrbotHelper`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: deeplink-host-validation
- Priority: 38/100 (P3)
- Why flagged: The host of a Uri is read and then compared with String.endsWith(). Checks like that accept hosts such as evil-example.com or example.com.evil.com, so a deep link can point the app (WebView, login, download) at an attacker's server.  (around line 574)
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Compare the whole host with an allow-list using equals(), or require host == "example.com" || host.endsWith(".example.com") (note the leading dot) after parsing with a real URI parser.

#### 21. [LOW] Dynamic receiver registered without export flag

- Location: `info.guardianproject.netcipher.proxy.MyOrbotHelper`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1037)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 22. [MEDIUM] Weak host validation of a Uri (x2)

- Location: `info.guardianproject.netcipher.proxy.MyOrbotHelper`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: deeplink-host-validation
- Priority: 38/100 (P3)
- Why flagged: The host of a Uri is read and then compared with String.endsWith(). Checks like that accept hosts such as evil-example.com or example.com.evil.com, so a deep link can point the app (WebView, login, download) at an attacker's server.  (around line 564)
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Compare the whole host with an allow-list using equals(), or require host == "example.com" || host.endsWith(".example.com") (note the leading dot) after parsing with a real URI parser.

#### 23. [LOW] Keyboard cache: sensitive input field (x7)

- Location: `res/66.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/66.xml]  The same applies to 6 more layout(s): res/J7.xml, res/JY.xml, res/YW.xml, res/fu.xml, res/i0.xml, res/vn.xml.
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 24. [MEDIUM] Password screen not protected against tapjacking (x5)

- Location: `res/KM.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("?") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 21: devices below Android 12 do not block touches through overlays.  [res/KM.xml]  The same applies to 4 more layout(s): res/N9.xml, res/OH.xml, res/Uu.xml, res/rY.xml.
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 25. [MEDIUM] Untrusted input is used as a file path

- Location: `com.m2049r.xmrwallet.util.ZipRestore`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: Data from ZipEntry.getName() (through ZipRestore.testArchive()Ljava/lang/String;) reaches FileOutputStream.<init>() in method ZipRestore.writeFile(Ljava/io/File;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. The value is the name of an archive entry. When the archive comes from outside the app (a download, a file another app shares) a name such as ../../x makes the extraction write outside the target folder (Zip Slip): the target path must be checked with getCanonicalPath() against the extraction folder. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 26. [LOW] Untrusted input chooses the file or content URI the app opens

- Location: `com.m2049r.xmrwallet.util.ZipBackup`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: Data from Intent.getData() in onActivityResult reaches ContentResolver.openOutputStream() in method ZipBackup.writeTo(Landroid/net/Uri;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. The Intent is the result that an activity this app started handed back to onActivityResult (a file picker, the camera, one of its own screens), not an input that another app sends to a component of this app. It is attacker-controlled only if the app starts an implicit Intent that another app can answer, or the activity it calls is untrusted (low confidence); check which activity is started and whether the Intent is explicit.
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

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

#### CWE-939 - Improper Authorization in Handler for Custom URL Scheme

OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM

Risk: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.

Vulnerable:

```kotlin
val target = intent.data?.getQueryParameter("redirect"); webView.loadUrl(target!!)
```

Secure:

```kotlin
val target = intent.data?.getQueryParameter("redirect")?.let(Uri::parse)
if (target?.host == "app.example.com") open(target)     // allow-list; require user confirmation for sensitive actions
// prefer verified App Links (https + assetlinks.json) over custom schemes
```

References: [CWE-939 (MITRE)](https://cwe.mitre.org/data/definitions/939.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-922 - Insecure Storage of Sensitive Information

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.

Vulnerable:

```kotlin
File(Environment.getExternalStorageDirectory(), "export.json").writeText(json)
<application android:requestLegacyExternalStorage="true" ...>
```

Secure:

```kotlin
File(filesDir, "export.json").writeText(json)          // app-private storage
// to share: use a FileProvider with a narrow path and grant temporary URI permission
// scoped storage: remove requestLegacyExternalStorage; use MediaStore, the Storage Access Framework or getExternalFilesDir
```

References: [CWE-922 (MITRE)](https://cwe.mitre.org/data/definitions/922.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-780 - Use of RSA Algorithm without OAEP

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: PKCS#1 v1.5 padding is vulnerable to padding-oracle attacks (Bleichenbacher) when error behaviour leaks.

Vulnerable:

```kotlin
Cipher.getInstance("RSA/ECB/PKCS1Padding")
```

Secure:

```kotlin
Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
```

References: [CWE-780 (MITRE)](https://cwe.mitre.org/data/definitions/780.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-916 - Use of Password Hash With Insufficient Computational Effort

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: A low iteration count lets an attacker who gets the hash (or the encrypted blob) try billions of guesses per second on a GPU.

Vulnerable:

```kotlin
PBEKeySpec(password, salt, 1000, 256)
```

Secure:

```kotlin
PBEKeySpec(password, salt, 600_000, 256)   // PBKDF2WithHmacSHA256; or use Argon2id / scrypt
```

References: [CWE-916 (MITRE)](https://cwe.mitre.org/data/definitions/916.html) | [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-798 - Use of Hard-coded Credentials

OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO

Risk: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.

Vulnerable:

```kotlin
const val API_KEY = "EXAMPLE_ONLY_NOT_A_REAL_KEY"   // shipped inside every APK
val client = Api(API_KEY)
<!-- res/values/strings.xml: this ends up readable inside resources.arsc -->
<string name="api_secret">EXAMPLE_ONLY_NOT_A_REAL_KEY</string>
```

Secure:

```kotlin
// keep the secret on YOUR server; the app only holds a short-lived user token
val token = authRepository.sessionToken()      // issued after login, expires, revocable
val client = Api(token)
// if a client key is unavoidable: restrict it (package name + SHA-256 cert, API scope, quota) and rotate it
// Google / Firebase API key in strings.xml: in the Cloud console restrict it to Android apps (package name + SHA-1) and to the APIs you use
<!-- strings.xml keeps only public identifiers; secrets and long-lived tokens stay on your backend -->
```

References: [CWE-798 (MITRE)](https://cwe.mitre.org/data/definitions/798.html) | [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-327 - Use of a Broken or Risky Cryptographic Algorithm

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: DES/RC4/MD5/ECB-mode data can be decrypted or forged much faster than the key length suggests. ECB shows patterns (equal blocks give equal ciphertext) and has no integrity.

Vulnerable:

```kotlin
Cipher.getInstance("AES/ECB/PKCS5Padding")
MessageDigest.getInstance("MD5")
```

Secure:

```kotlin
val cipher = Cipher.getInstance("AES/GCM/NoPadding")        // authenticated encryption
cipher.init(Cipher.ENCRYPT_MODE, key)                        // let the provider create a fresh random IV
val iv = cipher.iv; val ct = cipher.doFinal(plain)           // store iv next to ct
// hashing: SHA-256 or better; passwords: PBKDF2 / Argon2 / scrypt, never a plain hash
```

References: [CWE-327 (MITRE)](https://cwe.mitre.org/data/definitions/327.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-78 - Improper Neutralization of Special Elements used in an OS Command

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).

Vulnerable:

```kotlin
Runtime.getRuntime().exec("ping " + host)
```

Secure:

```kotlin
// no shell: fixed program, arguments as separate list items, validated input
ProcessBuilder("ping", "-c", "1", validatedHost).redirectErrorStream(true).start()
// better: use an Android API instead of a command
```

References: [CWE-78 (MITRE)](https://cwe.mitre.org/data/definitions/78.html) | [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


