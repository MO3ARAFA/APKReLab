# APK ReLab report: ch.protonmail.android

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 560 finding(s) in total; 72 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.

### Summary

| Severity | Count |
|---|---|
| HIGH | 1 |
| MEDIUM | 22 |
| LOW | 49 |

**OWASP Mobile Top 10 (2024) coverage**

- M1 Improper Credential Usage: 15
- M8 Security Misconfiguration: 14
- M5 Insecure Communication: 13
- M9 Insecure Data Storage: 13
- M4 Insufficient Input/Output Validation: 11
- M10 Insufficient Cryptography: 3
- M3 Insecure Authentication/Authorization: 2
- Not mapped: 1

### Findings

#### 1. [MEDIUM] Cleartext (plain HTTP) traffic allowed

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: manifest-cleartext-traffic
- Priority: 45/100 (P2)
- Why flagged: android:usesCleartextTraffic="true" lets the app make plain HTTP requests. Anyone sharing the network (public Wi-Fi, a compromised router) can read or tamper with that traffic.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set usesCleartextTraffic to "false" and use HTTPS everywhere; if a few hosts genuinely need HTTP, scope that with a network security config instead of a blanket allow.

#### 2. [MEDIUM] Deep link entry point: ch.protonmail.android.activities.composeMessage.ComposeMessageActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 38/100 (P3)
- Why flagged: This activity can be opened from a browser/other apps via mailto://. Anything in the link (path, query, fragment) is attacker-controlled input, and a custom scheme with no host can be claimed by any other installed app (link hijacking).
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 3. [MEDIUM] Exported receiver without a permission: ch.protonmail.android.receivers.LocaleChangeReceiver

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This receiver is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [MEDIUM] Exported activity without a permission: ch.protonmail.android.activities.composeMessage.ComposeMessageActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [MEDIUM] Exported activity without a permission: ch.protonmail.android.labels.presentation.ui.ParentFolderPickerActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [MEDIUM] Exported activity without a permission: androidx.biometric.DeviceCredentialHandlerActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 7. [LOW] WebView addJavascriptInterface

- Location: `me.proton.core.humanverification.presentation.ui.hv3.HV3DialogFragment`
- CWE: CWE-749 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: webview-js-interface | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A Java/Kotlin object is bridged into a WebView's JavaScript context. Any page the WebView loads - including one reached via a hijacked link or a MITM'd connection - can call that object's @JavascriptInterface methods. The bridge object is another class: its @JavascriptInterface methods are judged there ("JavaScript-exposed method" findings).  (around line 2705)
- Risk scenario: Every page the WebView loads (including injected ads or a hijacked link) can call the exposed @JavascriptInterface methods, for example to read files, tokens or start activities.
- Fix: Avoid exposing a JS interface to untrusted pages; restrict it to known HTTPS origins, or use WebMessageListener on modern APIs instead.

#### 8. [MEDIUM] WebView ignores TLS errors (SslErrorHandler.proceed)

- Location: `me.proton.core.humanverification.presentation.ui.common.HumanVerificationWebViewClient`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: webview-ssl-error | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: onReceivedSslError calls handler.proceed(), so the WebView keeps loading pages with invalid/untrusted certificates - the classic way TLS gets silently disabled. The call sits behind a condition (allow-list / flag / dialog): check what the condition is before treating it as a blanket proceed.  (around line 2569)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Call handler.cancel() (and show an error) instead of proceed(); never ship a blanket proceed.

#### 9. [LOW] Temp file created

- Location: `me.proton.core.key.domain.KeyHolderCryptoKt`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 6037)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 10. [LOW] Hardcoded cleartext URL

- Location: `me.proton.core.network.data.protonApi.RefreshTokenRequest`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://protonmail.ch). Traffic to it can be read or modified on the network.  (around line 262)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 11. [LOW] Dynamic receiver registered without export flag

- Location: `me.proton.core.network.data.NetworkManagerImpl`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 313)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 12. [LOW] High-entropy embedded string near a credential-like name

- Location: `me.proton.core.user.data.UserAddressKeySecretProvider$Companion`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 22-char string with high character randomness (entropy 4.5 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "0123…".  (around line 126) No key, IV or credential use was seen in this method, so this may be a public value.
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 13. [LOW] High-entropy embedded string near a credential-like name (x2)

- Location: `me.proton.core.usersettings.presentation.ui.PasswordManagementFragment`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 44-char string with high character randomness (entropy 4.2 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "onLo…".  (around line 798) No key, IV or credential use was seen in this method, so this may be a public value.
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 14. [LOW] Hardcoded cleartext URL

- Location: `s2.h$b`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://androidlinksfix.protonmail.com). Traffic to it can be read or modified on the network.  (around line 236)  [Renamed by R8, but this is the app's own code: the class references the app's package.]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 15. [LOW] Dynamic receiver registered without export flag

- Location: `k2.f`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 343)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 16. [LOW] Dynamic receiver registered without export flag

- Location: `k2.g`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 276)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 17. [LOW] Dynamic receiver registered without export flag

- Location: `k2.b`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 281)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 18. [LOW] Dynamic receiver registered without export flag

- Location: `k2.c`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 160)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 19. [LOW] Dynamic receiver registered without export flag

- Location: `k2.a`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 472)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 20. [LOW] HTTP client built without certificate pinning

- Location: `ch.protonmail.android.api.ProtonRetrofitSecure`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 353)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 21. [LOW] HTTP client built without certificate pinning

- Location: `ch.protonmail.android.api.DnsOverHttpsProviderRFC8484`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 168)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 22. [LOW] Dynamic receiver registered without export flag

- Location: `ch.protonmail.android.api.services.ConnectivityService`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 187)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 23. [LOW] OkHttp logs requests/responses (Level.HEADERS)

- Location: `ch.protonmail.android.api.ProtonRetrofitPublic`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW | Rule: okhttp-logging | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: HttpLoggingInterceptor is set to HEADERS: request/response data (tokens, cookies, personal data) is written to logcat, which other tools on the device or a connected PC can read.  (around line 297)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Use Level.NONE (or BASIC) in release builds; enable BODY only when BuildConfig.DEBUG.

#### 24. [LOW] HTTP client built without certificate pinning

- Location: `ch.protonmail.android.api.ProtonRetrofitPublic`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 353)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 25. [LOW] HTTP client built without certificate pinning

- Location: `ch.protonmail.android.api.ProtonRetrofitAttachments`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 376)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 26. [LOW] OkHttp logs requests/responses (Level.HEADERS)

- Location: `ch.protonmail.android.api.ProtonRetrofitExtended`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW | Rule: okhttp-logging | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: HttpLoggingInterceptor is set to HEADERS: request/response data (tokens, cookies, personal data) is written to logcat, which other tools on the device or a connected PC can read.  (around line 328)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Use Level.NONE (or BASIC) in release builds; enable BODY only when BuildConfig.DEBUG.

#### 27. [LOW] HTTP client built without certificate pinning

- Location: `ch.protonmail.android.api.ProtonRetrofitExtended`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 376)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 28. [LOW] Hardcoded sensitive field: FIELD_DEVICE_TOKEN

- Location: `ch.protonmail.android.api.models.RegisterDeviceRequestBodyKt`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Dev…", 11 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 32)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 29. [LOW] Hardcoded sensitive field: FIELD_DEVICE_TOKEN

- Location: `ch.protonmail.android.api.models.UnregisterDeviceRequestBodyKt`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Dev…", 11 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 33)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 30. [LOW] OkHttp logs requests/responses (Level.HEADERS)

- Location: `ch.protonmail.android.api.ProtonRetrofitPing`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW | Rule: okhttp-logging | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: HttpLoggingInterceptor is set to HEADERS: request/response data (tokens, cookies, personal data) is written to logcat, which other tools on the device or a connected PC can read.  (around line 297)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Use Level.NONE (or BASIC) in release builds; enable BODY only when BuildConfig.DEBUG.

#### 31. [LOW] HTTP client built without certificate pinning

- Location: `ch.protonmail.android.api.ProtonRetrofitPing`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 353)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 32. [LOW] Hardcoded sensitive field: PRIVATE_KEY

- Location: `ch.protonmail.android.api.utils.Fields$Keys$KeyBody`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Pri…", 10 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 51)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 33. [LOW] Hardcoded sensitive field: ENC_TOKEN

- Location: `ch.protonmail.android.api.utils.Fields$Message$Send`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Enc…", 8 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 101)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 34. [LOW] Hardcoded sensitive field: PASSWORD_HINT

- Location: `ch.protonmail.android.api.utils.Fields$Message$Send`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Pas…", 12 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 131)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 35. [LOW] Hardcoded sensitive field: PASSWORD_MODE

- Location: `ch.protonmail.android.api.utils.Fields$User`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Pas…", 12 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 147)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 36. [LOW] Hardcoded sensitive field: TOKEN_TYPE

- Location: `ch.protonmail.android.api.utils.Fields$User`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Tok…", 9 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 187)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 37. [LOW] Hardcoded sensitive field: PRIVATE_KEY

- Location: `ch.protonmail.android.api.utils.Fields$Organization`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Pri…", 10 chars), so it is baked into the APK and readable after decompiling. No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias).  (around line 110)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 38. [LOW] Temp file created

- Location: `ch.protonmail.android.activities.AddAttachmentsActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 1345)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 39. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `ch.protonmail.android.data.local.model.FullContactDetailsConverter`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 268)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 40. [MEDIUM] Weak hash: MD5

- Location: `ch.protonmail.android.data.local.model.Attachment$Companion`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 981)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 41. [MEDIUM] Predictable random value used for security

- Location: `ch.protonmail.android.data.local.model.Attachment$Companion`
- CWE: CWE-338 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: weak-random | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: The output of java.util.Random.nextInt() is returned by getRandomAttachmentId() of Attachment$Companion (a class that uses javax.crypto / MessageDigest). java.util.Random is a linear congruential generator: after a few outputs (or from the seed) every next value can be computed, so a token / PIN / key built from it can be guessed. Traced in SSA inside getRandomAttachmentId(); the receiver is a new java.util.Random (a SecureRandom held in a Random variable is not reported).  (around line 525)
- Risk scenario: java.util.Random is predictable from a few outputs; session ids, OTPs, reset tokens or keys built from it can be guessed.
- Fix: Use java.security.SecureRandom (and never a fixed seed) for tokens, PINs, salts, IVs and keys.

#### 42. [MEDIUM] File deleted while deserialising an object

- Location: `ch.protonmail.android.data.local.model.Attachment`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: serializable-dangerous | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: .method public final deleteLocalFile()V deletes a file (not a deserialisation hook, but the class is Serializable/Parcelable, so check who calls it after the object is rebuilt). Whoever can hand this object to the app (Intent extra, bound service, saved state) chooses the path that gets deleted.  (around line 1630)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Do not touch the file system from readObject / createFromParcel / constructors that read a Parcel; validate paths against an allow-list in the code that uses the object.

#### 43. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `ch.protonmail.android.data.local.model.MessagesTypesConverter`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 364)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 44. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `ch.protonmail.android.data.local.model.AttachmentHeaders`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 180)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 45. [LOW] Dynamic receiver registered without export flag

- Location: `ch.protonmail.android.core.z0`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 225)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 46. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `ch.protonmail.android.core.a1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 2016)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 47. [LOW] Credential stored in plain SharedPreferences

- Location: `ch.protonmail.android.core.a1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW | Rule: fintech-unencrypted-storage | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: A value under the key "mailbox_pin" is written with SharedPreferences.Editor.putString(), and this class never touches EncryptedSharedPreferences or the Android Keystore. Plain SharedPreferences XML is readable on a rooted device, from an adb backup, or from any app sharing the same Linux UID (shared UID apps) - for a PIN, API key or session token that's a direct credential-theft path.  (around line 2016) NOTE: this class never opens a preferences file itself (no getSharedPreferences / getDefaultSharedPreferences), so the SharedPreferences object is provided from outside (dependency injection, a field or a parameter) and may be EncryptedSharedPreferences: check where it is created before trusting this finding.
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Move this key to androidx.security.crypto.EncryptedSharedPreferences, or better, keep it only in the Android Keystore (StrongBox/TEE-backed where available) and never serialize it to disk in cleartext.

#### 48. [LOW] Data copied to clipboard

- Location: `ch.protonmail.android.details.presentation.ui.MessageDetailsActivity`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 5632)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 49. [HIGH] Weak cipher mode: ECB ("AES") (x2)

- Location: `s6.a`
- CWE: CWE-327 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-cipher | Scope: OBF
- Priority: 60/100 (P2)
- Why flagged: Cipher.getInstance("AES") uses ECB (a bare "AES"/"DES" defaults to ECB on Android): identical plaintext blocks give identical ciphertext blocks, leaking structure and allowing block swapping.  (around line 363)
- Risk scenario: DES/RC4/MD5/ECB-mode data can be decrypted or forged much faster than the key length suggests. ECB shows patterns (equal blocks give equal ciphertext) and has no integrity.
- Fix: Use AES/GCM/NoPadding with a fresh random 12-byte IV per message (or AES/CBC + HMAC if GCM is not possible).

#### 50. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `u4.e`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 195)  [Renamed by R8, but this is the app's own code: the class references the app's package.]
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 51. [LOW] Hardcoded cleartext URL

- Location: `ch.protonmail.android.views.PmWebViewClient`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://androidlinksfix.protonmail.com). Traffic to it can be read or modified on the network.  (around line 1464)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 52. [LOW] Hardcoded cleartext URL

- Location: `ch.protonmail.android.utils.t0`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://play.google.com/store/apps/details?id=ch.protonmail.a). Traffic to it can be read or modified on the network.  (around line 1540)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 53. [LOW] Data copied to clipboard

- Location: `ch.protonmail.android.utils.t0`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 864)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 54. [LOW] Temp file created

- Location: `ch.protonmail.android.utils.b`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 374)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 55. [LOW] Dynamic receiver registered without export flag

- Location: `com.birbit.android.jobqueue.network.a`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 143)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 56. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `com.birbit.android.jobqueue.persistentQueue.sqlite.SqliteJobQueue$b`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 89)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 57. [MEDIUM] Possible SQL built by string concatenation

- Location: `com.birbit.android.jobqueue.persistentQueue.sqlite.a`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat
- Priority: 38/100 (P3)
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 466)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 58. [LOW] Shell command execution

- Location: `me.proton.core.challenge.data.DeviceUtilsKt$checkRootMethod3$2`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 242)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 59. [LOW] High-entropy embedded string near a credential-like name

- Location: `me.proton.core.auth.presentation.ui.TwoPassModeActivity$onCreate$lambda$5$$inlined$onClick$1`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 40-char string with high character randomness (entropy 4.1 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "getS…".  (around line 85) No key, IV or credential use was seen in this method, so this may be a public value.
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 60. [LOW] High-entropy embedded string near a credential-like name

- Location: `me.proton.core.auth.presentation.ui.signup.ChoosePasswordFragment`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 23-char string with high character randomness (entropy 4.1 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "onNe…".  (around line 572) No key, IV or credential use was seen in this method, so this may be a public value.
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 61. [LOW] High-entropy embedded string near a credential-like name

- Location: `me.proton.core.auth.presentation.ui.UtilsKt`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 38-char string with high character randomness (entropy 3.9 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "cont…".  (around line 855) No key, IV or credential use was seen in this method, so this may be a public value.
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 62. [LOW] High-entropy embedded string near a credential-like name

- Location: `me.proton.core.auth.presentation.DefaultHelpOptionHandler`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 48-char string with high character randomness (entropy 4.2 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "cont…".  (around line 123) No key, IV or credential use was seen in this method, so this may be a public value.
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 63. [LOW] Native libraries not analysed (3 .so)

- Location: `lib/`
- Confidence: HIGH | Rule: native-coverage
- Priority: 20/100 (P4)
- Why flagged: This APK contains native libraries (libgojni.so, libsentry-android.so, libsentry.so). APKReLab analyses Java / Kotlin (dex) code only: data handed to native methods is not followed.
- Fix: Review the native code separately (e.g. strings / imports of the .so, a disassembler) and check what the app passes to its JNI methods.

#### 64. [MEDIUM] Network Security Config: cleartext permitted

- Location: `res/4u.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-cleartext
- Priority: 45/100 (P2)
- Why flagged: network_security_config.xml allows plain HTTP (cleartextTrafficPermitted=true) in base-config, i.e. for every domain the app talks to. Traffic can be read and modified on the network (MASVS-NETWORK).  [res/4u.xml]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set cleartextTrafficPermitted="false" in base-config and use HTTPS everywhere. If one legacy host really needs HTTP, allow it in a domain-config for that host only.

#### 65. [MEDIUM] FileProvider shares too much (<external-path path=".">, <cache-path path=".">, <files-path path=".">)

- Location: `res/jB.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: LOW | Rule: res-fileprovider-paths
- Priority: 27/100 (P3)
- Why flagged: These FileProvider paths cover a whole directory tree (the root of the file system or the app's private data: databases, shared_prefs, tokens). Any content:// URI the app hands out, or lets a caller choose, can then point at files that were never meant to be shared.  [res/jB.xml]
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: List only the specific sub-folder to share (for example path="shared/"), never root-path or path=".", and keep the provider exported="false" with grantUriPermissions="true".

#### 66. [LOW] Google API key in resources

- Location: `resources.arsc`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: res-strings-google-api-key
- Priority: 17/100 (P4)
- Why flagged: A Google API key (AIzaSy... (39 chars)) is stored in the app resources. The APK also has a Firebase app id, so this is the standard client key of google-services: it is meant to ship in the app, but it is only safe when it is restricted. Check it in the Google Cloud console (Credentials).  [resources.arsc]
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Restrict the key to this app (package name + SHA-1) and to the APIs you use, set a quota alert, and rotate it if it was ever unrestricted.

#### 67. [MEDIUM] Firebase Realtime Database URL

- Location: `resources.arsc`
- CWE: CWE-284 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM | Confidence: MEDIUM | Rule: res-strings-firebase-url
- Priority: 38/100 (P3)
- Why flagged: The app resources contain a Firebase Realtime Database URL (https://proton-mail-app.firebaseio.com). The URL alone is not a flaw, but if the database rules allow public reads or writes, anyone can dump or change the data. This cannot be checked statically.  [resources.arsc]
- Risk scenario: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.
- Fix: Open this URL + "/.json" from a test device you own: if it returns data, the database rules allow public reads. Lock the rules down (auth != null) and require authentication.

#### 68. [LOW] Keyboard cache: sensitive input field (x3)

- Location: `res/8_.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/8_.xml]  The same applies to 2 more layout(s): res/aR.xml, res/em.xml.
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 69. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/Q6.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f09038d") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 23: devices below Android 12 do not block touches through overlays.  [res/Q6.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 70. [MEDIUM] Untrusted data is deserialized (ObjectInputStream)

- Location: `ch.protonmail.android.data.local.model.AttachmentHeaders`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Parcel.readString() reaches ObjectInputStream.<init>() in method AttachmentHeaders.fromString(Ljava/lang/String;)Lch/protonmail/android/data/local/model/AttachmentHeaders;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. The value is read from a Parcel in one method and used in another, so this is a problem only if the whole Parcelable is received from another app (an Intent extra or a Binder call); if it only travels inside this app it is not attacker input: low confidence, check where this class is unmarshalled; The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Validate the value against an allow-list before it reaches this API.

#### 71. [LOW] Untrusted input chooses the file or content URI the app opens

- Location: `ch.protonmail.android.activities.AddAttachmentsActivity`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 8/100 (P4)
- Why flagged: Data from SharedPreferences.getString() (through ConfirmPasswordActivity.getInput()Lme/proton/core/auth/presentation/entity/confirmpass/ConfirmPasswordInput;) reaches ContentResolver.openFileDescriptor() in method AddAttachmentsActivity.r0(Ljava/util/concurrent/atomic/AtomicLong;Ljava/lang/String;)Ljava/lang/Boolean;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 5 methods. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it. The source is SharedPreferences, which only an attacker with root or a tampered backup can change: treat this as a lead, not as a confirmed flaw. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 72. [LOW] Untrusted input chooses the file or content URI the app opens

- Location: `h6.i`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 8/100 (P4)
- Why flagged: Data from SharedPreferences.getString() (through User.getRingtone()Landroid/net/Uri;) reaches ContentResolver.openInputStream() in method i.e(ILandroid/net/Uri;Z)Landroidx/core/app/v$e;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. The source is SharedPreferences, which only an attacker with root or a tampered backup can change: treat this as a lead, not as a confirmed flaw. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  [Renamed by R8, but this is the app's own code: the class references the app's package.]
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

#### CWE-749 - Exposed Dangerous Method or Function

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM

Risk: Every page the WebView loads (including injected ads or a hijacked link) can call the exposed @JavascriptInterface methods, for example to read files, tokens or start activities.

Vulnerable:

```kotlin
webView.addJavascriptInterface(Bridge(this), "app")
webView.loadUrl(urlFromIntent)
```

Secure:

```kotlin
// load only your own HTTPS origins and expose nothing else
if (Uri.parse(url).host == "app.example.com") webView.loadUrl(url)
// modern alternative with an origin allow-list: WebViewCompat.addWebMessageListener(webView, "app", setOf("https://app.example.com"), listener)
```

References: [CWE-749 (MITRE)](https://cwe.mitre.org/data/definitions/749.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-377 - Insecure Temporary File

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: A predictable temp file in a shared folder can be pre-created or replaced by another app.

Vulnerable:

```kotlin
File("/sdcard/tmp_" + id)
```

Secure:

```kotlin
File.createTempFile("tmp_", ".bin", cacheDir)   // app-private cache
```

References: [CWE-377 (MITRE)](https://cwe.mitre.org/data/definitions/377.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-502 - Deserialization of Untrusted Data

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.

Vulnerable:

```kotlin
val obj = ObjectInputStream(input).readObject()
```

Secure:

```kotlin
// use a data-only format with a schema (JSON / Protobuf) and validate every field
val dto = Json.decodeFromString<Message>(text)
// if Java serialization is unavoidable: set an ObjectInputFilter allow-list
```

References: [CWE-502 (MITRE)](https://cwe.mitre.org/data/definitions/502.html) | [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-338 - Use of Cryptographically Weak PRNG

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: java.util.Random is predictable from a few outputs; session ids, OTPs, reset tokens or keys built from it can be guessed.

Vulnerable:

```kotlin
val otp = Random().nextInt(999999)
```

Secure:

```kotlin
val otp = SecureRandom().nextInt(1_000_000)
```

References: [CWE-338 (MITRE)](https://cwe.mitre.org/data/definitions/338.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-284 - Improper Access Control

OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM

Risk: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.

Vulnerable:

```kotlin
// Firebase rules: { ".read": true, ".write": true }
```

Secure:

```kotlin
// Firebase rules: only authenticated users, only their own node
{ "rules": { "users": { "uid": { ".read": "auth != null && auth.uid == 'uid'" } } } }
// test your own database from a device you own: open PROJECT-ID.firebaseio.com/.json  -> it must answer Permission denied
```

References: [CWE-284 (MITRE)](https://cwe.mitre.org/data/definitions/284.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


