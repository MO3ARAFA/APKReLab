# APK ReLab report: com.nononsenseapps.feeder

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 152 finding(s) in total; 36 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| MEDIUM | 17 |
| LOW | 18 |

**OWASP Mobile Top 10 (2024) coverage**

- M8 Security Misconfiguration: 12
- M4 Insufficient Input/Output Validation: 10
- M5 Insecure Communication: 6
- M9 Insecure Data Storage: 5
- M3 Insecure Authentication/Authorization: 2
- Not mapped: 1

### Findings

#### 1. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 2. [MEDIUM] Cleartext (plain HTTP) traffic allowed

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: manifest-cleartext-traffic
- Priority: 45/100 (P2)
- Why flagged: android:usesCleartextTraffic="true" lets the app make plain HTTP requests. Anyone sharing the network (public Wi-Fi, a compromised router) can read or tamper with that traffic.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set usesCleartextTraffic to "false" and use HTTPS everywhere; if a few hosts genuinely need HTTP, scope that with a network security config instead of a blanket allow.

#### 3. [LOW] Deep link entry point: com.nononsenseapps.feeder.ui.AddFeedFromShareActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 17/100 (P4)
- Why flagged: This activity can be opened from a browser/other apps via http, https://*. Anything in the link (path, query, fragment) is attacker-controlled input. No android:autoVerify, so the link is not verified as belonging to this app.
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 4. [MEDIUM] Exported provider guarded by a weak custom permission: com.nononsenseapps.feeder.contentprovider.RSSContentProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-permission-protection
- Priority: 45/100 (P2)
- Why flagged: The permission protecting this provider ("com.nononsenseapps.feeder.permission.read") is declared with android:protectionLevel="normal". Unlike "signature", a normal/dangerous permission is not tied to the app's signing key - any other app can request it in its own manifest (a dangerous one may need a one-time user grant, a normal one is silent) and then use this component freely.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Declare the permission with android:protectionLevel="signature" if only your own apps (same signing key) should use this component, or review whether exporting it at all is necessary.

#### 5. [MEDIUM] Exported activity without a permission: com.nononsenseapps.feeder.ui.ManageSettingsActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [LOW] Exported activity without a permission: com.nononsenseapps.feeder.ui.ImportOPMLFileActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: VIEW, SEND).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 7. [LOW] Exported activity without a permission: com.nononsenseapps.feeder.ui.AddFeedFromShareActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: VIEW, SEND).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 8. [MEDIUM] Exported activity without a permission: com.nononsenseapps.feeder.ui.OpenLinkInDefaultActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 9. [MEDIUM] Exported activity without a permission: androidx.compose.ui.tooling.PreviewActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 10. [MEDIUM] Exported provider protects only reads: com.nononsenseapps.feeder.contentprovider.RSSContentProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-provider-partial-permission
- Priority: 45/100 (P2)
- Why flagged: This exported provider declares android:readPermission but no writePermission, so any app can insert / update / delete its data.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Declare both readPermission and writePermission (signature level if only your own apps need it), or use android:permission for both.

#### 11. [LOW] Dynamic receiver registered without export flag

- Location: `zq`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 60)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 12. [LOW] Data copied to clipboard

- Location: `c8`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 73)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 13. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `ac1`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 192)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 14. [LOW] Possible SQL built by string concatenation

- Location: `o86`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 1285)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 15. [LOW] Dynamic receiver registered without export flag

- Location: `dh0`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 137)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 16. [LOW] Dynamic receiver registered without export flag

- Location: `z31`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 126)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 17. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `com.ibm.icu.text.MessageFormat`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 5577)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 18. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `com.ibm.icu.text.DecimalFormat`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 522)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 19. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `com.ibm.icu.text.RuleBasedNumberFormat`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 2566)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 20. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `com.ibm.icu.impl.number.DecimalFormatProperties`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 3032)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 21. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `com.ibm.icu.impl.TimeZoneNamesImpl`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 1502)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 22. [LOW] Hardcoded cleartext URL

- Location: `com.nononsenseapps.feeder.ui.text.HtmlToPlainTextConverter`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://www.ccil.org/~cowan/tagsoup/properties/schema). Traffic to it can be read or modified on the network.  (around line 247)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 23. [LOW] Hardcoded cleartext URL

- Location: `com.nononsenseapps.feeder.ui.text.VideoTagHunterKt`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://img.youtube.com/vi/). Traffic to it can be read or modified on the network.  (around line 119)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 24. [LOW] Possible sensitive data in logs

- Location: `com.nononsenseapps.feeder.ui.compose.sync.SyncScreenKt`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: log-sensitive-strings | Scope: APP
- Priority: 17/100 (P4)
- Why flagged: A string passed near a Log call mentions a credential-like word ("Failed to decode secret key"). Logcat output can be read by other apps with the right permission on many devices.  (around line 22133)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Never log passwords, tokens, or session identifiers, even at debug level; strip such log calls from release builds.

#### 25. [LOW] Data copied to clipboard

- Location: `com.nononsenseapps.feeder.ui.compose.utils.FeederTextActionModeCallback`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 1518)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 26. [MEDIUM] Cloud storage bucket URL (S3/GCS)

- Location: `com.nononsenseapps.feeder.localtranslation.BergamotModelManager`
- CWE: CWE-284 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: A string literal matches this pattern (bergam... (25 chars)). Anything inside the APK can be extracted by anyone who downloads it.  (around line 3622)
- Risk scenario: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.
- Fix: Check the bucket's ACL/policy: it must not allow public listing or writes. Use pre-signed URLs from your backend.

#### 27. [MEDIUM] WebView addJavascriptInterface

- Location: `com.nononsenseapps.feeder.localtranslation.BergamotWebTranslator`
- CWE: CWE-749 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: webview-js-interface | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: A Java/Kotlin object is bridged into a WebView's JavaScript context. Any page the WebView loads - including one reached via a hijacked link or a MITM'd connection - can call that object's @JavascriptInterface methods. The bridge object is another class: its @JavascriptInterface methods are judged there ("JavaScript-exposed method" findings).  (around line 685)
- Risk scenario: Every page the WebView loads (including injected ads or a hijacked link) can call the exposed @JavascriptInterface methods, for example to read files, tokens or start activities.
- Fix: Avoid exposing a JS interface to untrusted pages; restrict it to known HTTPS origins, or use WebMessageListener on modern APIs instead.

#### 28. [LOW] WebView JavaScript enabled

- Location: `com.nononsenseapps.feeder.localtranslation.BergamotWebTranslator`
- CWE: CWE-79 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: setJavaScriptEnabled(true) widens the attack surface of every page this WebView loads.  (around line 573)
- Risk scenario: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.
- Fix: Enable it only if needed and only for trusted https:// origins.

#### 29. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `com.nononsenseapps.feeder.archmodel.SettingsStore`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 8805)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 30. [CRITICAL] TLS certificate validation disabled

- Location: `com.nononsenseapps.jsonfeed.OkHttpBuilderExtensionsKt$trustAllCerts$trustManager$1`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-trustmanager | Scope: APP
- Priority: 90/100 (P1)
- Why flagged: This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.  (around line 71)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.

#### 31. [LOW] Dynamic receiver registered without export flag

- Location: `rz6`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 55)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 32. [LOW] Dynamic receiver registered without export flag

- Location: `v3`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 3325)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 33. [LOW] Hardcoded cleartext URL

- Location: `org.ccil.cowan.tagsoup.CommandLine`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://www.ccil.org/~cowan/tagsoup/properties/schema) and 9 more in this class. Traffic to it can be read or modified on the network.  (around line 1541)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 34. [LOW] Hardcoded cleartext URL

- Location: `org.ccil.cowan.tagsoup.Parser`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://www.ccil.org/~cowan/tagsoup/features/ignore-bogons) and 21 more in this class. Traffic to it can be read or modified on the network.  (around line 533)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 35. [LOW] Native libraries not analysed (2 .so)

- Location: `lib/`
- Confidence: HIGH | Rule: native-coverage
- Priority: 20/100 (P4)
- Why flagged: This APK contains native libraries (libandroidx.graphics.path.so, libgojni.so). APKReLab analyses Java / Kotlin (dex) code only: data handed to native methods is not followed.
- Fix: Review the native code separately (e.g. strings / imports of the .so, a disassembler) and check what the app passes to its JNI methods.

#### 36. [MEDIUM] Untrusted input is used as a file path

- Location: `com.nononsenseapps.feeder.archmodel.FontStoreKt`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Why flagged: Data from SharedPreferences.getString() (through PrefUtilsKt.getStringNonNull(Landroid/content/SharedPreferences;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;) reaches FileInputStream.<init>() in method FontStoreKt.getFontMetadata(Ljava/io/File;)Lcom/nononsenseapps/feeder/truetype/TrueTypeMetadata;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. The source is SharedPreferences, which only an attacker with root or a tampered backup can change: treat this as a lead, not as a confirmed flaw.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

### Remediation guide

One entry per weakness type found above.

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

#### CWE-79 - Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM

Risk: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.

Vulnerable:

```kotlin
webView.loadData("<h1>Hello " + userName + "</h1>", "text/html", "UTF-8")
```

Secure:

```kotlin
val safe = android.text.Html.escapeHtml(userName)   // or TextUtils.htmlEncode
webView.loadDataWithBaseURL(null, "<h1>Hello " + safe + "</h1>", "text/html", "UTF-8", null)
// plus: keep JavaScript off unless needed, no JS interface on untrusted pages
```

References: [CWE-79 (MITRE)](https://cwe.mitre.org/data/definitions/79.html) | [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


