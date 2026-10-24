# APK ReLab report: org.jellyfin.mobile

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 146 finding(s) in total; 37 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| HIGH | 3 |
| MEDIUM | 9 |
| LOW | 25 |

**OWASP Mobile Top 10 (2024) coverage**

- M8 Security Misconfiguration: 15
- M4 Insufficient Input/Output Validation: 15
- M9 Insecure Data Storage: 4
- M5 Insecure Communication: 2
- Not mapped: 1

### Findings

#### 1. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 2. [MEDIUM] Exported service without a permission: org.jellyfin.mobile.sessionbrowser.LibraryService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 3. [MEDIUM] Exported receiver without a permission: androidx.mediarouter.media.MediaTransferReceiver

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This receiver is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [MEDIUM] Exported provider protects only reads: org.jellyfin.mobile.ui.content.ImageProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-provider-partial-permission
- Priority: 45/100 (P2)
- Why flagged: This exported provider declares android:readPermission but no writePermission, so any app can insert / update / delete its data.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Declare both readPermission and writePermission (signature level if only your own apps need it), or use android:permission for both.

#### 5. [MEDIUM] Provider grants URI permissions broadly: org.jellyfin.mobile.ui.content.ImageProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-exported-provider-grant-uri
- Priority: 38/100 (P3)
- Why flagged: android:grantUriPermissions="true" on the whole provider lets any Intent that carries a content:// Uri of it hand temporary access to the receiving app, for every path of the provider.
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Limit it with <grant-uri-permission android:path/pathPrefix=...> to only the paths that must be shared, and check the FileProvider paths XML does not expose root-path or the whole external storage.

#### 6. [LOW] Low minSdkVersion (21)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-min-sdk
- Priority: 12/100 (P4)
- Why flagged: Supporting API < 23 (Android 6) means the app can run on devices without runtime permission prompts and with older TLS/cipher defaults.
- Fix: Raise minSdkVersion if the user base allows it; otherwise double check that sensitive permissions and network calls are still handled safely on the oldest supported devices.

#### 7. [LOW] Possible SQL built by string concatenation

- Location: `nm1`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 1234)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 8. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `ta2`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 509)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 9. [LOW] Dynamic receiver registered without export flag

- Location: `tb2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 982)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 10. [LOW] Possible SQL built by string concatenation

- Location: `yr3`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 168)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 11. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `org.jellyfin.mobile.downloads.NotificationProgressCallback`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 280)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 12. [LOW] Shared external storage used

- Location: `org.jellyfin.mobile.app.StorageManager`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 327)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 13. [LOW] Dynamic receiver registered without export flag

- Location: `org.jellyfin.mobile.webapp.RemotePlayerService`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1761)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 14. [MEDIUM] WebView addJavascriptInterface

- Location: `org.jellyfin.mobile.webapp.WebViewFragment`
- CWE: CWE-749 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: webview-js-interface | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: A Java/Kotlin object is bridged into a WebView's JavaScript context. Any page the WebView loads - including one reached via a hijacked link or a MITM'd connection - can call that object's @JavascriptInterface methods. The bridge object is another class: its @JavascriptInterface methods are judged there ("JavaScript-exposed method" findings).  (around line 687)
- Risk scenario: Every page the WebView loads (including injected ads or a hijacked link) can call the exposed @JavascriptInterface methods, for example to read files, tokens or start activities.
- Fix: Avoid exposing a JS interface to untrusted pages; restrict it to known HTTPS origins, or use WebMessageListener on modern APIs instead.

#### 15. [HIGH] JavaScript-exposed method reaches a sensitive API

- Location: `org.jellyfin.mobile.bridge.NativeInterface`
- CWE: CWE-749 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: webview-js-bridge-method | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: Methods of this class are annotated @JavascriptInterface, so JavaScript in any page of a WebView that bridges this object can call them, and they reach: hideMediaSession(): starting components / broadcasts. A malicious or MITM'd page can use them with the app's permissions.  (around line 188)
- Risk scenario: Every page the WebView loads (including injected ads or a hijacked link) can call the exposed @JavascriptInterface methods, for example to read files, tokens or start activities.
- Fix: Expose only what the page needs, validate every argument as untrusted input, and load only your own HTTPS content in a WebView with a bridge.

#### 16. [LOW] WebView JavaScript enabled

- Location: `org.jellyfin.mobile.utils.WebViewUtilsKt`
- CWE: CWE-79 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: setJavaScriptEnabled(true) widens the attack surface of every page this WebView loads.  (around line 19)
- Risk scenario: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.
- Fix: Enable it only if needed and only for trusted https:// origins.

#### 17. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `xf0`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 255)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 18. [LOW] Dynamic receiver registered without export flag

- Location: `wm`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 109)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 19. [LOW] Data copied to clipboard

- Location: `u7`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 81)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 20. [LOW] Possible SQL built by string concatenation

- Location: `jc3`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 1264)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 21. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `v5`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 110)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 22. [LOW] Dynamic receiver registered without export flag

- Location: `mr`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 78)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 23. [LOW] PendingIntent without FLAG_IMMUTABLE (x2)

- Location: `sk0`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 1538)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 24. [LOW] Dynamic receiver registered without export flag

- Location: `an`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 497)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 25. [LOW] Possible SQL built by string concatenation

- Location: `ux3`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 3210)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 26. [LOW] Dynamic receiver registered without export flag

- Location: `s2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 481)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 27. [LOW] Dynamic receiver registered without export flag

- Location: `nb2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 503)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 28. [LOW] Dynamic receiver registered without export flag

- Location: `vu`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 106)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 29. [HIGH] Network Security Config: cleartext permitted

- Location: `res/8G.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-cleartext
- Priority: 70/100 (P1)
- Why flagged: network_security_config.xml allows plain HTTP (cleartextTrafficPermitted=true) in base-config, i.e. for every domain the app talks to. Traffic can be read and modified on the network (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set cleartextTrafficPermitted="false" in base-config and use HTTPS everywhere. If one legacy host really needs HTTP, allow it in a domain-config for that host only.

#### 30. [HIGH] Network Security Config: trusts user-installed CAs

- Location: `res/8G.xml`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-user-ca
- Priority: 70/100 (P1)
- Why flagged: The config trusts certificates the user installed in: base-config (every domain). A proxy such as Burp/mitmproxy (or malware that installs a CA) can then decrypt this app's HTTPS traffic (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Trust only the system CAs (src="system") in release builds; keep user CAs inside <debug-overrides> only.

#### 31. [LOW] Untrusted input reaches an SQL statement

- Location: `cn3`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readBundle() (through field nm1.r:Ljava/lang/Object; (written in aj0.c(Lru0;)V)) reaches SQLiteDatabase.delete() in method cn3.k()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 32. [MEDIUM] Untrusted input reaches an SQL statement

- Location: `k91`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readBundle() (through q0.next()Ljava/lang/Object;) reaches SQLiteDatabase.compileStatement() in method k91.o(Ljava/lang/String;)Lmw3;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 33. [LOW] Untrusted input reaches an SQL statement

- Location: `nm1`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readBundle() (through field nm1.r:Ljava/lang/Object; (written in aj0.c(Lru0;)V)) reaches SQLiteDatabase.execSQL() in method nm1.h(J)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call. 2 flows of this kind end in this method.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 34. [LOW] Untrusted input reaches an SQL statement

- Location: `nm1`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readBundle() (through field nm1.r:Ljava/lang/Object; (written in aj0.c(Lru0;)V)) reaches SQLiteDatabase.delete() in method nm1.m(Ljava/util/Set;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 35. [LOW] Untrusted input is used as a file path

- Location: `ta2`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readBundle() (through field ta2.r:Ljava/lang/Object; (written in x13.i(Lqy1;Lbl;Z)V)) reaches FileOutputStream.<init>() in method ta2.A()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 36. [LOW] Untrusted input selects a class or method by name

- Location: `gy2`
- CWE: CWE-470 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readBundle() (through gy2.n(I)Landroid/os/Bundle;) reaches Class.forName() in method gy2.l(ILandroid/os/Bundle;)Lgy2;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: A class or method name coming from outside lets the attacker pick which code runs.
- Fix: Look the name up in an explicit allow-list (a map of known keys to classes) instead of passing it to Class.forName / getMethod.

#### 37. [MEDIUM] Untrusted input is loaded into a WebView

- Location: `org.jellyfin.mobile.webapp.WebViewFragment`
- CWE: CWE-79 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: Data from Parcel.readBundle() (through zt3.c1(Ljava/lang/String;[C)Ljava/lang/String;) reaches WebView.loadUrl() in method WebViewFragment.initialize(Landroid/webkit/WebView;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.
- Fix: Allow-list the scheme and host before loading (https and your own domains only), or map a small id to a fixed URL. Never pass an Intent extra straight to the WebView.

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

#### CWE-470 - Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: A class or method name coming from outside lets the attacker pick which code runs.

Vulnerable:

```kotlin
Class.forName(intent.getStringExtra("cls")).newInstance()
```

Secure:

```kotlin
val handlers = mapOf("a" to ::HandlerA, "b" to ::HandlerB)     // explicit allow-list
val h = handlers[intent.getStringExtra("cls")]?.invoke() ?: return
```

References: [CWE-470 (MITRE)](https://cwe.mitre.org/data/definitions/470.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)


