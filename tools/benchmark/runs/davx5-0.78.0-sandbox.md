# APK ReLab report: at.bitfire.davdroid

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 222 finding(s) in total; 36 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| HIGH | 2 |
| MEDIUM | 26 |
| LOW | 8 |

**OWASP Mobile Top 10 (2024) coverage**

- M8 Security Misconfiguration: 17
- M9 Insecure Data Storage: 7
- M4 Insufficient Input/Output Validation: 5
- M5 Insecure Communication: 4
- M3 Insecure Authentication/Authorization: 2
- M10 Insufficient Cryptography: 1

### Findings

#### 1. [MEDIUM] Deep link entry point: net.openid.appauth.RedirectUriReceiverActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 38/100 (P3)
- Why flagged: This activity can be opened from a browser/other apps via at.bitfire.davdroid://. Anything in the link (path, query, fragment) is attacker-controlled input, and a custom scheme with no host can be claimed by any other installed app (link hijacking).
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 2. [MEDIUM] Deep link entry point: at.bitfire.davdroid.ui.setup.LoginActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 38/100 (P3)
- Why flagged: This activity can be opened from a browser/other apps via caldav, caldavs, carddav, carddavs, davx5, http, https://. Anything in the link (path, query, fragment) is attacker-controlled input, and a custom scheme with no host can be claimed by any other installed app (link hijacking). No android:autoVerify, so the link is not verified as belonging to this app.
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 3. [LOW] Exported activity without a permission: net.openid.appauth.RedirectUriReceiverActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [LOW] Exported activity without a permission: at.bitfire.davdroid.ui.AppSettingsActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: APPLICATION_PREFERENCES).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [MEDIUM] Exported activity without a permission: at.bitfire.davdroid.ui.setup.LoginActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [MEDIUM] Exported activity without a permission: at.bitfire.davdroid.ui.account.AccountActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 7. [MEDIUM] Exported activity without a permission: at.bitfire.davdroid.ui.webdav.WebdavMountsActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 8. [MEDIUM] Exported service without a permission: at.bitfire.davdroid.sync.adapter.CalendarsSyncAdapterService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 9. [MEDIUM] Exported service without a permission: at.bitfire.davdroid.sync.adapter.JtxSyncAdapterService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 10. [MEDIUM] Exported service without a permission: at.bitfire.davdroid.sync.adapter.OpenTasksSyncAdapterService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 11. [MEDIUM] Exported service without a permission: at.bitfire.davdroid.sync.adapter.TasksOrgSyncAdapterService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 12. [MEDIUM] Exported service without a permission: at.bitfire.davdroid.sync.account.AddressBookAuthenticatorService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 13. [MEDIUM] Exported service without a permission: at.bitfire.davdroid.sync.adapter.ContactsSyncAdapterService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 14. [MEDIUM] Exported activity without a permission: at.bitfire.cert4android.TrustCertificateActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 15. [MEDIUM] Exported service without a permission: org.unifiedpush.android.connector.internal.RaiseToForegroundService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 16. [MEDIUM] Exported receiver without a permission: org.unifiedpush.android.connector.internal.MessagingReceiverImpl

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This receiver is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 17. [MEDIUM] Provider grants URI permissions broadly: at.bitfire.davdroid.webdav.DavDocumentsProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-exported-provider-grant-uri
- Priority: 38/100 (P3)
- Why flagged: android:grantUriPermissions="true" on the whole provider lets any Intent that carries a content:// Uri of it hand temporary access to the receiving app, for every path of the provider.
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Limit it with <grant-uri-permission android:path/pathPrefix=...> to only the paths that must be shared, and check the FileProvider paths XML does not expose root-path or the whole external storage.

#### 18. [MEDIUM] Powerful permissions requested (1)

- Location: `AndroidManifest.xml`
- CWE: CWE-250 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-powerful-permissions
- Priority: 45/100 (P2)
- Why flagged: - ACCESS_BACKGROUND_LOCATION: tracks location in the background
- Risk scenario: Extra privileges (debuggable, test-only, shared user id, legacy storage) widen what a compromise or a malicious app can reach. Powerful permissions (SMS, overlay, install packages) and an AccessibilityService give a compromised app, or overlay and banking malware, far more reach than the feature needs.
- Fix: Request only what the feature really needs, and prefer the narrower alternative (photo picker, SAF, SMS Retriever / User Consent API instead of READ_SMS).

#### 19. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `net.fortuna.ical4j.model.property.Attach`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 203)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 20. [LOW] Temp file created

- Location: `net.fortuna.ical4j.model.property.Attach`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 714)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 21. [LOW] Hardcoded cleartext URL

- Location: `net.fortuna.ical4j.data.HCalendarParser`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://javax.xml.XMLConstants/feature/secure-processing) and 2 more in this class. Traffic to it can be read or modified on the network.  (around line 170)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 22. [LOW] Dynamic receiver registered without export flag

- Location: `net.openid.appauth.JsonUtil$Field`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1100)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 23. [MEDIUM] Possible SQL built by string concatenation

- Location: `org.unifiedpush.android.connector.internal.DBStore$KeyStore`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat
- Priority: 38/100 (P3)
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 191)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 24. [MEDIUM] Sensitive data stored in plain SQLite

- Location: `org.unifiedpush.android.connector.internal.DBStore$KeyStore`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: sqlite-unencrypted
- Priority: 38/100 (P3)
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "connectorToken" (ContentValues.put). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 1121)  Also matched by: androgoat-checks (merged).
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 25. [MEDIUM] Sensitive data stored in plain SQLite

- Location: `org.unifiedpush.android.connector.internal.DBStore`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: sqlite-unencrypted
- Priority: 45/100 (P2)
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "connectorToken" (CREATE TABLE column). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 222)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 26. [LOW] Hardcoded cleartext URL

- Location: `at.bitfire.dav4jvm.property.caldav.CalDAV`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://apple.com/ns/ical/) and 1 more in this class. Traffic to it can be read or modified on the network.  (around line 400)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 27. [LOW] Dynamic receiver registered without export flag

- Location: `at.bitfire.davdroid.util.BroadcastReceiverFlowKt$broadcastReceiverFlow$1`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 710)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 28. [MEDIUM] Shell command execution

- Location: `at.bitfire.davdroid.ui.DebugInfoViewModel`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 795)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 29. [LOW] Data copied to clipboard

- Location: `at.bitfire.davdroid.ui.DebugInfoActivity`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 1005)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 30. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `at.bitfire.davdroid.settings.migration.AccountSettingsMigration12`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 762)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 31. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `at.bitfire.davdroid.webdav.CredentialsStore`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 1314)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 32. [MEDIUM] Sensitive data stored in plain SQLite

- Location: `at.bitfire.davdroid.sync.SyncNotificationManager$$ExternalSyntheticLambda1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: sqlite-unencrypted | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "connectorToken" (ContentValues.put). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 889)  Also matched by: androgoat-checks (merged).
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 33. [MEDIUM] SecureRandom(SHA1PRNG) seeded manually

- Location: `io.ktor.util.NonceKt$nonceGeneratorJob$1`
- CWE: CWE-336 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-sha1prng-seed | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: SecureRandom.getInstance("SHA1PRNG") followed by setSeed() in the same method. With SHA1PRNG a seed set before the first use makes the output deterministic, so keys/tokens/IVs generated from it can be predicted (the classic Android key-derivation bug).  (around line 235)
- Risk scenario: A manually seeded or constant-seeded generator produces a sequence the attacker can reproduce, so tokens, keys or IVs derived from it can be guessed.
- Fix: Use new SecureRandom() without setSeed (the platform seeds it), and derive keys with a KDF or the Android Keystore.

#### 34. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `io.ktor.util.TextKt`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 4391)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 35. [HIGH] Network Security Config: cleartext permitted

- Location: `res/8G.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-cleartext
- Priority: 70/100 (P1)
- Why flagged: network_security_config.xml allows plain HTTP (cleartextTrafficPermitted=true) in base-config, i.e. for every domain the app talks to. Traffic can be read and modified on the network (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set cleartextTrafficPermitted="false" in base-config and use HTTPS everywhere. If one legacy host really needs HTTP, allow it in a domain-config for that host only.

#### 36. [HIGH] Network Security Config: trusts user-installed CAs

- Location: `res/8G.xml`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-user-ca
- Priority: 70/100 (P1)
- Why flagged: The config trusts certificates the user installed in: base-config (every domain). A proxy such as Burp/mitmproxy (or malware that installs a CA) can then decrypt this app's HTTPS traffic (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Trust only the system CAs (src="system") in release builds; keep user CAs inside <debug-overrides> only.

### Remediation guide

One entry per weakness type found above.

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

#### CWE-250 - Execution with Unnecessary Privileges

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: Extra privileges (debuggable, test-only, shared user id, legacy storage) widen what a compromise or a malicious app can reach. Powerful permissions (SMS, overlay, install packages) and an AccessibilityService give a compromised app, or overlay and banking malware, far more reach than the feature needs.

Vulnerable:

```kotlin
<application android:debuggable="true" android:testOnly="true" ...>
<uses-permission android:name="android.permission.READ_SMS" />
```

Secure:

```kotlin
<!-- ship release builds without debuggable / testOnly; request only the permissions you use -->
<!-- OTP codes: SMS Retriever or SMS User Consent API instead of READ_SMS; files: photo picker or the Storage Access Framework -->
```

References: [CWE-250 (MITRE)](https://cwe.mitre.org/data/definitions/250.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-336 - Same Seed in Pseudo-Random Number Generator (PRNG)

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: A manually seeded or constant-seeded generator produces a sequence the attacker can reproduce, so tokens, keys or IVs derived from it can be guessed.

Vulnerable:

```kotlin
val r = SecureRandom.getInstance("SHA1PRNG"); r.setSeed(12345L)
```

Secure:

```kotlin
val r = SecureRandom()    // self-seeds from the OS; do not call setSeed with a fixed value
```

References: [CWE-336 (MITRE)](https://cwe.mitre.org/data/definitions/336.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


