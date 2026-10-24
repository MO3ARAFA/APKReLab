# APK ReLab report: ml.docilealligator.infinityforreddit.plus

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 278 finding(s) in total; 69 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| HIGH | 2 |
| MEDIUM | 11 |
| LOW | 56 |

**OWASP Mobile Top 10 (2024) coverage**

- M9 Insecure Data Storage: 31
- M8 Security Misconfiguration: 17
- M4 Insufficient Input/Output Validation: 12
- M3 Insecure Authentication/Authorization: 4
- M5 Insecure Communication: 2
- M10 Insufficient Cryptography: 2
- Not mapped: 1

### Findings

#### 1. [HIGH] Cleartext (plain HTTP) traffic allowed

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: manifest-cleartext-traffic
- Priority: 70/100 (P1)
- Why flagged: android:usesCleartextTraffic="true" lets the app make plain HTTP requests. Anyone sharing the network (public Wi-Fi, a compromised router) can read or tamper with that traffic.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Set usesCleartextTraffic to "false" and use HTTPS everywhere; if a few hosts genuinely need HTTP, scope that with a network security config instead of a blanket allow.

#### 2. [LOW] Deep link entry point: ml.docilealligator.infinityforreddit.activities.LinkResolverActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 17/100 (P4)
- Why flagged: This activity can be opened from a browser/other apps via https, http://www.reddit.com|reddit.com|v.redd.it|amp.reddit.com|m.reddit.com|old.reddit.com|new.reddit.com|np.reddit.com|reddit.app.link|redd.it|s.reddit.com|click.redditmail.com|www.google.com. Anything in the link (path, query, fragment) is attacker-controlled input. No android:autoVerify, so the link is not verified as belonging to this app.
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 3. [LOW] Exported activity without a permission: ml.docilealligator.infinityforreddit.activities.LoginChromeCustomTabActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [LOW] Exported activity without a permission: ml.docilealligator.infinityforreddit.activities.ShareDataResolverActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: SEND).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [LOW] Exported activity without a permission: ml.docilealligator.infinityforreddit.activities.LinkResolverActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: SEND, VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [LOW] Low minSdkVersion (21)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-min-sdk
- Priority: 12/100 (P4)
- Why flagged: Supporting API < 23 (Android 6) means the app can run on devices without runtime permission prompts and with older TLS/cipher defaults.
- Fix: Raise minSdkVersion if the user base allows it; otherwise double check that sensitive permissions and network calls are still handled safely on the oldest supported devices.

#### 7. [LOW] Dynamic receiver registered without export flag

- Location: `h6.v`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 124)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 8. [LOW] Possible SQL built by string concatenation

- Location: `l6.f`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 99)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 9. [LOW] Possible SQL built by string concatenation

- Location: `l6.l$a`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 218)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 10. [LOW] Dynamic receiver registered without export flag

- Location: `j.h$p`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 162)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 11. [LOW] Dynamic receiver registered without export flag

- Location: `q6.b`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1441)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 12. [LOW] Dynamic receiver registered without export flag

- Location: `o6.z2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 156)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 13. [LOW] Dynamic receiver registered without export flag

- Location: `o6.b`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 111)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 14. [LOW] Possible SQL built by string concatenation

- Location: `j6.c`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 191)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 15. [LOW] Hardcoded cleartext URL

- Location: `s6.d`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://dashif.org/guidelines/last-segment-number) and 3 more in this class. Traffic to it can be read or modified on the network.  (around line 1387)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 16. [LOW] Temp file created

- Location: `z8.x`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 305)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 17. [LOW] Data copied to clipboard

- Location: `a3.f`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 186)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 18. [LOW] Temp file created

- Location: `sc.a$c`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 216)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 19. [LOW] Shared external storage used

- Location: `sc.a`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 350)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 20. [LOW] PendingIntent without FLAG_IMMUTABLE (x2)

- Location: `ha.a`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 194)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 21. [LOW] Data copied to clipboard

- Location: `rn.t6`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 241)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 22. [LOW] Data copied to clipboard

- Location: `rn.m0`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 265)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 23. [LOW] Data copied to clipboard

- Location: `rn.w1`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 139)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 24. [MEDIUM] Possible Zip Slip (unsanitized zip entry path)

- Location: `ua.r`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: zip-slip | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: This method reads ZipEntry.getName() while extracting an archive and builds a File/output path from it, with no getCanonicalPath()/normalize() check anywhere in the method. A crafted entry name containing "../" segments can write outside the intended extraction directory (e.g. overwrite app files or drop an executable in a sensitive location).  (around line 200)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Resolve the destination file, call getCanonicalPath() on it, and verify it still starts with the intended output directory before writing; reject/skip any entry that fails the check.

#### 25. [LOW] Dynamic receiver registered without export flag

- Location: `la.e`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 148)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 26. [LOW] Dynamic receiver registered without export flag

- Location: `la.c`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 314)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 27. [LOW] Dynamic receiver registered without export flag

- Location: `la.a`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 476)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 28. [LOW] Dynamic receiver registered without export flag

- Location: `la.m`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 309)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 29. [MEDIUM] Cloud storage bucket URL (S3/GCS)

- Location: `ln.u1`
- CWE: CWE-284 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: A string literal matches this pattern (reddit... (49 chars)). Anything inside the APK can be extracted by anyone who downloads it.  (around line 1114)
- Risk scenario: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.
- Fix: Check the bucket's ACL/policy: it must not allow public listing or writes. Use pre-signed URLs from your backend.

#### 30. [LOW] Sensitive value saved to SharedPreferences (plaintext)

- Location: `ln.d3`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 3508)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 31. [LOW] Dynamic receiver registered without export flag

- Location: `dc.r$e$b`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 89)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 32. [LOW] Weak hash: SHA-1

- Location: `fd.c`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 65)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 33. [LOW] Dynamic receiver registered without export flag

- Location: `ib.l1`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 118)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 34. [LOW] Shell command execution

- Location: `pc.b`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 215)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 35. [LOW] Shell command execution

- Location: `pc.d`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 233)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 36. [LOW] Data copied to clipboard

- Location: `gg.k`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 738)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 37. [LOW] Sensitive value saved to SharedPreferences (plaintext)

- Location: `uo.e`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 559)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 38. [LOW] Data copied to clipboard

- Location: `ml.docilealligator.infinityforreddit.activities.CustomThemeListingActivity$c`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 142)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 39. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.PostGalleryActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 1808)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 40. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `ml.docilealligator.infinityforreddit.activities.LoginChromeCustomTabActivity$b$a`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 218)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 41. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.PostTextActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 2400)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 42. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `ml.docilealligator.infinityforreddit.activities.LoginActivity$b$a$a`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 238)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 43. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.PostImageActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 947)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 44. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.EditCommentActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 1041)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 45. [LOW] Data copied to clipboard

- Location: `ml.docilealligator.infinityforreddit.activities.b`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 3319)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 46. [MEDIUM] Cloud storage bucket URL (S3/GCS)

- Location: `ml.docilealligator.infinityforreddit.activities.LinkResolverActivity`
- CWE: CWE-284 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: A string literal matches this pattern (reddit... (49 chars)). Anything inside the APK can be extracted by anyone who downloads it.  (around line 956)
- Risk scenario: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.
- Fix: Check the bucket's ACL/policy: it must not allow public listing or writes. Use pre-signed URLs from your backend.

#### 47. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.EditPostActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 218)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 48. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.CommentActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 1119)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 49. [LOW] Data copied to clipboard

- Location: `ml.docilealligator.infinityforreddit.activities.WebViewActivity`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 818)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 50. [LOW] Temp file created

- Location: `ml.docilealligator.infinityforreddit.activities.PostPollActivity`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 1782)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 51. [LOW] Data copied to clipboard

- Location: `ml.docilealligator.infinityforreddit.activities.CustomThemeListingActivity`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 152)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 52. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `ml.docilealligator.infinityforreddit.thing.d`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 540)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 53. [LOW] Secret token stored in plain SharedPreferences

- Location: `ml.docilealligator.infinityforreddit.thing.d`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW | Rule: fintech-unencrypted-storage | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: A value under the key "redgifs_access_token" is written with SharedPreferences.Editor.putString(), and this class never touches EncryptedSharedPreferences or the Android Keystore. Plain SharedPreferences XML is readable on a rooted device, from an adb backup, or from any app sharing the same Linux UID (shared UID apps) - for a PIN, API key or session token that's a direct credential-theft path.  (around line 540) NOTE: this class never opens a preferences file itself (no getSharedPreferences / getDefaultSharedPreferences), so the SharedPreferences object is provided from outside (dependency injection, a field or a parameter) and may be EncryptedSharedPreferences: check where it is created before trusting this finding.
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Move this key to androidx.security.crypto.EncryptedSharedPreferences, or better, keep it only in the Android Keystore (StrongBox/TEE-backed where available) and never serialize it to disk in cleartext.

#### 54. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `ml.docilealligator.infinityforreddit.asynctasks.f`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 82)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 55. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `ml.docilealligator.infinityforreddit.asynctasks.l2`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 1998)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 56. [LOW] Dynamic receiver registered without export flag

- Location: `ml.docilealligator.infinityforreddit.Infinity`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1073)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 57. [MEDIUM] Weak hash: MD5

- Location: `db.g`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 152)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 58. [LOW] Dynamic receiver registered without export flag

- Location: `xh.f`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 61)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 59. [LOW] Weak host validation of a Uri

- Location: `on.f8`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: deeplink-host-validation | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: The host of a Uri is read and then compared with String.startsWith(). Checks like that accept hosts such as evil-example.com or example.com.evil.com, so a deep link can point the app (WebView, login, download) at an attacker's server.  (around line 443)
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Compare the whole host with an allow-list using equals(), or require host == "example.com" || host.endsWith(".example.com") (note the leading dot) after parsing with a real URI parser.

#### 60. [LOW] Data copied to clipboard

- Location: `on.ha$b`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 180)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 61. [LOW] Shared external storage used

- Location: `cd.a`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 234)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 62. [LOW] Sensitive value saved to SharedPreferences (plaintext)

- Location: `np.a`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 1182)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 63. [LOW] FileProvider shares too much (<external-path path=".">)

- Location: `res/8K.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: LOW | Rule: res-fileprovider-paths
- Priority: 12/100 (P4)
- Why flagged: These FileProvider paths cover a whole directory tree (all of shared storage). Any content:// URI the app hands out, or lets a caller choose, can then point at files that were never meant to be shared.  [res/8K.xml]
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: List only the specific sub-folder to share (for example path="shared/"), never root-path or path=".", and keep the provider exported="false" with grantUriPermissions="true".

#### 64. [LOW] Keyboard cache: sensitive input field

- Location: `res/66.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/66.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 65. [HIGH] Untrusted input is loaded into a WebView

- Location: `ml.docilealligator.infinityforreddit.activities.WebViewActivity`
- CWE: CWE-79 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: taint-flow | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getDataString() (through field WebViewActivity.l0:Ljava/lang/String; (written in WebViewActivity.onCreate(Landroid/os/Bundle;)V)) reaches WebView.loadUrl() in method WebViewActivity.onCreate(Landroid/os/Bundle;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  Also matched by: taint-flow (merged).
- Risk scenario: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.
- Fix: Allow-list the scheme and host before loading (https and your own domains only), or map a small id to a fixed URL. Never pass an Intent extra straight to the WebView.

#### 66. [MEDIUM] Untrusted input selects a class or method by name

- Location: `t5.z`
- CWE: CWE-470 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readString() (through field q0.g:Ljava/lang/String; (written in q0.<init>(Landroid/os/Parcel;)V)) reaches Class.forName() in method z.c(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 6 methods. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call.
- Risk scenario: A class or method name coming from outside lets the attacker pick which code runs.
- Fix: Look the name up in an explicit allow-list (a map of known keys to classes) instead of passing it to Class.forName / getMethod.

#### 67. [MEDIUM] Untrusted input is used as a file path

- Location: `ml.docilealligator.infinityforreddit.broadcastreceivers.DownloadedMediaDeleteActionBroadcastReceiver`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 27/100 (P3)
- Note: Lowered one level: the Intent is read in a receiver / service that the manifest does not export, so another app cannot send it directly (only through this app's own PendingIntents or explicit Intents).
- Why flagged: Data from Intent.getData() reaches File.delete() in method DownloadedMediaDeleteActionBroadcastReceiver.onReceive(Landroid/content/Context;Landroid/content/Intent;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  Also matched by: taint-flow (merged).
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 68. [LOW] Untrusted input is used as a file path

- Location: `ua.r`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from ZipEntry.getName() reaches FileOutputStream.<init>() in method r.A(Landroid/content/Context;Ljava/util/zip/ZipInputStream;Ljava/lang/String;)Lua/n0;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value is the name of an archive entry. When the archive comes from outside the app (a download, a file another app shares) a name such as ../../x makes the extraction write outside the target folder (Zip Slip): the target path must be checked with getCanonicalPath() against the extraction folder. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow. 3 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 69. [LOW] Untrusted input is used as a file path

- Location: `wc.c`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Parcel.readString() (through k.get()Ljava/lang/Object;) reaches File.delete() in method c.a(Ljava/io/File;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
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


