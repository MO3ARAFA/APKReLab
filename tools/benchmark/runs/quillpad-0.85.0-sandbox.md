# APK ReLab report: io.github.quillpad

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 113 finding(s) in total; 29 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 11 |
| LOW | 15 |

**OWASP Mobile Top 10 (2024) coverage**

- M4 Insufficient Input/Output Validation: 10
- M8 Security Misconfiguration: 9
- M9 Insecure Data Storage: 5
- M5 Insecure Communication: 3
- M10 Insufficient Cryptography: 1
- Not mapped: 1

### Findings

#### 1. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 2. [LOW] Exported activity without a permission: org.qosp.notes.ui.MainActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: SEND, SEND_MULTIPLE).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 3. [MEDIUM] Exported activity without a permission: androidx.test.core.app.InstrumentationActivityInvoker$BootstrapActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [MEDIUM] Exported activity without a permission: androidx.test.core.app.InstrumentationActivityInvoker$EmptyActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [MEDIUM] Exported activity without a permission: androidx.test.core.app.InstrumentationActivityInvoker$EmptyFloatingActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [LOW] Dynamic receiver registered without export flag

- Location: `jm`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 333)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 7. [LOW] Sensitive value written to log

- Location: `zh4`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A log call is built from a credential-like label ("Server rejected the credential") plus an appended variable. Logcat can be read from a computer over ADB, and by other apps on some devices.  (around line 687)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Never log passwords, tokens, or personal data; strip such Log calls from release builds.

#### 8. [CRITICAL] TLS certificate validation disabled

- Location: `gq2`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-trustmanager | Scope: OBF
- Priority: 77/100 (P1)
- Note: Restored one level: an obfuscated class, but a method of this app instantiates it and installs it (SSLContext.init, a hostname-verifier / socket-factory setter), so it is in use.
- Why flagged: This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.  (around line 27)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.

#### 9. [HIGH] Hostname verification disabled

- Location: `fq2`
- CWE: CWE-297 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-hostname-verifier | Scope: OBF
- Priority: 60/100 (P2)
- Note: Restored one level: an obfuscated class, but a method of this app instantiates it and installs it (SSLContext.init, a hostname-verifier / socket-factory setter), so it is in use.
- Why flagged: A HostnameVerifier that accepts every hostname (ALLOW_ALL_HOSTNAME_VERIFIER, or a verify() that always returns a hardcoded true) is used - TLS stops confirming the server is who it claims to be.  (around line 10)
- Risk scenario: A valid certificate issued for ANY site is accepted for your server's name, so an attacker with a cheap certificate can sit between the app and the backend.
- Fix: Use the default HostnameVerifier, or a strict one that actually checks the certificate against the hostname.

#### 10. [LOW] Dynamic receiver registered without export flag

- Location: `nr`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 96)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 11. [LOW] Temp file created

- Location: `uv0`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 406)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 12. [MEDIUM] Possible Zip Slip (unsanitized zip entry path)

- Location: `ep`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: zip-slip | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: This method reads ZipEntry.getName() while extracting an archive and builds a File/output path from it, with no getCanonicalPath()/normalize() check anywhere in the method. A crafted entry name containing "../" segments can write outside the intended extraction directory (e.g. overwrite app files or drop an executable in a sensitive location).  (around line 1282)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Resolve the destination file, call getCanonicalPath() on it, and verify it still starts with the intended output directory before writing; reject/skip any entry that fails the check.

#### 13. [LOW] Shared external storage used

- Location: `xp0`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 25)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 14. [LOW] Possible SQL built by string concatenation

- Location: `fi3`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 1130)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 15. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `xb2`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 6231)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 16. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `wf0`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 255)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 17. [LOW] Temp file created

- Location: `yu3`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 123)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 18. [LOW] Dynamic receiver registered without export flag

- Location: `l3`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1237)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 19. [LOW] Dynamic receiver registered without export flag

- Location: `vp2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 81)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 20. [HIGH] Insecure TLS protocol requested: "SSL"

- Location: `eq2`
- CWE: CWE-327 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: tls-protocol-version | Scope: OBF
- Priority: 60/100 (P2)
- Why flagged: SSLContext.getInstance("SSL") is used. SSL/SSLv2/SSLv3 are broken (POODLE and other attacks let a network attacker decrypt or tamper with the connection).  (around line 134)
- Risk scenario: A network attacker can push the connection down to SSLv3 / TLSv1.0 / TLSv1.1, which have known attacks, and read or change the traffic.
- Fix: Use SSLContext.getInstance("TLSv1.3") (fall back to "TLSv1.2" only if you must support very old peers), or omit explicit protocol selection and rely on the platform default on modern API levels.

#### 21. [LOW] Native libraries not analysed (2 .so)

- Location: `lib/`
- Confidence: HIGH | Rule: native-coverage
- Priority: 20/100 (P4)
- Why flagged: This APK contains native libraries (libandroidx.graphics.path.so, libdatastore_shared_counter.so). APKReLab analyses Java / Kotlin (dex) code only: data handed to native methods is not followed.
- Fix: Review the native code separately (e.g. strings / imports of the .so, a disassembler) and check what the app passes to its JNI methods.

#### 22. [MEDIUM] Network Security Config: trusts user-installed CAs

- Location: `res/8G.xml`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-user-ca
- Priority: 45/100 (P2)
- Why flagged: The config trusts certificates the user installed in: base-config (every domain). A proxy such as Burp/mitmproxy (or malware that installs a CA) can then decrypt this app's HTTPS traffic (MASVS-NETWORK).  [res/8G.xml]
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Trust only the system CAs (src="system") in release builds; keep user CAs inside <debug-overrides> only.

#### 23. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/0M.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0a012c") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 24: devices below Android 12 do not block touches through overlays.  [res/0M.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 24. [LOW] Untrusted input is used as a file path

- Location: `ep`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through p40.d1(Ljava/util/List;)Ljava/lang/Object;) reaches FileOutputStream.<init>() in method ep.q(Ljava/lang/Object;)Ljava/lang/Object;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 25. [LOW] Untrusted input reaches an SQL statement

- Location: `me1`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through x51.next()Ljava/lang/Object;) reaches SQLiteDatabase.compileStatement() in method me1.n(Ljava/lang/String;)Lte1;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 26. [LOW] Untrusted input is used as a file path

- Location: `ra`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through jj.get(I)Ljava/lang/Object;) reaches File.delete() in method ra.run()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 27. [MEDIUM] Untrusted input is used as a file path

- Location: `t51`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Intent.getSerializableExtra() (through field se0.b:Ljava/io/File; (written in se0.<init>(Lorg/acra/dialog/CrashReportDialog;Landroid/content/Intent;)V)) reaches FileInputStream.<init>() in method t51.O0(Ljava/io/File;)Ljava/lang/String;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink. 2 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 28. [MEDIUM] Untrusted input is used as a file path

- Location: `t51`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 23/100 (P4)
- Note: Lowered one level: the Intent belongs to org.acra.dialog.CrashReportDialog, an activity that is not exported and runs in its own process (a crash / report dialog started by the app itself).
- Why flagged: Data from Intent.getSerializableExtra() (through field se0.b:Ljava/io/File; (written in se0.<init>(Lorg/acra/dialog/CrashReportDialog;Landroid/content/Intent;)V)) reaches FileOutputStream.<init>() in method t51.Q0(Ljava/io/File;Ljava/lang/String;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. 2 flows of this kind end in this method. The same input, read in jf3.a(Lg21;)V, also reaches this kind of API in: wq4.A(Ljava/io/File;)V (one root cause, one card).
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 29. [LOW] Untrusted input is used as a file path

- Location: `xb2`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through by0.b()[Ljava/io/File;) reaches File.delete() in method xb2.l(Ljava/io/File;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.
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

#### CWE-297 - Improper Validation of Certificate with Host Mismatch

OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK

Risk: A valid certificate issued for ANY site is accepted for your server's name, so an attacker with a cheap certificate can sit between the app and the backend.

Vulnerable:

```kotlin
HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
```

Secure:

```kotlin
// keep the default HostnameVerifier; if you must check, compare the real host
HostnameVerifier { host, session -> host == "api.example.com" && HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) }
```

References: [CWE-297 (MITRE)](https://cwe.mitre.org/data/definitions/297.html) | [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


