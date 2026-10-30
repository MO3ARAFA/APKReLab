# APK ReLab report: io.horizontalsystems.bankwallet

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 462 finding(s) in total; 49 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| HIGH | 20 |
| MEDIUM | 9 |
| LOW | 20 |

**OWASP Mobile Top 10 (2024) coverage**

- M1 Improper Credential Usage: 21
- M8 Security Misconfiguration: 7
- M9 Insecure Data Storage: 7
- M10 Insufficient Cryptography: 6
- M4 Insufficient Input/Output Validation: 4
- M5 Insecure Communication: 3
- M3 Insecure Authentication/Authorization: 1

### Findings

#### 1. [LOW] Exported activity without a permission: io.horizontalsystems.bankwallet.modules.main.MainActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 2. [MEDIUM] Exported activity without a permission: androidx.compose.ui.tooling.PreviewActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 3. [LOW] Temp file created

- Location: `px9`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 130)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 4. [LOW] Weak hash: SHA-1

- Location: `cash.z.ecc.android.sdk.internal.ext.FileExtKt$getSha1Hash$2`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 224)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 5. [LOW] Temp file created

- Location: `jp`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 574)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 6. [LOW] Dynamic receiver registered without export flag

- Location: `kl0`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 150)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 7. [LOW] Weak hash: SHA-1

- Location: `it5`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 358)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 8. [HIGH] High-entropy embedded string near a credential-like name

- Location: `com.solana.programs.AssociatedTokenProgram`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings
- Priority: 60/100 (P2)
- Why flagged: A 44-char string with high character randomness (entropy 4.8 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "ATok…".  (around line 57)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 9. [HIGH] High-entropy embedded string near a credential-like name

- Location: `com.solana.core.PublicKey$Companion`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings
- Priority: 60/100 (P2)
- Why flagged: A 44-char string with high character randomness (entropy 4.8 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "ATok…".  (around line 110)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 10. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `ce2`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 985)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 11. [LOW] Dynamic receiver registered without export flag

- Location: `e2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 636)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 12. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `kkb`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 16)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 13. [LOW] Weak hash: SHA-1

- Location: `net.freehaven.tor.control.PasswordDigest`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 121)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 14. [HIGH] High-entropy embedded string near a credential-like name (x2)

- Location: `org.tron.protos.Protocol$MarketOrder`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings
- Priority: 60/100 (P2)
- Why flagged: A 24-char string with high character randomness (entropy 3.9 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "sell…".  (around line 728)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 15. [HIGH] Hardcoded encryption key

- Location: `org.stellar.sdk.SLIP10`
- CWE: CWE-321 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-hardcoded-key
- Priority: 70/100 (P1)
- Why flagged: A SecretKeySpec is built from a string literal ("ed2…", 12 chars) that sits in the APK - anyone who decompiles it can decrypt/forge whatever this key protects.  (around line 42)
- Risk scenario: The key is the same for every install and is readable from the APK, so all data protected with it can be decrypted offline by anyone.
- Fix: Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.

#### 16. [HIGH] High-entropy embedded string near a credential-like name (x3)

- Location: `org.sol4k.Constants`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings
- Priority: 60/100 (P2)
- Why flagged: A 43-char string with high character randomness (entropy 5.0 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "Toke…".  (around line 90)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 17. [LOW] Weak hash: SHA-1

- Location: `jw2`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 317)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 18. [MEDIUM] High-entropy embedded string near a credential-like name

- Location: `sdc`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 24-char string with high character randomness (entropy 3.8 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "Zcas…".  (around line 40)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 19. [LOW] Dynamic receiver registered without export flag

- Location: `d9`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 212)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 20. [MEDIUM] High-entropy embedded string near a credential-like name

- Location: `xa`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A 36-char string with high character randomness (entropy 4.3 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "onEn…".  (around line 6069)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 21. [LOW] Data copied to clipboard

- Location: `ou5`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 483)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 22. [LOW] Dynamic receiver registered without export flag

- Location: `h1`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 2140)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 23. [MEDIUM] Untrusted input selects a class or method by name

- Location: `h1`
- CWE: CWE-470 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: OBF
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: Data from Intent.getExtras() reaches Class.forName() in method invokeSuspend(): the caller picks which class is loaded and initialised. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The method also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.  (around line 3807)
- Risk scenario: A class or method name coming from outside lets the attacker pick which code runs.
- Fix: Look the name up in an explicit allow-list (a map of known keys to classes) instead of passing it to Class.forName / getMethod.

#### 24. [LOW] Data copied to clipboard

- Location: `npa`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 148)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 25. [LOW] Deep link parameter stored as configuration

- Location: `kz5`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: deeplink-config-poisoning | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A query parameter of an incoming Uri is saved to SharedPreferences. A crafted link can overwrite a setting such as the login URL, so later requests (with the user's credentials) go to the attacker.  (around line 680)
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Never let a link change configuration. Ignore the parameter, or accept it only after matching it against a fixed allow-list of values.

#### 26. [LOW] Dynamic receiver registered without export flag

- Location: `vn`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 206)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 27. [LOW] Data copied to clipboard

- Location: `zn9`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 1868)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 28. [LOW] Shell command execution

- Location: `xn8`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 115)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 29. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.solanakit.database.transaction.TransactionDatabase_Impl$1`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 35-char string with high character randomness (entropy 3.9 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "inde…".  (around line 571)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 30. [MEDIUM] Sensitive value written to log

- Location: `io.horizontalsystems.solanakit.transactions.TransactionSyncer`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: A log call is built from a credential-like label ("Failed to fetch signatures for") plus an appended variable. Logcat can be read from a computer over ADB, and by other apps on some devices.  (around line 1791)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Never log passwords, tokens, or personal data; strip such Log calls from release builds.

#### 31. [HIGH] Hardcoded sensitive field: associatedTokenAccount

- Location: `io.horizontalsystems.solanakit.transactions.KnownPrograms`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("ATo…", 44 chars), so it is baked into the APK and readable after decompiling.  (around line 58)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 32. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.solanakit.transactions.KnownPrograms`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 44-char string with high character randomness (entropy 4.8 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "ATok…".  (around line 151)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 33. [HIGH] Hardcoded sensitive field: ASSOCIATED_TOKEN_PROGRAM

- Location: `io.horizontalsystems.walletkit.modules.walletconnect.solana.WCSolanaTxSummary`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("ATo…", 44 chars), so it is baked into the APK and readable after decompiling.  (around line 80)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 34. [HIGH] Hardcoded sensitive field: TOKEN_2022_PROGRAM

- Location: `io.horizontalsystems.walletkit.modules.walletconnect.solana.WCSolanaTxSummary`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Tok…", 43 chars), so it is baked into the APK and readable after decompiling.  (around line 126)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 35. [HIGH] Hardcoded sensitive field: TOKEN_PROGRAM

- Location: `io.horizontalsystems.walletkit.modules.walletconnect.solana.WCSolanaTxSummary`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-sensitive-fields | Scope: APP
- Priority: 70/100 (P1)
- Why flagged: A field named like a credential is initialised with a fixed secret-looking string ("Tok…", 43 chars), so it is baked into the APK and readable after decompiling.  (around line 128)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.

#### 36. [HIGH] High-entropy embedded string near a credential-like name (x3)

- Location: `io.horizontalsystems.walletkit.modules.walletconnect.solana.WCSolanaTxSummary`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 44-char string with high character randomness (entropy 4.9 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "3i5J…".  (around line 201)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 37. [HIGH] High-entropy embedded string near a credential-like name (x2)

- Location: `io.horizontalsystems.walletkit.core.storage.NftDao_Impl`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 27-char string with high character randomness (entropy 4.0 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "aver…".  (around line 971)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 38. [HIGH] High-entropy embedded string near a credential-like name (x3)

- Location: `io.horizontalsystems.walletkit.core.storage.AppDatabase_Impl$createOpenDelegate$_openDelegate$1`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 27-char string with high character randomness (entropy 4.0 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "aver…".  (around line 1704)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 39. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.uniswapkit.v3.pool.GetPoolMethod`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 31-char string with high character randomness (entropy 4.0 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "getP…".  (around line 67)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 40. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.nftkit.contracts.Eip1155BalanceOfMethod`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 26-char string with high character randomness (entropy 4.2 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "bala…".  (around line 88)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 41. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.nftkit.contracts.Eip721SafeTransferFromMethod`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 47-char string with high character randomness (entropy 4.1 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "safe…".  (around line 110)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 42. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.nftkit.contracts.Eip1155SafeTransferFromMethod`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 55-char string with high character randomness (entropy 4.2 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "safe…".  (around line 118)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 43. [MEDIUM] Predictable random value used for security

- Location: `io.horizontalsystems.bitcoincore.network.messages.VersionMessage`
- CWE: CWE-338 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: weak-random | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: The output of Math.random() is stored in the field nonce. java.util.Random is a linear congruential generator: after a few outputs (or from the seed) every next value can be computed, so a token / PIN / key built from it can be guessed. Traced in SSA inside <init>(); the receiver is a new java.util.Random (a SecureRandom held in a Random variable is not reported).  (around line 167)
- Risk scenario: java.util.Random is predictable from a few outputs; session ids, OTPs, reset tokens or keys built from it can be guessed.
- Fix: Use java.security.SecureRandom (and never a fixed seed) for tokens, PINs, salts, IVs and keys.

#### 44. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.ethereumkit.core.Eip1155Provider$BalanceOfMethod`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 26-char string with high character randomness (entropy 4.2 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "bala…".  (around line 73)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 45. [LOW] Data copied to clipboard

- Location: `io.horizontalsystems.monerokit.util.Helper`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 174)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 46. [HIGH] High-entropy embedded string near a credential-like name

- Location: `io.horizontalsystems.marketkit.storage.MarketDatabase_Impl$1`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 46-char string with high character randomness (entropy 4.1 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "inde…".  (around line 739)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 47. [LOW] Hardcoded cleartext URL

- Location: `tj4`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://play.google.com/store/apps/details?id=io.horizontalsy). Traffic to it can be read or modified on the network.  (around line 127)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 48. [LOW] Hardcoded cleartext URL

- Location: `r22`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: cleartext-url | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: A plain http:// URL is hardcoded (http://play.google.com/store/apps/details?id=io.horizontalsy). Traffic to it can be read or modified on the network.  (around line 227)
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Switch to https:// (and make sure the server supports it).

#### 49. [MEDIUM] Network Security Config: cleartext permitted for specific domains

- Location: `res/8G.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-cleartext-domains
- Priority: 45/100 (P2)
- Why flagged: Plain HTTP is allowed for: onion (+subdomains), node.xmr.rocks, opennode.xmr-tw.org, node.sethforprivacy.com, nodex.monerujo.io and 2 more. Traffic to these hosts can be read and modified on the network.  [res/8G.xml]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Move the backend to HTTPS and remove cleartextTrafficPermitted="true". If a legacy host cannot be fixed yet, keep the exception scoped to that exact domain and track its removal.

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

#### CWE-321 - Use of Hard-coded Cryptographic Key

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: The key is the same for every install and is readable from the APK, so all data protected with it can be decrypted offline by anyone.

Vulnerable:

```kotlin
SecretKeySpec("MySecretKey12345".toByteArray(), "AES")
```

Secure:

```kotlin
// generate the key on the device inside the Android Keystore (non-exportable)
val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
kg.init(KeyGenParameterSpec.Builder("data_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
val key = kg.generateKey()
```

References: [CWE-321 (MITRE)](https://cwe.mitre.org/data/definitions/321.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


