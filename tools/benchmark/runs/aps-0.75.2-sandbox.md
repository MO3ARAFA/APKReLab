# APK ReLab report: app.passwordstore

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 246 finding(s) in total; 68 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 10 |
| HIGH | 22 |
| MEDIUM | 18 |
| LOW | 18 |

**OWASP Mobile Top 10 (2024) coverage**

- M4 Insufficient Input/Output Validation: 28
- M9 Insecure Data Storage: 16
- M1 Improper Credential Usage: 9
- M8 Security Misconfiguration: 6
- M10 Insufficient Cryptography: 6
- M5 Insecure Communication: 3

### Findings

#### 1. [LOW] No network security config referenced

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: MEDIUM | Rule: manifest-network-security-config
- Priority: 17/100 (P4)
- Why flagged: No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Add a network_security_config.xml with cleartextTrafficPermitted="false" as the base config (and certificate pinning if the app always talks to the same backend).

#### 2. [MEDIUM] Exported activity without a permission: app.passwordstore.ui.crypto.DecryptActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 3. [MEDIUM] Exported activity without a permission: androidx.compose.ui.tooling.PreviewActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [MEDIUM] Weak hash: MD5 (x2)

- Location: `net.schmizz.sshj.common.SecurityUtils`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 541)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 5. [LOW] Weak hash: SHA-1 (x2)

- Location: `net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 47)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 6. [LOW] Temp file created

- Location: `org.eclipse.jgit.dircache.DirCacheCheckout`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 365)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 7. [LOW] Temp file created

- Location: `org.eclipse.jgit.util.TemporaryBuffer$LocalFile`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 138)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 8. [CRITICAL] TLS certificate validation disabled

- Location: `org.eclipse.jgit.util.HttpSupport$DummyX509TrustManager`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-trustmanager
- Priority: 90/100 (P1)
- Why flagged: This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.  (around line 16)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.

#### 9. [MEDIUM] Shell command execution

- Location: `org.eclipse.jgit.util.FS$Holder`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 312)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 10. [MEDIUM] Shell command execution

- Location: `org.eclipse.jgit.util.FS_POSIX`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 706)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 11. [MEDIUM] Shell command execution

- Location: `org.eclipse.jgit.util.FS`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 386)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 12. [HIGH] Hostname verification disabled

- Location: `org.eclipse.jgit.util.HttpSupport$DummyHostnameVerifier`
- CWE: CWE-297 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-hostname-verifier
- Priority: 70/100 (P1)
- Why flagged: A HostnameVerifier that accepts every hostname (ALLOW_ALL_HOSTNAME_VERIFIER, or a verify() that always returns a hardcoded true) is used - TLS stops confirming the server is who it claims to be.  (around line 10)
- Risk scenario: A valid certificate issued for ANY site is accepted for your server's name, so an attacker with a cheap certificate can sit between the app and the backend.
- Fix: Use the default HostnameVerifier, or a strict one that actually checks the certificate against the hostname.

#### 13. [MEDIUM] Shell command execution

- Location: `org.eclipse.jgit.util.FS_Win32_Cygwin`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 221)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 14. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `org.eclipse.jgit.util.NB`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 5539)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 15. [MEDIUM] Shell command execution

- Location: `org.eclipse.jgit.util.FS_Win32`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 302)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 16. [LOW] Temp file created

- Location: `org.eclipse.jgit.util.FS_Win32`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 341)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 17. [MEDIUM] Weak hash: MD5 (x2)

- Location: `org.eclipse.jgit.transport.TransportAmazonS3$DatabaseS3`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 874)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 18. [MEDIUM] PBKDF2 with a low iteration count (5000)

- Location: `org.eclipse.jgit.transport.WalkEncryption$JetS3tV2`
- CWE: CWE-916 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-pbkdf2-iterations
- Priority: 45/100 (P2)
- Why flagged: PBEKeySpec is created with only 5000 iterations. A key (or stored password hash) derived from a password with so few iterations can be brute-forced very quickly.  (around line 88)
- Risk scenario: A low iteration count lets an attacker who gets the hash (or the encrypted blob) try billions of guesses per second on a GPU.
- Fix: Use at least 100,000 iterations of PBKDF2WithHmacSHA256 (OWASP currently recommends 600,000), or a memory-hard KDF such as Argon2 / scrypt.

#### 19. [MEDIUM] Weak hash: MD5 (x2)

- Location: `org.eclipse.jgit.transport.HttpAuthMethod$Digest`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 278)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 20. [LOW] Temp file created

- Location: `org.eclipse.jgit.transport.WalkFetchConnection$RemotePack`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 209)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 21. [LOW] Weak hash: SHA-1

- Location: `org.eclipse.jgit.lib.Constants`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash
- Priority: 20/100 (P4)
- Why flagged: SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.  (around line 570)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256 or better.

#### 22. [LOW] Temp file created

- Location: `org.eclipse.jgit.internal.storage.file.FileRepository`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 484)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 23. [LOW] Temp file created

- Location: `org.eclipse.jgit.internal.storage.file.GC`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 2740)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 24. [LOW] Temp file created

- Location: `org.eclipse.jgit.internal.storage.file.ObjectDirectoryInserter`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 170)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 25. [LOW] Temp file created

- Location: `org.eclipse.jgit.internal.storage.file.ObjectDirectoryPackParser`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 1599)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 26. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `app.passwordstore.util.services.ClipboardService`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 451)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 27. [LOW] Data copied to clipboard

- Location: `app.passwordstore.util.services.ClipboardService$clearClipboard$1$2`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 84)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 28. [LOW] Data copied to clipboard

- Location: `app.passwordstore.util.services.ClipboardService$clearClipboard$1`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 146)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 29. [LOW] Data copied to clipboard

- Location: `app.passwordstore.ui.crypto.BasePGPActivity`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 156)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 30. [MEDIUM] QR/barcode input reaches a sensitive sink

- Location: `app.passwordstore.ui.crypto.PasswordDialog$$ExternalSyntheticLambda1`
- CWE: CWE-20 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 27/100 (P3)
- Why flagged: This class scans QR/barcodes and also calls a sensitive API (Landroid/content/Context;->startActivity). A malicious QR code is attacker-controlled input; if it is used unvalidated, it can open arbitrary URLs/intents or inject SQL/commands.  (around line 116)
- Risk scenario: Data from an Intent, deep link, QR code or server is trusted without checks, so it can steer the app into unintended screens, URLs or file operations.
- Fix: Treat the scanned text as untrusted: validate scheme/host against an allow-list, never pass it straight to WebView/Intent/SQL.

#### 31. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `app.passwordstore.ui.crypto.DecryptActivity$$ExternalSyntheticLambda1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 320)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 32. [HIGH] Credential stored in plain SharedPreferences

- Location: `app.passwordstore.ui.crypto.DecryptActivity$$ExternalSyntheticLambda1`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: fintech-unencrypted-storage | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A value under the key "proxy_password" is written with SharedPreferences.Editor.putString(), and this class never touches EncryptedSharedPreferences or the Android Keystore. Plain SharedPreferences XML is readable on a rooted device, from an adb backup, or from any app sharing the same Linux UID (shared UID apps) - for a PIN, API key or session token that's a direct credential-theft path.  (around line 427)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Move this key to androidx.security.crypto.EncryptedSharedPreferences, or better, keep it only in the Android Keystore (StrongBox/TEE-backed where available) and never serialize it to disk in cleartext.

#### 33. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `app.passwordstore.ui.git.config.GitConfigActivity$$ExternalSyntheticLambda0`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 340)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 34. [HIGH] High-entropy embedded string near a credential-like name

- Location: `app.passwordstore.ui.passwords.PasswordStore$$ExternalSyntheticLambda3`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: A 26-char string with high character randomness (entropy 3.8 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "getA…".  (around line 418)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 35. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `app.passwordstore.ui.dialogs.DicewarePasswordGeneratorDialogFragment`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 151)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 36. [LOW] Dynamic receiver registered without export flag

- Location: `app.passwordstore.Application`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1312)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 37. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `logcat.LogcatKt`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 2593)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 38. [CRITICAL] Hardcoded credential: Private key block

- Location: `com.jcraft.jsch.KeyPairPKCS8`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-known-formats
- Priority: 90/100 (P1)
- Why flagged: A string matching the Private key block format is embedded in the code ("-----BEG…"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.  (around line 76)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.

#### 39. [CRITICAL] Hardcoded credential: Private key block

- Location: `com.jcraft.jsch.KeyPairRSA`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-known-formats
- Priority: 90/100 (P1)
- Why flagged: A string matching the Private key block format is embedded in the code ("-----BEG…"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.  (around line 32)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.

#### 40. [CRITICAL] Private key embedded

- Location: `com.jcraft.jsch.KeyPairRSA`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: androgoat-checks
- Priority: 90/100 (P1)
- Why flagged: A string literal matches this pattern (-----B... (31 chars)). Anything inside the APK can be extracted by anyone who downloads it.  (around line 32)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Remove the secret from the APK, rotate it (it must be treated as leaked), and keep it on a server you control; the app should call your backend instead.

#### 41. [CRITICAL] Hardcoded credential: Private key block

- Location: `com.jcraft.jsch.KeyPairECDSA`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-known-formats
- Priority: 90/100 (P1)
- Why flagged: A string matching the Private key block format is embedded in the code ("-----BEG…"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.  (around line 60)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.

#### 42. [CRITICAL] Private key embedded

- Location: `com.jcraft.jsch.KeyPairECDSA`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: androgoat-checks
- Priority: 90/100 (P1)
- Why flagged: A string literal matches this pattern (-----B... (30 chars)). Anything inside the APK can be extracted by anyone who downloads it.  (around line 60)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Remove the secret from the APK, rotate it (it must be treated as leaked), and keep it on a server you control; the app should call your backend instead.

#### 43. [CRITICAL] Hardcoded credential: Private key block

- Location: `com.jcraft.jsch.KeyPairDSA`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-known-formats
- Priority: 90/100 (P1)
- Why flagged: A string matching the Private key block format is embedded in the code ("-----BEG…"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.  (around line 26)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.

#### 44. [CRITICAL] Hardcoded credential: Private key block

- Location: `com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: secrets-known-formats
- Priority: 90/100 (P1)
- Why flagged: A string matching the Private key block format is embedded in the code ("-----BEG…"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.  (around line 1465)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.

#### 45. [CRITICAL] Private key embedded

- Location: `com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: HIGH | Rule: androgoat-checks
- Priority: 90/100 (P1)
- Why flagged: A string literal matches this pattern (-----B... (35 chars)). Anything inside the APK can be extracted by anyone who downloads it.  (around line 1465)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Remove the secret from the APK, rotate it (it must be treated as leaked), and keep it on a server you control; the app should call your backend instead.

#### 46. [LOW] Keyboard cache: sensitive input field (x3)

- Location: `res/66.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/66.xml]  The same applies to 2 more layout(s): res/J7.xml, res/fu.xml.
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 47. [MEDIUM] Password screen not protected against tapjacking (x6)

- Location: `res/Hs.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0a01f5") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 26: devices below Android 12 do not block touches through overlays.  [res/Hs.xml]  The same applies to 5 more layout(s): res/KD.xml, res/Rm.xml, res/b2.xml, res/l6.xml, res/pJ.xml.
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 48. [CRITICAL] Untrusted input reaches a shell command

- Location: `org.eclipse.jgit.util.FS`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 77/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Config.getRawString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;) reaches ProcessBuilder.<init>() in method FS.readPipe(Ljava/io/File;[Ljava/lang/String;Ljava/lang/String;Ljava/util/HashMap;)Ljava/lang/String;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Do not build shell commands from input. Call an API instead, or pass fixed arguments and validate each one against an allow-list.

#### 49. [HIGH] Untrusted input is used as a file path

- Location: `app.passwordstore.ui.crypto.BasePGPActivity`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through UnsafeLazyImpl.getValue()Ljava/lang/Object;) reaches FileInputStream.<init>() in method BasePGPActivity.getPGPIdentifiers(Ljava/lang/String;)Ljava/util/ArrayList;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 50. [HIGH] Untrusted input is used as a file path

- Location: `com.jcraft.jsch.IO`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through field IO.out_ext:Ljava/lang/Object; (written in IO.add(Lorg/eclipse/jgit/revwalk/RevObject;)V)) reaches FileOutputStream.<init>() in method IO.log(Ljava/lang/String;[B)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink. 2 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 51. [HIGH] Untrusted input is used as a file path

- Location: `com.jcraft.jsch.Util`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through FS.userHome()Ljava/io/File;) reaches FileInputStream.<init>() in method Util.fromFile(Ljava/lang/String;)[B. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 4 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 52. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.attributes.AttributesHandler`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through FS.userHome()Ljava/io/File;) reaches FileInputStream.<init>() in method AttributesHandler.<init>(Lorg/eclipse/jgit/treewalk/TreeWalk;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 53. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.dircache.DirCacheCheckout`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches FileOutputStream.<init>() in method DirCacheCheckout.checkoutEntry(Lorg/eclipse/jgit/lib/Repository;Lorg/eclipse/jgit/dircache/DirCacheEntry;Lorg/eclipse/jgit/internal/storage/file/WindowCursor;ZLorg/eclipse/jgit/dircache/DirCacheCheckout$CheckoutMetadata;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 54. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.dircache.DirCacheCheckout`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches File.delete() in method DirCacheCheckout.cleanUpConflicts()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. 2 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 55. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.dircache.DirCacheCheckout`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches File.delete() in method DirCacheCheckout.doCheckout()Z. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 56. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.dircache.DirCacheCheckout`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches File.delete() in method DirCacheCheckout.removeEmptyParents(Ljava/io/File;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 57. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.internal.storage.file.GC`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through ArrayIterator.next()Ljava/lang/Object;) reaches File.delete() in method GC.gc()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 58. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.internal.storage.file.GC`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through ArrayIterator.next()Ljava/lang/Object;) reaches File.delete() in method GC.writePack(Ljava/util/HashSet;Ljava/util/Set;Ljava/util/HashSet;Ljava/util/LinkedList;)Lorg/eclipse/jgit/internal/storage/file/PackFile;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. 3 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 59. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.internal.storage.file.RefDirectory`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through ArrayIterator.next()Ljava/lang/Object;) reaches File.delete() in method RefDirectory.delete(Ljava/io/File;ILorg/eclipse/jgit/internal/storage/file/LockFile;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. 2 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 60. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.internal.storage.file.RefDirectory`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through ArrayIterator.next()Ljava/lang/Object;) reaches FileInputStream.<init>() in method RefDirectory.scanRef(Lorg/eclipse/jgit/internal/storage/file/RefDirectory$LooseRef;Ljava/lang/String;)Lorg/eclipse/jgit/internal/storage/file/RefDirectory$LooseRef;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 61. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.merge.ResolveMerger`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches FileOutputStream.<init>() in method ResolveMerger.mergeTrees(Lorg/eclipse/jgit/treewalk/AbstractTreeIterator;Lorg/eclipse/jgit/revwalk/RevTree;Lorg/eclipse/jgit/revwalk/RevTree;Z)Z. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. 3 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 62. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.transport.DefaultSshSessionFactory`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through FS.userHome()Ljava/io/File;) reaches FileInputStream.<init>() in method DefaultSshSessionFactory.knownHosts(Lcom/jcraft/jsch/JSch;Lorg/eclipse/jgit/util/FS;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 63. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.transport.TransportAmazonS3`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through FS.userHome()Ljava/io/File;) reaches FileInputStream.<init>() in method TransportAmazonS3.loadPropertiesFile(Ljava/io/File;)Ljava/util/Properties;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 64. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.treewalk.WorkingTreeIterator$RootIgnoreNode`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through FS.userHome()Ljava/io/File;) reaches FileInputStream.<init>() in method WorkingTreeIterator$RootIgnoreNode.load()Lorg/eclipse/jgit/ignore/IgnoreNode;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 65. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.util.IO`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow
- Priority: 60/100 (P2)
- Why flagged: Data from Intent.getStringExtra() (through field RevWalk$1.val$objItr:Ljava/lang/Object; (written in TransportHttp.httpOpen(Ljava/lang/String;Ljava/net/URL;)Lorg/eclipse/jgit/revwalk/RevWalk$1;)) reaches FileInputStream.<init>() in method IO.readFully(Ljava/io/File;I)[B. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 66. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.util.NB`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches File.delete() in method NB.delete(Ljava/io/File;I)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. 2 flows of this kind end in this method.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 67. [HIGH] Untrusted input is used as a file path

- Location: `org.eclipse.jgit.util.NB`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow
- Priority: 70/100 (P1)
- Why flagged: Data from Intent.getStringExtra() (through Repository.getWorkTree()Ljava/io/File;) reaches File.delete() in method NB.rename(Ljava/io/File;Ljava/io/File;[Ljava/nio/file/CopyOption;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 68. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `app.passwordstore.util.git.sshj.SshKey`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: Data from Intent.getData() (through MiscSettings$storeExportAction$1.parseResult(Landroid/content/Intent;I)Ljava/lang/Object;) reaches ContentResolver.openInputStream() in method SshKey.import(Landroid/net/Uri;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.
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

#### CWE-20 - Improper Input Validation

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: Data from an Intent, deep link, QR code or server is trusted without checks, so it can steer the app into unintended screens, URLs or file operations.

Vulnerable:

```kotlin
val url = intent.getStringExtra("url"); webView.loadUrl(url!!)
```

Secure:

```kotlin
val url = intent.getStringExtra("url")
val u = url?.let { Uri.parse(it) }
if (u?.scheme == "https" && u.host in ALLOWED_HOSTS) webView.loadUrl(url) else finish()
```

References: [CWE-20 (MITRE)](https://cwe.mitre.org/data/definitions/20.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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


