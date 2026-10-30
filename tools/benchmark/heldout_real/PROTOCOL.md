# Real-app held-out set (frozen 2026-10-13, BEFORE the first scan, tool version 0.75.2)

Apps (never scanned by APKReLab before; not in the 15-app study, not in the tuning set):
| app | package | source | sha256 |
|---|---|---|---|
| andOTP 0.9.0.1 (2FA) | org.shadowice.flocke.andotp | github.com/andOTP/andOTP releases | 35459f1f4924ab065b90959049e0d080e951fb03ba0742d1d6e525e62436a76b |
| Android Password Store 2.0.0-SNAPSHOT freeRelease (password manager, OpenPGP, autofill) | (from the manifest) | github.com/android-password-store/Android-Password-Store releases "latest" | c4c113a7b42158b4dcd7d32b500d63e86426f1b5a8902317b910a0d7fa9ddecc |
| Unstoppable Wallet 0.52.0 github build (crypto wallet) | (from the manifest) | github.com/horizontalsystems/unstoppable-wallet-android releases | bb1ef99867f55bb2143fe4b1ae8a2748c4caf5c91d7b266d21f208612adade84 |

OpenKeychain was the first choice but publishes no APK on GitHub (F-Droid only, not reachable from the sandbox); APS replaces it (also OpenPGP + IPC).
No public security advisory naming a specific vulnerable version was found for these apps, so there is NO recall list.

Scoring (precision only):
1. Run the scan (sandbox: tools/sandbox/SandboxScan.kt; device: Smart scan) and keep the report unchanged in runs/.
2. Read EVERY HIGH / CRITICAL finding in the app's own code (scope APP / OBF) in the smali and classify it: TP (exploitable or a real weakness), BY-DESIGN (true but intended and documented), FP (wrong).
3. Precision = TP / (TP + FP). BY-DESIGN is reported separately. MEDIUM findings: a sample, said as a sample.
4. A fix made because of one of these apps moves THAT app to the tuning set.

## FIRST RUN (frozen), 0.75.2 sandbox (SandboxScan; Unstoppable without SSA because the whole-app SSA does not fit the sandbox memory; the device groups it)
Reports: `runs/andotp-0.75.2-sandbox.md`, `runs/aps-0.75.2-sandbox.md`, `runs/unstoppable-0.75.2-sandbox.md`.

| app | HIGH/CRIT cards | app scope read: TP / FP | unrecognised library cards |
|---|---|---|---|
| andOTP | 2 | 0 / 2: `RSA/ECB/PKCS1Padding` called "ECB" (ECB means nothing for RSA; key wrapping with the Keystore, AOSP SecretKeyWrapper) | 0 |
| APS (app.passwordstore) | 33 | 1 / 2. TP (low impact): `DecryptActivity` is exported with no permission and `BasePGPActivity` takes FILE_PATH / REPO_PATH from the caller's Intent (`File(repoDir, subDir)` with no canonical check). FP: "Credential stored in plain SharedPreferences" proxy_password = the prefs are `EncryptedSharedPreferences("http_proxy")` injected by Hilt (the rule only looks inside the class); FP: high-entropy "getApplicationContext(...)" = a Kotlin null-check message | 30: jgit / jsch / sshj have scope OTHER, not LIB: 7 "private key block" = PEM header literals of key parsers (FP), jgit Dummy TrustManager / HostnameVerifier (library feature behind http.sslVerify=false, by design), 21 SSA flows Intent -> jgit Repository work tree -> file ops / ProcessBuilder (field-level taint through the jgit Repository object; not read one by one) |
| Unstoppable 0.52.0 | 20 | 0 / 14: Solana program ids (base58 public addresses), Solidity method signatures, Room `*_Impl` schema SQL, token-program constants flagged by `high-entropy-strings` / `secrets-sensitive-fields` (4 read in the smali, the rest have the same pattern in the title + location) | 6: solana / sol4k / tron / stellar classes not recognised as libraries (same public constants) |

**Precision on app-scope HIGH/CRITICAL: 1 TP / 19 read = about 5%** (n is small; 1 TP is low impact). Plus 36 HIGH/CRITICAL cards from libraries the scanner does not recognise.
The training apps (86-100% recall) said nothing about this: on real apps the HIGH list is dominated by a few rule families.
Root causes, in order of cards: (1) secret detectors on PUBLIC constants (blockchain addresses, method signatures, schema SQL, Kotlin messages); (2) third-party libraries outside the known list (jgit, jsch, sshj, solana, tron, stellar); (3) PEM headers in key parsers; (4) "ECB" for RSA; (5) class-local check blind to DI-provided EncryptedSharedPreferences.
Fixing these makes the three apps tuning apps; a NEW real held-out set is needed after the fixes.


## After the fixes: 0.76.0 sandbox (these three apps are now TUNING apps)
Reports: `runs/*-0.76.0-sandbox.md`. Sandbox SSA now skips library classes like the device (`ssaFindings` keeps scope != LIB); the 0.75.2
sandbox runs above analysed library classes too, which is why some of their flows (and the Password Store TP) came through Kotlin stdlib code.
| app | cards 0.75.2 -> 0.76.0 | HIGH/CRIT 0.75.2 -> 0.76.0 |
|---|---|---|
| andOTP | 22 -> 20 | 2 -> 0 (RSA no longer called ECB; it is the LOW "RSA with PKCS#1 v1.5" card) |
| Password Store | 49 -> 17 | 33 -> 0 (jgit / jsch / sshj are libraries; PEM headers; Kotlin message; injected prefs LOW) |
| Unstoppable | 49 -> 29 | 20 -> 0 (base58 addresses, ABI signatures, identifiers, SLIP10 spec key; chain SDKs are libraries) |
The one true positive (Password Store DecryptActivity FILE_PATH) is still reported, as a MEDIUM SSA flow: it now survives without the Kotlin
library classes because `by lazy { }` is modelled (CallGraph.addLazyEdges, matched by the `(...Function0;)Lkotlin/Lazy;` shape because R8
renames `LazyKt.lazy` to e.g. `ExceptionsKt.unsafeLazy`).
Noted, not scored (MEDIUM): andOTP `PlainTextBackupBroadcastReceiver` is exported without a permission and makes a PLAIN-TEXT backup of all
2FA secrets when any app sends `org.shadowice.flocke.andotp.broadcast.PLAIN_TEXT_BACKUP`; it is gated by an opt-in setting
(`isPlainTextBackupBroadcastEnabled`), so BY-DESIGN, but a real risk for users who enable it. The scanner reports the exported receiver.
Precision on HIGH/CRITICAL can no longer be computed on these apps (0 cards), and they are tuned now: the next real held-out set must be new apps.
