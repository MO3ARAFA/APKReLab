# Held-out results, 0.73.0 (first run)

Apps: PIVAA, Allsafe, Vuldroid (never tuned on). Expected lists: `expected_heldout/*.json`, written from each app's own README before the first scan.

## Part 1: taint engine only (measured in the sandbox, `MeasureBig`, real `ir` package, apktool smali)
The Kotlin scanner (manifest, crypto, WebView, logging... rules) is NOT run in the sandbox. Part 2 needs the device.

| app | flows | reviewed in smali | verdict |
|---|---|---|---|
| PIVAA | 2 | 2 | TP: exported `VulnerableReceiver` writes to the path in the Intent extra `location` (`FileOutputStream`); TP: provider parameter into `rawQuery` |
| Vuldroid | 4 | 4 | TP x4: `RootDetection` `Runtime.exec(getIntent().getStringExtra("command"))`; Intent data / extra into `WebView.loadUrl` in `BlogsViewer`, `ForgetPassword`, `YoutubeViewer` |
| Allsafe | 4 | 4 | TP x4: `DataProvider` query / update / delete (selection from the caller into SQLite); `NoteReceiver` sends to the server named in an Intent extra (README challenge 7) |

Precision of the taint engine on these three apps: 10 of 10 flows reviewed are true positives (n = 10, small; the 3 DataProvider flows are one root cause).
Recall of the taint engine against the README lists: it found 5 of the README-listed data-flow items (Vuldroid code execution, 3 WebView items; Allsafe broadcast receiver) plus PIVAA SQL. Not found by taint: Allsafe SQL injection challenge (login form, the input comes from an EditText), Allsafe vulnerable WebView, Allsafe deep link, Vuldroid FileProvider and intent-sniffing items (those are not Intent-to-sink flows of this engine, other rules may cover them: Part 2).

## Part 2 RESULT (owner, 0.73.0 on device, Smart scan, `bench.py --measure`)
| app | first scan (official) |
|---|---|
| PIVAA | 14/25 = 56% |
| Vuldroid | 5/7 = 71% |
| Allsafe | 6/7 = 86% |
| **Total** | **25/39 = 64% (frozen baseline)** |

After correcting 3 mistakes in MY expected lists (Allsafe WebView and Vuldroid FileProvider were found by rules I had not listed: `androgoat-checks`, `res-fileprovider-paths`; PIVAA "self-signed CA in WebView": the code has no `SslErrorHandler`, only the README mentions it): 28/39 = 72%. Presence check, lenient: an upper bound.
Accuracy: 4 HIGH/CRITICAL findings outside the lists, no clear false positive; one wrong title ("financial value" on a password in Allsafe).
The 11 real misses and their causes: `tls-trustmanager` bug (METHOD_PREAMBLE vs `throws` annotation), constant IV / key as `fill-array-data`, MD5 name passed as a parameter, missing rules (tapjacking, setPluginState, unencrypted SQLite, intent sniffing in Vuldroid), weak RNG (design), hardcoded key / JS-enabled / hardcoded data in PIVAA (key = same fill-array-data cause).
0.74.0 fixes the TrustManager, IV, key and MD5-helper misses; **PIVAA is therefore in the tuning set from 0.74.0**, and a new held-out app is needed before a new benchmark claim.

## Part 2 (original instructions)
1. Install the three APKs in APKReLab (`apks` are the GitHub release files: PIVAA `apks/pivaa.apk`, Allsafe `allsafe.apk`, Vuldroid `Apks/Vuldroid.apk`).
2. Smart scan, wait for the end, Report > Markdown.
3. `python3 tools/benchmark/bench.py <report>.md --expected tools/benchmark/expected_heldout/<package>.json --measure` (Termux works).
4. Send the 3 outputs: the RECALL line and the unreviewed HIGH/CRITICAL list are the first independent numbers.

## Honest limits of this benchmark
- Presence check, lenient rule families: recall is an upper bound.
- 3 apps, about 47 entries (9 out of scope): small. PIVAA's list is rule-like (written for scanner benchmarking), so it favours static scanners.
- Allsafe/Vuldroid README lists are short; real weaknesses not in the list are not recall misses and not counted.


## Sieve (com.mwr.example.sieve), first blind run: 0.75.0, SANDBOX (2026-10-13)
- APK: `github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk`, sha256 `31878e33c526f9747c9b7ff38954bfcb2acc2a947ce7103589438e034637a6b7`.
- Expected list `expected_heldout/com.mwr.example.sieve.json` written from the public drozer walkthrough BEFORE the download (sha256 of the list at freeze: `0d0a9f04b1a3f940...`), 9 entries, 8 in scope.
- Scan: `tools/sandbox/SandboxScan.kt` = the real Kotlin pipeline without the UI (SecurityScanner.scanManifest on the Axml-decoded manifest, scanSmali per class, ResourceScanner.scanApk, SsaBridge.newFlows with the exported components as entries, dedupe, ReportBuilder.securitySection). NOT the device: no AI triage, no reach labels, no Smart-scan grouping. Report: `runs/sieve-0.75.0-sandbox.md`.
- **RECALL 8/8 = 100%** (presence check, upper bound). Honest limits: entries 1, 2 and 5 use the same rule (`manifest-exported-components`) without a class filter, so one exported-component finding could satisfy all three; reading the report, each component IS named in its own finding (PWList, DBContentProvider, FileBackupProvider, AuthService, CryptoService). The list is small and taken from a tutorial that covers the IPC attack surface, which is this scanner's strongest area.
- **Precision**: 1 HIGH/CRITICAL outside the list: `tls-trustmanager` in `NetBackupHandler$1` = TRUE POSITIVE (empty checkServerTrusted with a `throws` annotation, used in `SSLContext.init`: exactly the 0.74.0 METHOD_PREAMBLE fix). Other findings not all read: clipboard copy in PWList, credentials in the log (MainLoginActivity), 5 tapjacking layouts, 2 SettingsActivity URI flows (MEDIUM/LOW), a LOW reflection flow inside the support library `Fragment`.
- Sieve stays HELD-OUT: nothing was changed because of it. Next lists must carry a `class` per entry so one finding cannot satisfy several entries.


## Device runs, 0.75.1 (owner, Smart scan, 2026-10-13; reports in `runs/`)
- **Sieve** (the APK on the device is the newer WithSecure build `com.withsecure.example.sieve`, minSdk 17 / targetSdk 28, not the mwr 2.3.4 build used in the sandbox): **RECALL 8/8 = 100%**, same as the sandbox. 1 HIGH/CRITICAL outside the list: `tls-trustmanager` NetBackupHandler$1 (AI: NEEDS REVIEW; read in the mwr build = true positive). AI dismissed 1 finding (credential-looking constant in a log rule): agreed.
- **Allsafe**: **RECALL 6/7 = 86%** official (7/7 with the known list mistake: the WebView challenge is reported by `androgoat-checks`). 4 HIGH outside the list, AI: all TRUE POSITIVE (intent redirection ProxyActivity, prefs secret with the wrong "financial value" title, ECB, hardcoded key). AI dismissed 2: `sqlite-unencrypted` and `androgoat-checks` SQLite in `NoteDatabaseHelper` = REAL FALSE POSITIVES (the word "password" is inside the VALUES text of `insert into note (user, note) values ('admin', '... her password ...')`), checked in the smali.
- Status line: Allsafe SSA +2 flows, Sieve no extra flow.
- **Consequence**: 0.75.2 fixes that false positive, so **Allsafe moves to the tuning set**. Held-out now: **Sieve only**. Vulnerable training apps are close to saturation (86-100%); the next held-out set should be real open-source apps, scored on precision (every HIGH/CRITICAL read).
