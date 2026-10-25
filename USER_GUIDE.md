# APKReLab: how to use it as a security scanner (1.0.0)

## What it is good at today (measured, see "Evidence")
- Static analysis of an APK ON THE PHONE: manifest, resources, Java/Kotlin code (Dalvik IR, SSA, call graph, inter-procedural taint from exported components / deep links / Intents to WebView, SQL,
  files, commands, Intent redirection, deserialization ...), secrets (206 vendor formats + key/credential rules with positive evidence), crypto and TLS misuse, WebView settings and JavaScript bridges,
  SCA (1,272 GitHub advisories, Maven-style versions, versions read from code constants), native libraries (ELF hardening, 16 KB pages, unsafe imports, secrets in native data),
  a defense-posture table, attack scenarios, a MASVS v2 coverage table, SARIF / CycloneDX export.
- Ranking what matters: severity is lowered for code that no exported component reaches, for libraries, and for renamed code of unknown origin; findings carry the call path from the entry point.

## Workflow (what to read, in order)
1. **Attack scenarios** section: chains with an entry point, a likelihood and an adb line to try on YOUR build. Start here.
2. **CRITICAL / HIGH findings with `Scope: APP`** (the app's own code). Read the "Call path" and "Data path" lines: a reachable sink is the first to fix.
3. **SCA table**: libraries with known advisories; for versions shown as "?", run the `dependencyInsight` lines printed under the table in your project.
4. **Defense posture**: which protections are in the app's own code, which only inside an SDK ("library only"), which are of unknown origin.
5. **MASVS v2 coverage**: which controls the tool assessed. Since 1.0.0 every one of the 24 has a rule or a posture signal, but 6 (authentication, update enforcement, part of privacy) are seen ONLY through what the code uses (the table says "posture signal(s) only"): a login done on the server or in a WebView, and a consent screen of the app's own design, are not seen.
6. Export SARIF for GitHub code scanning / DefectDojo, CycloneDX for the SBOM.

## How to read the labels
- `Scope: APP` the app's code; no tag: other readable code; `OBF` renamed code (severity lowered one level); `LIB` a known library (hidden by default).
- Reach `YES` exact path from an exported component, `YES~` approximate (class-level), `NO` none found within 6 calls.
- AI triage verdicts are a SIGNAL: on 19 hand-judged cards the model never confirmed a false alarm, but it called 2 of 7 real findings false positives (tools/ai_triage). Never delete a finding because the AI said FP.

## What it does NOT do (do not rely on it for these)
- No dynamic analysis; native code is not disassembled; Flutter / React Native / Unity logic is mostly invisible; string-encrypted / heavily obfuscated apps are only partly visible.
- Authentication, server-side and business-logic flaws are out of scope.
- "No finding" is never a pass. Use it next to a dynamic test and a second scanner (MobSF) for a release decision.

## Evidence (all in the repository)
ELF reader vs readelf: 2,886 comparisons, 0 differences (tools/native). SARIF: 1,320 results on 7 apps, 0 schema errors (tools/sarif). Secret formats: 196 / 201 literal samples, 0 / 169 false positives
(tools/secrets). SCA matcher vs an independent implementation: 6,926 / 6,968 boundary versions (tools/sca). Known vulnerable apps: Sieve 8/8, Allsafe 6/7, PIVAA 21/25, Vuldroid 7/8, OVAA 16/19 (tuned on).
InjuredAndroid (never seen before, set 11): its RCE, XSS WebView, intent redirection, exported components, deep link, Firebase URL, FileProvider root path, and (after 0.94.0) the DES key challenge.
Weak spots of the evidence: precision on new apps is not measured since many fixes (last measure about 28% of HIGH cards were real, before them); recall on unknown real bugs is unknown.

## Apps from the Play Store are SPLIT: give the scanner the splits (0.99.0)
A Play Store install is several files: `base.apk` (code, manifest) and `split_config.arm64_v8a.apk` (the native libraries: Flutter's `libapp.so`, a protector, JNI code), plus resource splits.
The base alone says "native code not analysed". On a test phone with the app installed:
`adb shell pm path <package>` lists the files, `adb pull <path> .` for each. In the app, tap **Select APK** and pick the base AND the splits together (multi-select), or pick one `.apks` / `.xapk` / `.apkm` bundle.
The report then says "Splits: N" in the header, reads the libraries of the splits (hardening, 16 KB pages, secrets in the data strings), and for a Flutter app lists the hosts named in the Dart snapshot.
Checked on a real Flutter app: base + ABI split gave the same native cards as the universal APK. On the owner's phone the split import works (Axis Pay reports say "Splits: 4").
Alternatively tap **Installed apps** and pick the installed app: its base and splits are copied together.

## Reading a report since 0.102-0.108 (what changed)
- **A re-scan is fast**: group results and the planner's per-class digests are kept between scans of the same APK (Settings: cache). The status line says `cache: N of M groups reused, plan digests: N of M reused`. The first scan after installing a new APKReLab version re-runs everything (results depend on the engine).
- **Renamed SDK code**: a renamed class that only one bundled library names (Firebase, MoEngage, BouncyCastle ...) is shown with the libraries, with the reason in the card. A class R8 MERGED from several origins is never given to a library (it may hold app code).
- **LOW cards of renamed / library code are merged** per rule: one card lists every class (nothing is dropped). App-code cards stay one per class.
- **Defense posture** also reads the native libraries (root / Frida / TracerPid strings in `.so` files) and finds root checks whose paths are encrypted (`Root detection: file + installed-package probes and a shell command`).
- **Hybrid apps** (Flutter, React Native, Expo): the app's own package is taken from the launcher activity, so the app's few Java classes are `in app code`.
- **Agent tools**: `classify_class` (what an obfuscated class probably is, R8 merge signs) and `verify_class_edit` (does a smali patch assemble, which findings it removes or adds) next to callers / callees / flow_path / search_assets.
- **Strings decrypted at run time** (a protector): the report prints a Frida snippet to dump them on YOUR test device; import the dump with the Strings button and scan again.

## What changed in 1.0.0
- **Fewer false flows through R8-merged classes.** R8 can merge unrelated classes into one (a Firebase class and a Crashlytics class in one renamed class, sharing its fields) and keeps a hidden class-id field. The data-flow engine now follows that id: a value written into an object of one original class is not read back through an object of another. It finds the id from the allocation, from the builder that returned the object, from the field the object was read from, from the callers of a method, from a switch on the id, and from how the reader casts the object's other fields. Writes whose id is unknown stay visible to every read (nothing real is dropped on a guess). Checked against real R8 output (a merged pair built with R8 8.13.25: the false flow goes, the real flow through the same field stays). On Axis Pay 3 of 18 flows went (all Crashlytics reading a Firebase value; read in the smali); on Keep It 2 of 13; unchanged on the other gate apps.
- **Renamed code cards say what kind of renamed code it is**: an R8-merged class (mixed origins), R8's static helper holder, or renamed code no single library names, with the tool to check it (`classify_class`).
- **Defense posture covers authentication, updates and privacy**: OAuth (AppAuth), Credential Manager, AccountManager tokens, biometric prompt with or without a Keystore key, keys that need the user's authentication or die with a new fingerprint, device-credential confirmation, Play In-App Updates, the Google consent dialog and its privacy options, Privacy Sandbox ads. Each row says app code / renamed / library only.
- **Agent**: `audit_brief` gives one deterministic page (counts, what to verify first numbered like `get_findings`, flows through merged code, what the scan could not see). The agent is told to check a flow with `flow_path`, then `classify_class` for renamed classes on the path, and to test a patch with `verify_class_edit` before proposing it.
- **Less memory churn in the data-flow step**: the engine allocated about 40% fewer bytes on Axis Pay (same flows, same loss counters); see "How this version was verified".
- The first Deep scan after installing 1.0.0 reads every class again (the planner's cache format changed).

## How 1.0.0 was verified
- Gradle (AGP 9.3.1, Gradle 9.8.2, JDK 21): `assembleDebug` OK, 670 unit tests / 0 failures, `lintDebug` 0 errors.
- Engine: 11 open-source apps and Axis Pay in the sandbox, flow sets compared before / after (see "What changed in 1.0.0"); a real R8 fixture; every new signal has a test that fails when it is switched off.
- Memory: on Axis Pay at a 256 MB heap the data-flow step took 105 s instead of 140 s with the same flows; at 512 MB 33 s instead of 35 s. Below about 200 MB both versions run short of memory and re-run groups in parts (results are then incomplete in both): use a phone with a bigger heap for big apps.
- Mangled input: 2,700 corrupted classes through the parser, the planner and the data-flow engine: no exception.
- APKReLab's own APK scanned with itself: 4 HIGH cards in its own code, each read: 3 false alarms of heuristics, 1 already protected (the install receiver). Debug builds are flagged "debuggable" (expected).
- NOT verified here: the UI on a device; the memory gain on the phone and on WE Wallet.

## How 0.108.0 was verified
- Built with the real Android toolchain for the first time (AGP 9.3.1, Gradle 9.8.2, JDK 21, compileSdk 36): `assembleDebug` OK, `testDebugUnitTest` 648 tests / 0 failures, `lintDebug` 0 errors. Steps: `tools/sandbox/GRADLE_BUILD.md`.
- The engine was run on 46 real apps (34 + 5 F-Droid apps, Axis Pay 3.0.1 in the sandbox; the owner's device reports of Axis Pay and WE Wallet). Malformed input: 240 corrupted APKs and 1,800 mangled classes went through every static component without an exception.
- NOT verified here: the UI on a device or an emulator (no emulator in the sandbox); every Android-only change is built and linted, but only the owner's phone runs it.
