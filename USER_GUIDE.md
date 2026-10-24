# APKReLab: how to use it as a security scanner (0.108.0)

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
5. **MASVS v2 coverage**: which controls the tool assessed, which it did not (6 of 24 are never assessed: authentication, update enforcement, part of privacy).
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

## How this version was verified (0.108.0)
- Built with the real Android toolchain for the first time (AGP 9.3.1, Gradle 9.8.2, JDK 21, compileSdk 36): `assembleDebug` OK, `testDebugUnitTest` 648 tests / 0 failures, `lintDebug` 0 errors. Steps: `tools/sandbox/GRADLE_BUILD.md`.
- The engine was run on 46 real apps (34 + 5 F-Droid apps, Axis Pay 3.0.1 in the sandbox; the owner's device reports of Axis Pay and WE Wallet). Malformed input: 240 corrupted APKs and 1,800 mangled classes went through every static component without an exception.
- NOT verified here: the UI on a device or an emulator (no emulator in the sandbox); every Android-only change is built and linted, but only the owner's phone runs it.
