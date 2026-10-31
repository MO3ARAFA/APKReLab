# CLAUDE.md - APK ReLab (read this first, then docs/internal/HANDOFF.md and BLUEPRINT.md)

On-device Android SAST app (Kotlin + a Java `ir` package: Dalvik -> IR -> SSA -> call graph -> inter-procedural taint). Owner: an Arabic speaker (Egyptian), builds on a PHONE with Code On the Go; wants short, actionable answers, in Egyptian Arabic when chatting. Code, comments and docs stay in English.

## Environment since 0.101.1 (READ FIRST): you run on the owner's PHONE
- You are Claude Code CLI inside **Termux / proot-distro Ubuntu** on the owner's Android phone. There is no PC, no Mac, no adb cable. The app is built by the owner in Code on the Go; you cannot compile Android code, so every `MainActivity.kt` / `Ui.kt` edit is "parse-checked only" until the owner's next build says otherwise (so far every such edit compiled: say it only when it did).
- Mobile limits are the main engineering constraint: RAM (the phone is memory-bound: GC took about half of a scan at a 1 GB heap), heat (device timings vary about 36% between identical runs), battery. Before any change that holds more in memory, adds threads or a cache, measure at `-Xmx1000m` and keep the flows identical. `docs/internal/PERF.md` has the method and the numbers; `tools/termux/README.md` has what runs on a phone.
- Keep the empirical workflow of the rules below: numbers before and after, negative twins, mutation checks, read the smali of every HIGH, held-out discipline, honest "not measured".
- ONE agent at a time on the repository: two sessions on the same working tree already produced a duplicate commit, a wrong note and a collision in the recall kit's work directory. `git log` and `git status` first; private temp directories (`RECALL_WORK=...`); never `pkill` by process name.
- Company apps (see tools/company/): reports, APKs and decoded folders stay in `./private/` (git-ignored). The repository is PRIVATE and must stay so. Never paste a token or an API key in a file, a commit message or a chat.

## How the owner works with you
- You produce a versioned zip (APKReLab-0_NN_0.zip) or a git commit; the owner builds it on the phone and sends back errors / screenshots / scan reports (markdown). Gradle is NOT run by you today (see "Build" below).
- Constraint of the product: it runs on Android ART with a 256-512 MB heap. Anything that holds the whole app's IR in memory, or grows per class, is a bug. Big apps are analysed in groups (ScopePlanner / SsaGroups).

## Non-negotiable working rules (they exist because each one caught a real mistake)
1. **Measure before you build, and say what you did not measure.** A claim is "verified" only if you ran it. `MainActivity.kt` and the Android-only files (Ui.kt, Ai*.kt, Council.kt ... anything importing android/androidx) were NEVER compiled by the previous assistant (no SDK in its sandbox); say so for every change you make there until you have built it.
2. **Held-out discipline.** The first run of a benchmark app is FROZEN in tools/benchmark/runs/ before any change. A fix made because of an app moves that app to the tuning set. Never report a benchmark number on an app you tuned on as if it were blind. Only Sieve is still held-out; the real-app sets 1-6 are tuning sets now. Next blind set = set 7 (protocol: tools/benchmark/heldout_real/PROTOCOL*.md).
3. **Precision = read the smali.** For real apps there is no expected list: read EVERY HIGH/CRITICAL card in the decoded smali/manifest and judge TP / TP-1CLICK / TP-low / BY-DESIGN / FP. Report by card AND by distinct issue. Do not "improve" a number by re-running.
4. **No tuning to names.** No package-name lists, no per-app exceptions (a proposal to lower network cards by "jellyfin / nextcloud" names was rejected). Prefer evidence in the code.
5. **Every new rule gets a negative twin test** and, for engine changes, a mutation check (turn the feature off, the positive test must fail).
6. **Tell the truth about provenance.** If something is already in the tree and you did not write it, say so (this happened twice: the MD5 hash-helper rule in 0.74.0 and the first half of 0.82.0).
7. **Do not delete or rewrite files to tidy up**; keep docs/internal/HANDOFF.md (it is the log) and add to it. Memory-bank style files other than HANDOFF/BLUEPRINT do not exist.
8. The owner's own product (JustMarkets) was read with its APK: "0 HIGH" was honest for 6.15.1. It is a tuning app.

## Build and test (what exists, what does not)
- `app/build.gradle.kts`: AGP 9.3.1, Kotlin 2.3.21 (+ Compose compiler plugin), compileSdk/targetSdk 36, minSdk 26, JDK 17 target. Dependencies: ARSCLib, smali / baksmali 3.0.9, apksig, jadx-core 1.5.0 (optional), JUnit 4.13.2 and org.json for unit tests.
- **There is NO Gradle wrapper in the repo** (the owner builds in Code On the Go, which brings its own Gradle). On a PC you must create one and pick a Gradle version that AGP 9.3.1 supports (look it up in the AGP release notes; the previous assistant did not verify this). Needs an Android SDK with platform 36.
- Type check of the whole app without Gradle (0.102.0): `tools/sandbox/typecheck_app.sh` (kotlinc + android-all 16 + the real jars; only the generated `R` is unresolved). It catches type errors in `MainActivity.kt` / `Ui.kt`; it is NOT a build.
- JVM unit tests: `./gradlew testDebugUnitTest` (tests live in app/src/test; the `ir` ones are plain Java).
- **0.108.0: a real Gradle build works** (AGP 9.3.1 + Gradle 9.8.2 + JDK 21 + compileSdk 36, verified): `tools/sandbox/gradle_build.sh` (downloads the toolchain into ~/android-build, builds a copy in ~/apkbuild, never copies private/). Last result (1.2.0): assembleDebug OK, 736 tests / 0 failures, lint 0 errors. Run it after any MainActivity / Android-only change.
- The previous assistant ran the tests WITHOUT Gradle: a JUnit stub + kotlinc 2.3.21 + android stubs (tools/sandbox/README.md and tools/sandbox/SETUP_FROM_SCRATCH.md). Last results (0.82.0): `ir` 268/268, Kotlin (non-Android classes only) 126/126. With a real SDK you can compile everything: do that FIRST and fix whatever the Android-only files break.

## Where things are
- `app/src/main/java/dev/apkrelab/` Kotlin: SecurityScanner.kt (scope, secrets, dedupe/absorb), ScanRules*.kt (rules: Legacy = old text rules, Ir = rules on the IR, Manifest, Resources, FinTech, Ovaa, Taint), FindingPolish.kt (severity lowering, reach), MainActivity.kt (UI, scan orchestration, ssaFindings, reachPass, AI triage), Council.kt (AI second opinion), Capabilities.kt.
- `.../ir/` Java: SmaliParser, Cfg, SsaForm, CallGraph, TaintIr (the engine), SsaBridge (flows -> cards), ScopePlanner + SsaGroups (big apps), IrRules (rules on one class), MergeTags + MergeFacts (1.0.0: R8 merged classes told apart by their class id; app-wide for grouped apps).
- 1.1.0 Kotlin modules: DeepLinks (per-filter deep links + autoVerify), NativeBridge (native method -> .so, JNI names / JNI_OnLoad), DynamicReceivers (run-time receivers' protection), PathFlow (does a value reach a file path in one method). Sandbox: SandboxScan applies DynamicReceivers; tools/sandbox/FuzzParsers110.kt fuzzes the new parsers.
- 1.2.0 report layer (no detection): Verdict (top of every report), FindingScore.confidence (per-card factors), Correlation (related findings), FixTemplates (one-sentence fixes). Release process: `tools/sandbox/self_check.sh` before every release, its "Recall:" line in the release notes (HANDOFF 1.2.0).
- `tools/sandbox/` measurement harnesses (SandboxScan.kt = the real Kotlin pipeline without the UI, MeasureBig / MeasureCompare / FlowDump = SSA only). `tools/benchmark/` bench.py, expected lists, runs/ (frozen reports), heldout_real/ (protocols + judgements).
