# APK ReLab

An Android app that analyses other Android apps' APKs **on the phone itself**: static application security testing (SAST) with an inter-procedural data-flow engine, manifest and resource checks, native-library and SBOM / SCA inspection, MASVS coverage, and a report that says what to fix first and what the scan could not see.

Current version: **1.2.1** (versionCode 225). Package `dev.apkrelab`, minSdk 26, targetSdk 36.

## What it does
- Decodes the APK (baksmali), parses Dalvik bytecode into an IR (CFG + SSA), builds a call graph and runs an inter-procedural taint analysis (sources: Intents, deep links, providers, JavaScript bridges, preferences ...; sinks: WebView, files, SQL, shell, reflection ...). Big apps are analysed in groups that fit a 256-512 MB heap.
- Rules on the manifest, resources, assets, secrets (206 vendor formats), crypto, TLS, WebViews, exported components, deep links (per intent-filter `autoVerify`), dynamic receivers, native libraries (ELF hardening, JNI bindings).
- Third-party libraries: inventory, versions, known advisories.
- Report (Markdown, HTML, SARIF): a five-line **Verdict** first (counts, critical path, at most three must-fix cards with what to verify, a confidence ratio, what was not seen), then every card with its priority, confidence factors, related findings and a one-sentence fix.
- An optional AI assistant (bring your own key) that reads the scan's own data; its answers are labelled as such and never change a card.

## What APK ReLab is NOT
- **Not a dynamic tester.** It never runs the analysed app, never sends it input, never contacts its servers.
- **Not a penetration-testing or exploitation tool.** It reports code patterns and data flows for the app's developers to fix; it produces no exploits.
- **Not complete.** It does not analyse native (C/C++) code, Dart (Flutter) or JavaScript (React Native) code beyond their strings, server-side logic, or business rules. A missing finding is never a pass; the Verdict's NOT SEEN line lists what a scan could not check.
- **Not a verdict on its own.** Findings are leads: a card says what to open and verify before acting on it.
- **Not for apps you are not allowed to analyse.** Use it on your own apps or with the owner's permission.

## Build
The owner builds on the phone with Code on the Go (no Gradle wrapper in the repository). On a PC or in CI: AGP 9.3.1, Gradle 9.8.2, JDK 17+ (JDK 21 verified), Android SDK platform 36:
```
tools/sandbox/gradle_build.sh            # downloads the toolchain into ~/android-build, builds a copy in ~/apkbuild
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug   # with your own Gradle 9.8.2
tools/termux/run_ir_tests.sh             # the `ir` engine tests with javac only
```

## Documentation
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): the pipeline and where the code is.
- [CHANGELOG.md](CHANGELOG.md): releases.
- [CONTRIBUTING.md](CONTRIBUTING.md): working rules, tests, repository hygiene.
- [USER_GUIDE.md](USER_GUIDE.md): how to read a report.
- `docs/internal/HANDOFF.md` (the engineering log) and `docs/internal/PERF.md` (every measurement).

## License
Proprietary, all rights reserved: see [LICENSE](LICENSE).
