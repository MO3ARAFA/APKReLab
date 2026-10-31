# Architecture

APK ReLab is one Android app (`app/`, package `dev.apkrelab`): Kotlin for the UI, the scan orchestration and the rules, and a plain-Java engine package `dev.apkrelab.ir` that also runs on a desktop JVM (the sandbox harnesses and the `ir` unit tests use it without Android).

## Pipeline
```
APK (+ split APKs)
 ├─ manifest (Axml) ─────────────► manifest rules, attack surface, deep links, permission guards
 ├─ resources / assets ──────────► resource rules, secrets, Hermes string tables, network security config
 ├─ lib/<abi>/*.so (ElfAnalyzer)─► native hardening, JNI bindings (NativeBridge), Flutter snapshot strings
 ├─ libraries (SCA) ─────────────► inventory, versions, advisories
 └─ classes*.dex ─ baksmali ─► smali text (+ optional decoded-strings overlay)
        ├─ per-class rules (SecurityScanner / ScanRules*)
        └─ ir: SmaliParser → Cfg → SsaForm → CallGraph (RTA) → TaintIr (summaries, field heap,
               R8 merged-class tags) → SsaBridge (flows → cards)
               big apps: ScopePlanner groups + SsaGroups, on-disk digests / group cache
cards → FindingPolish (severity lowering, reach) → dedupe
     → ReportBuilder (MD / HTML) · SarifExport · Verdict · Correlation · FixTemplates · Masvs · AttackScenarios
```

## Where the code is
| Area | Files |
|---|---|
| UI, scan orchestration, grouped SSA, reach pass, report export | `MainActivity.kt`, `Ui.kt` |
| Scope, secrets, rule dispatch, dedupe | `SecurityScanner.kt`, `ScanRules*.kt` (Legacy, Ir, Manifest, Resources, FinTech, Ovaa, Taint, Db) |
| Severity lowering, reach, provider / network evidence | `FindingPolish.kt`, `PermissionGuard.kt`, `DynamicReceivers.kt`, `PathFlow.kt` |
| Engine | `ir/SmaliParser`, `Cfg`, `SsaForm`, `CallGraph`, `TaintIr`, `SsaBridge`, `ScopePlanner`, `SsaGroups`, `CallSkeleton`, `DigestStore`, `MergeTags`, `MergeFacts`, `IrRules` |
| Native, assets, libraries | `ElfAnalyzer.kt`, `NativeScanner.kt`, `NativeBridge.kt`, `AssetScanner.kt`, `HermesStrings.kt`, `ScanLibraries.kt`, `ScaScanner.kt`, `VersionProbes.kt` |
| Report layer | `ReportBuilder.kt`, `SarifExport.kt`, `Verdict.kt`, `FindingScore.kt`, `Correlation.kt`, `FixTemplates.kt`, `Masvs.kt`, `AttackScenarios.kt`, `DeepLinks.kt`, `PostureScanner.kt` |
| AI assistant (optional) | `Agent.kt`, `Tools.kt`, `Council.kt`, `AuditBrief.kt`, `GraphTools.kt`, `Capabilities.kt` |
| Smali edit / rebuild / sign | `Rebuild.kt` and the Build tab in `MainActivity.kt` |

## Constraints that shape the design
- Runs on Android ART with a 256-512 MB heap: nothing may hold the whole app's IR in memory or grow per class; big apps are analysed in groups, class text is read on demand, parsed IR sits behind soft references, plan digests and group results are cached on disk.
- Every rule has a negative twin test; every engine feature has a switch whose removal must make a positive test fail (mutation check).
- Measurements (device and sandbox) are in `docs/internal/PERF.md`; decisions and their evidence in `docs/internal/HANDOFF.md`.

## Tooling outside the app
- `tools/sandbox/`: desktop harnesses (SandboxScan = the app's Kotlin pipeline without the UI; MeasureBig / FlowDump = the engine), the Gradle build script, the type check, fuzzers, the release self-check.
- `tools/benchmark/`: expected lists, frozen runs, baselines, `bench.py`.
- `tools/termux/`: what runs on the phone.
