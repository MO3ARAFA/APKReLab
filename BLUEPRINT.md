# Project Blueprint: Android App for Educational Reverse Engineering & Static Analysis

> **HANDOFF NOTE FOR ANY AI ASSISTANT READING THIS FILE**
> This file is the single source of truth for the project. Read it fully, then continue development from the section "Roadmap & Status".
> - The project owner speaks **Egyptian Arabic** and prefers **concise, directly actionable** answers (code, files, commands). Reply in Egyptian Arabic unless asked otherwise; keep code and identifiers in English.
> - The owner is **not a professional programmer** (learns by experimenting) and develops on a Mac, possibly building on Android with tools like Android Studio or Code On the Go. Give complete, copy-paste-ready files and explain each step briefly.
> - Do not redesign decisions in "Key Decisions" without a stated reason. When you make progress, update the "Status Log" at the bottom and hand back the updated file.

---

## 1. Project Goal

An Android app for researchers and developers to study how apps work internally (educational reverse engineering and static analysis):

1. Import an APK and unpack it.
2. Inspect `AndroidManifest.xml`, resources, and DEX code (as Smali and Java).
3. Use an AI model (OpenAI / Gemini) to explain code, detect design patterns, and suggest educational modifications.
4. Edit files in a built-in code editor, rebuild, sign, and install the modified APK on a device for behavior testing.

**Scope / legal note:** intended for apps the user owns or is permitted to analyze. The app must show a clear notice on first launch and in the import screen. Do not add features aimed at bypassing licensing, DRM, or payments, or at distributing modified third-party apps.

---

## 2. Key Decisions (keep unless there is a strong reason)

| Area | Decision |
|---|---|
| Language / UI | Kotlin + Jetpack Compose |
| Architecture | MVVM + Clean-ish layers, Hilt for DI |
| Async | Kotlin Coroutines + Flow; heavy jobs in WorkManager / Foreground Service |
| Local DB | Room (class/method index for search) |
| DEX to Smali | smali/baksmali (dexlib2) |
| DEX to Java | jadx-core, **on demand per class only** (heavy on mobile) |
| Manifest / resources | ARSCLib (REAndroid), no `aapt` needed |
| Fallback resources | apktool-lib (needs `aapt2` shipped as `libaapt2.so` in `jniLibs`) |
| Zip | `java.util.zip` / zip4j |
| Editor | Sora Editor (Rosemoe) with TextMate grammars |
| Signing | `apksig` (v1/v2/v3), keystore generated in-app via BouncyCastle |
| Install | `PackageInstaller` API |
| AI | `AiProvider` interface; OpenAI + Gemini implementations; user supplies own API key |
| Key storage | EncryptedSharedPreferences / Android Keystore |
| Networking | Retrofit or Ktor with SSE streaming |

---

## 3. Architecture

### 3.1 Module layout (suggested Gradle modules)

```
:app                  - Compose UI, navigation, Hilt entry
:core:common          - utils, Result types, dispatchers
:core:model           - data classes (ApkProject, ClassInfo, MethodInfo, ...)
:core:database        - Room entities/DAOs (class & method index)
:feature:importer     - SAF picker, installed-apps list, workspace copy
:feature:analysis     - manifest parser, resource decoder, DEX indexer
:feature:decompiler   - baksmali wrapper, jadx wrapper (lazy)
:feature:editor       - Sora Editor integration, file tree, tabs
:feature:ai           - AiProvider, prompt templates, diff/apply logic
:feature:build        - smali assemble, resource rebuild, zip, zipalign, sign, install
```

Start with fewer modules (e.g. one `:app` with packages) if modularization slows the owner down; split later.

### 3.2 Workspace layout (private app storage)

```
files/workspaces/<projectId>/
  original.apk
  unpacked/            # raw zip contents
  smali/               # classes.dex -> smali/classes/..., classes2.dex -> ...
  res/                 # decoded resources
  AndroidManifest.xml  # decoded text
  out/                 # rebuilt artifacts
  project.json         # metadata (package, version, createdAt, edited files)
```

---

## 4. Decompilation & Analysis Pipeline

1. **Import:** pick APK via Storage Access Framework (or from installed apps via `PackageManager` -> `sourceDir`), copy to the workspace.
2. **Unzip** to `unpacked/`.
3. **Manifest:** decode binary XML with ARSCLib; show package, versionName/Code, min/target SDK, permissions, activities/services/receivers/providers, exported flags.
4. **Resources:** decode `resources.arsc` and binary XML under `res/` with ARSCLib.
5. **DEX to Smali:** baksmali **lazily** (per class when opened) with a full class-name index built first.
6. **Index:** store class names, method signatures, and smali file paths in Room for fast search.
7. **DEX to Java (optional view):** run jadx-core for a single class on demand; cache the result; show a progress indicator and a timeout.
8. All heavy work in `WorkManager` / Foreground Service with progress notifications.

**Technical notes**
- Android 10+ forbids executing binaries from app data directories. If `aapt2` is needed, ship it as `libaapt2.so` in `jniLibs` and run from `nativeLibraryDir`. ARSCLib avoids this.
- Multi-DEX: handle `classes.dex`, `classes2.dex`, ... in order.
- Memory: stream large files; never load a whole DEX into a String.
- Obfuscated apps: show names as-is; AI can help suggest meaningful names (see prompts).

---

## 5. AI Integration

### 5.1 Layer design

```kotlin
interface AiProvider {
    suspend fun complete(request: AiRequest): AiResponse
    fun stream(request: AiRequest): Flow<String>   // SSE tokens
}
class OpenAiProvider(...) : AiProvider
class GeminiProvider(...) : AiProvider
```

- The user enters their own API key (Settings screen), stored encrypted.
- Optional later: a local-model provider (e.g. an on-device or LAN server) for privacy.
- Show a clear warning that selected code is sent to an external service.

### 5.2 Context & chunking

- Send one class or method plus **direct context**: callee signatures, field declarations, class header. Not the full app.
- Estimate tokens before sending; truncate or split long methods and summarize in steps.
- Cache responses per (class, method, template, model) in Room.

### 5.3 Prompt templates

Each template = fixed system prompt + variables.

**A) Explain function flow & logic**
```
System: You are a reverse-engineering tutor for educational static analysis.
User: Explain this {smali|java} method step by step: purpose, inputs/outputs,
control flow (branches/loops), and calls to other methods.
Class: {class} | Method: {method}
Code: {code}
Context (callees/fields): {context}
Answer in {lang}, as a numbered flow, then a 2-line summary.
```

**B) Detect design patterns**
```
Analyze these classes and identify design patterns (Singleton, Observer, Factory,
Builder, Adapter, MVVM, Repository...). For each: evidence from the code,
confidence (low/medium/high), and the role of each class. If none, say so.
Code: {code}
```

**C) Educational modification suggestion (structured output)**
```
Suggest an educational modification to test this behavior (e.g. change a constant,
add a log line, flip a condition). Return JSON only, no prose:
{"file":"","original":"","modified":"","explanation":"","risk":""}
Code: {code}
```
- Validate the JSON; on failure, retry once with "return valid JSON only".
- **Never auto-apply.** Show a diff; apply only when the user taps **Apply**.

**D) Rename suggestions for obfuscated code**
```
Suggest meaningful names for these obfuscated classes/methods/fields based on behavior.
Return JSON: [{"old":"","new":"","reason":""}]
Code: {code}
```

**E) Manifest / permission review**
```
Explain each permission and exported component in this manifest in plain language,
and note which are unusual for the app's apparent purpose.
Manifest: {manifest}
```

---

## 6. Code Editor & Rebuild

### 6.1 Editor
- **Sora Editor** with TextMate grammars for Smali, Java, XML.
- Collapsible file tree (`LazyColumn`), tabs for open files, search-in-file and global search (via Room index).
- Toggle Smali <-> Java (Java is read-only, from jadx).
- Select code -> floating action "Explain" -> opens the AI panel.
- Undo/redo, unsaved-changes indicator, per-file "modified" marker; keep a backup of the original file for diffing.

### 6.2 Rebuild pipeline
1. Assemble edited Smali -> `classes*.dex` (smali assembler); report errors with file/line.
2. Rebuild resources/manifest via ARSCLib.
3. Re-zip: keep `resources.arsc` **uncompressed** and 4-byte aligned; preserve other entries.
4. Zipalign (apksig / ARSCLib).
5. Sign with `apksig` (v1/v2/v3). Keystore generated in-app (BouncyCastle) and stored securely.
6. Install via `PackageInstaller`.

**Known issue:** an APK signed with the user's key cannot update over the original (signature mismatch). Options: uninstall the original first, or auto-change `package` name in the manifest for side-by-side testing (warn: may break apps relying on the package name, providers/authorities need updating too).

Show a build log screen with each step's status and errors.

---

## 7. UI / UX (Compose, MVVM)

1. **Import screen:** pick APK / installed apps; recent projects; legal notice.
2. **Overview screen:** manifest summary, permissions, components, DEX count/size.
3. **File tree screen:** `smali/`, `res/`, `assets/`, `lib/`, `META-INF/`; search bar.
4. **Editor screen:** tabs, syntax highlighting, Smali/Java toggle, "Explain" action.
5. **AI panel (bottom sheet):** explanation (streamed), design patterns, suggested modifications with diff + Apply/Reject; provider/model selector.
6. **Build screen:** log, sign settings, install button.
7. **Settings:** API keys, model choice, language, theme, keystore management, cache clearing.

---

## 8. Roadmap & Status

**MVP (do first)**
- [ ] Project setup (Compose, Hilt, Room, Gradle version catalog)
- [ ] Import APK via SAF -> copy to workspace -> unzip
- [ ] Manifest viewer (ARSCLib)
- [ ] File tree screen
- [ ] DEX -> Smali on demand + class index in Room
- [ ] Smali viewer with syntax highlighting
- [ ] AI: explain a single method (one provider, streaming)

**Phase 2**
- [ ] Editor with save/diff/backup
- [ ] Rebuild + sign + install pipeline
- [ ] Second AI provider, all prompt templates, response cache
- [ ] jadx on-demand Java view

**Phase 3**
- [ ] Global search, rename suggestions (template D), manifest review (template E)
- [ ] Local/LAN model provider
- [ ] Export project / share report (Markdown)

---

## 9. Risks & Open Questions

- jadx-core is heavy on mobile (RAM/time): enforce per-class decompile, timeouts, and a size limit.
- Build pipeline correctness (alignment, resource table rewrite) is the hardest part; test with a simple sample APK the owner built.
- Signature mismatch and package-name changes (see 6.2).
- Play Protect or OS install restrictions may block installing modified APKs; document for the user.
- Open: minimum Android version to support? (suggest minSdk 26)
- Open: build the app in Android Studio on Mac vs on-device (Code On the Go)? Dependency availability differs.

---

## 10. Suggested First Task for the Next AI

Produce the initial project skeleton:
1. `libs.versions.toml` + `build.gradle.kts` with dependencies (Compose, Hilt, Room, WorkManager, ARSCLib, smali/baksmali, zip4j, apksig, BouncyCastle, Retrofit/Ktor, Sora Editor).
2. Package structure from section 3.
3. A working "Import APK -> unzip -> show Manifest summary" flow.

Then wait for the owner's confirmation before moving on.

---

## 11. Status Log

| Date | Update |
|---|---|
| 2026-10-06 | Blueprint created (architecture, pipeline, AI prompts, editor/rebuild, UI). No code written yet. |
| 2026-10-06 | 0.1-0.6.1 built in Code On the Go: import/unzip, manifest XML, file tree, class index (16,649 classes), baksmali viewer + highlighting, Gemini explain (Egyptian Arabic) with 503 retry/fallback and markdown rendering. Verified through 0.6.0. |
| 2026-10-06 | 0.7.0: editable Smali with save/diff/revert/backup (Phase 2 "Editor with save/diff/backup"). Next: 0.8.0 rebuild + sign + install. See HANDOFF.md. |
| 2026-10-06 | 0.8.0: Build tab (assemble edited smali -> merge dex -> repack/align -> apksig sign -> verify -> PackageInstaller install, export). Signing key lives in Android Keystore (deviation from BouncyCastle, fewer deps). Unverified on device. See HANDOFF.md. |
| 2026-10-06 | 0.8.2 verified end-to-end (edit -> build -> sign -> install, split app). 0.9.0: AI Suggest (Template C) with JSON validation, diff, Apply/Reject. Unverified. |
| 2026-10-06 | 0.9.1 verified (AI Suggest -> Apply -> Build -> Install works). 0.10.0: exportable signing key (PKCS12 file, hand-built self-signed cert) with Export/Import/New key buttons; replaces the non-exportable Keystore key. Unverified. |
| 2026-10-06 | 0.10.1 verified (key export/import, same fingerprint, install OK). 0.11.0: Foreground Service for Build with progress notification. Unverified. |
| 2026-10-06 | 0.11.0 verified (foreground service build). 0.12.0: AI response cache (file based), template E (manifest review), template D (rename suggestions, read-only). Unverified. |
| 2026-10-06 | 0.12.0 verified (cache, manifest review). 0.12.1: 'answered by <model>' footer with fallback reasons; no-preamble prompts. Unverified. |
| 2026-10-06 | 0.12.2: Rename prompt lists declared names; empty answers not cached and show the model footer. Unverified. |
| 2026-10-06 | 0.12.3: full code review; fixes only (fallback answers not cached, back button on Android 16, rotation, confirm before wiping edits, split reuse, install-session cleanup). Next: global search, then template B. Unverified. |
| 2026-10-06 | 0.12.4: second review; foreground-service stop race fixed, signing.p12 written atomically. Next: global search, then template B. Unverified. |
| 2026-10-06 | 0.13.0: global code search across all classes (streamed baksmali, jump-to-line). Owner-accepted known limits recorded in HANDOFF.md (dex >= 040 untested, no edge-to-edge insets, AI cache is FIFO). Next: template B, Markdown report. Unverified. |
| 2026-10-07 | 0.14.0: template B (design patterns) via "Patterns (AI)" button. Next: Markdown report export, streaming, jadx view, Sora Editor, package rename. Unverified. |
| 2026-10-07 | 0.13.0 and 0.14.0 verified on device. 0.15.0: Markdown report export (app info, manifest, edited-class diffs, AI notes). Next: streaming, jadx view, Sora Editor, package rename. Unverified. |
| 2026-10-07 | 0.15.0 verified (report export). 0.16.0: SSE streaming for free-text AI answers (Explain/Patterns/Manifest review). Next: jadx view, Sora Editor, package rename. Unverified. |
| 2026-10-07 | 0.16.0 built and runs. 0.17.0: package rename (binary manifest patcher, splits too) so the modified app installs next to the original. Next: Sora Editor, jadx view. Unverified. |
| 2026-10-07 | 0.22.0: Security tab UX - Smart scan (manifest + deep scan + AI triage in one button, one progress line), Top-5 confirmed-findings summary, per-finding "Explain exploit" (idea / impact / safe check / fix, Egyptian Arabic). Next: entry-point -> sink tracing, "Fix all confirmed", before/after compare. Unverified. |
| 2026-10-07 | 0.22.0 verified on device (Smart scan, Top 5). 0.22.1: scanner tuning (data-class toString false positives, scope after package rename, more SDK prefixes) + smaller tab labels. Unverified. |
| 2026-10-07 | 0.22.1 verified (604 findings, Explain exploit works). 0.23.0: call graph built during Deep scan + entry-point->vulnerable-method tracing, reachability shown in Top 5, stricter AI triage (TP needs intrinsic weakness or demonstrated attacker input). Next: Fix all confirmed, before/after compare. Unverified. |
| 2026-10-07 | 0.23.1: compile fix for 0.23.0 (trailing lambda bound to the wrong parameter in SecurityScanner.trace call). Unverified. |
| 2026-10-07 | 0.27.0: multi-provider AI (Gemini + Groq + OpenRouter via AiHub.kt, fallback chain, per-provider keys). Plan agreed with owner: 0.28.0 agent tools + chat tab + quick buttons (reads automatic, edits ask), 0.29.0 multi-model council (analyst/critic/judge), free providers only. Unverified. |
| 2026-10-07 | 0.27.0 verified on device (fallback chain works). 0.27.1: OpenRouter default -> openrouter/free, cooldown for 404/quota models. Unverified. |
| 2026-10-07 | 0.27.2: OpenRouter free-model rotation (live list from OpenRouter, ordered strongest first, per-model cooldowns, editable list in settings). Unverified. |
| 2026-10-07 | 0.27.2 verified on device (OpenRouter free list works; nvidia nemotron-3-ultra answered). 0.28.0: AI Agent (Agent.kt tool loop + full-screen chat + quick buttons; read tools automatic, propose_edit asks with diff); markdown code fences rendered. Unverified. |
| 2026-10-07 | 0.28.1: app icon (adaptive vector icon: package cube + magnifier, Midnight palette, themed monochrome layer). 0.28.0 agent still unverified. |
| 2026-10-07 | 0.28.0 verified on device (Agent chat answers, tool loop + OpenRouter free rotation work). 0.28.2: Agent window cosmetics (dark status/nav icons, no nav scrim, markdown rules). Unverified. |
| 2026-10-07 | 0.28.2 verified? (owner to confirm). 0.29.0: Council (critic + judge on different models) for agent edits and confirmed security findings; `AiHub.callAvoiding`; Council ON/OFF in AI settings. Next: 0.30.0 build/rename tools for the agent, dry-run assemble before the diff. Unverified. |
| 2026-10-07 | 0.30.0: AI Hub - every feature is an agent tool (Tools.kt registry + Tools palette), model team (Team.kt: strongest model = lead, other models = workers run in parallel via delegate/delegate_many, lead pin + delegation toggle in AI settings), new tools: scan_security, build_apk, install_apk, uninstall_original, set_package_rename, revert_class, list_edits, open_class, export_report, explain_class, design_patterns, rename_suggestions, security_review, review_manifest. Unverified, not compiled. |
| 2026-10-08 | 0.36.0: background indexing (class index + gzipped smali text index built right after an APK loads, progress line, toggle in AI settings, Deep scan reads through the index). Next: 0.37.0 jadx Java view (per-class). Unverified. |
| 2026-10-08 | 0.37.0: Java view via jadx (one class + inner classes per run, from the smali text index -> tiny dex; size limit, 45 s timeout, per-APK gzip cache; `Java view` toggle, `Explain Java (AI)`, agent tool `get_java`). Next: Fix all confirmed, before/after compare. Unverified. |
| 2026-10-08 | 0.38.0-0.38.2: manifest quick fixes (boolean flips applied at build), AI Hub tools queue_manifest_fix + queue_manifest_all (fix all in one confirmation, launcher / deep links kept). Next: before/after compare, keys/signing + settings. Unverified. |
| 2026-10-08 | 0.39.0: scanner coverage + AI self-knowledge. New manifest checks (targetSdk, sharedUserId, legacy storage, accessibility, half-protected provider), new code checks (PBKDF2 iterations, SHA1PRNG seed, JWT secret, intent redirection, fragment injection, WebView URL from Intent, OkHttp body logging), 12 more secret formats, FileProvider path check; Capabilities.kt + tool app_capabilities so the AI Hub knows the app's features, checks and limits. Unverified. |
| 2026-10-13 | 0.73.0: first independent benchmark (held-out PIVAA / Allsafe / Vuldroid, expected lists from their READMEs, `bench.py --measure`, taint-only sandbox run: 10/10 reviewed flows TP). Device Part 2 pending. Next: 0.74.0 the 3 audit gaps, then rule-gap analysis. Unverified. |
| 2026-10-13 | 0.74.0: held-out misses fixed (METHOD_PREAMBLE vs `throws` annotation = tls-trustmanager bug, constant byte[] IV/key via fill-array-data, GCM nonce, MD5 helper) + ir sources/sinks: Parcel.read*, ZipEntry.getName, intent redirection (getParcelableExtra -> startActivity). First held-out recall was 25/39 = 64% (72% after list fixes); PIVAA moved to the tuning set. ir 227/227, Kotlin 87/87 in the sandbox; not built on device. |
| 2026-10-13 | 0.75.0: IR rules on one class (ir/IrRules.java + ScanRulesIr.kt, RuleContext.ir lazy): intent sniffing (SSA trace to new Intent, aliases, escape = quiet), sqlite-unencrypted (sensitive column / PII slice, else INFO), webview-plugin-state (enum traced through phis), tapjacking-sensitive-layout (layout + dex mitigation names + minSdk). Vuldroid moved to the tuning set; held-out = Allsafe only. ir 248/248, Kotlin 95/95 in the sandbox. |
| 2026-10-13 | 0.75.1: Sieve blind sandbox run 8/8 (+1 true-positive CRITICAL outside the list); tools/sandbox/SandboxScan.kt; weak-random decided on the IR (Random output traced in SSA to a security use; receiver must be new java.util.Random). Held-out: Allsafe + Sieve. |
| 2026-10-13 | 0.75.1 device: Sieve 8/8, Allsafe 6/7 (+1 real SQLite FP). 0.75.2: SQL column-list only (VALUES ignored), dedupe re-run after SSA (+2 absorb rules), grouped tapjacking / keyboard-cache cards, credential title for prefs, bench.py counts merged rule ids. Allsafe -> tuning set; held-out = Sieve. |
| 2026-10-13 | 0.76.0: real-app held-out (andOTP, Password Store, Unstoppable) first precision 1/19 on HIGH/CRIT; fixes: public-value filters for secret detectors, 15 git/ssh/PGP/chain library prefixes, PEM needs a body, RSA is not ECB, BIP32/SLIP10 seed keys, injected prefs LOW, Kotlin `by lazy` modelled in the call graph. HIGH/CRIT on the three apps 55 -> 0, the TP kept. Those apps are tuning now. |
| 2026-10-13 | 0.77.0: real-app set 2 (Termux GitHub/Play, Monerujo, Ivy) precision 3/6 sandbox, 0/2 device Termux Play; fixes: unreached HIGH taint in helper / signature-guarded classes -1 level, ContentResolver/Cursor carry the URI taint, zip from inside the APK = LOW. Set 2 -> tuning. |
| 2026-10-13 | 0.78.0: real-app set 3 (DAVx5, Kiwix, Markor) first precision 1/6 by issue; fixes: JS bridge judged by its exposed methods (+ webview-js-bridge-method rule), SharedPreferences links via non-literal keys are weak leads. Kiwix HIGH 3 -> 1, Markor 7 -> 5, nothing else moved. Set 3 -> tuning. |
| 2026-10-13 | 0.79.0: one root cause = one SSA card, onActivityResult helpers, Fetch2 library; FlowDump census: 1 of the judged HIGH FPs comes from field conflation, so the object-sensitive heap (0.80.0) is postponed. Markor HIGH 5 -> 3, Termux 8 -> 7. |
| 2026-10-13 | 0.80.0: from sets 4+5 (0.79.0 on unseen apps: 6/10 by card, 3/6 by issue): non-exported receivers/services lower Intent taint, SSA absorbs the in-class twin, R8 short-package Object fields weak, path literals not secrets. Infinity 5 -> 2 HIGH, Read You 4 -> 3; recall unchanged everywhere. Object-sensitive heap postponed. |
| 2026-10-14 | 0.80.0 built on device (JustMarkets full deep scan, 0 HIGH). 0.81.0: network config cards MEDIUM unless the app code uses a plain-HTTP URL (cleartext-url-used), provider-code-permission marker lowers the manifest provider card, separate-process crash dialogs lowered, JS bridge follows same-class helpers. HIGH on 23 apps: 13 BY-DESIGN network cards gone, all judged TPs kept. |
| 2026-10-14 | JustMarkets 6.15.1 read with the APK: 0 HIGH honest, but OBF lowering hit renamed app code. 0.82.0: renamed classes with >= 3 app-package refs and no SDK identity string are APP scope (no OBF lowering), JVM descriptors not secrets, native-coverage card (ABI split without .so), report scope line. Breezy +1 real HIGH token surfaced; benchmarks unchanged. |
| 2026-10-14 | 0.82.0 part 2: the AI triage / council is shown the source method and the source -> sink path of an SSA flow (Item.sourceMethod / dataPath, methodExcerpt, 900-char detail). Part 1 (app-bound renamed classes, native card) re-verified: JustMarkets attribution, benchmarks unchanged. |
| 2026-10-14 | Measured before 0.83.0: group loss at the device size ~9% of AnkiDroid SSA sinks (low-value prefs leads), 0 on 3 other apps; old in-class taint engine = 1 of 123 taint cards. Boundary summaries / engine merge not justified by data; next: set 7 of unseen real apps. |

