# Changelog

Release notes in short. The full record (measurements, what was not measured, every decision) is `docs/internal/HANDOFF.md`; numbers are in `docs/internal/PERF.md`.

## 2.0.1 (versionCode 231)
- Precision (from the 2.0.0 device reports): a non-exported Activity/Service no longer counts as attacker-fed because an exported class "reads some Intent value and launches it" - the value must be proven to flow into the launching Intent; hub-aware reach (a path through a call on a framework interface with 8+ implementers is approximate); deserialization / weak hash / weak random in obfuscated code one level lower; a pattern-only fintech card is MEDIUM.
- Coverage: the card of a sink shared by a SharedPreferences flow and an Intent flow is the Intent one; AsyncTask constructor capture; parameter-valued Intent extras through method summaries.
- Real-CVE benchmark: reported in 13 of 13 valid in-scope cases, fix visible in 7 (secondary measure); C13 removed as an invalid pair (docs/VALIDATION.md).

## 2.0.0 (versionCode 230)
- Engine: async dispatch to Runnable / Callable / AsyncTask, constructor capture (deferred tasks, collection fields), Kotlin FunctionN devirtualisation,
  explicit-Intent extras and WorkManager Data linked by key, collection fields filled through "this".
- Rules: setResult(getIntent()) reflected to the caller (uri-grant-via-result); verify* calls count as validation-like.
- Hybrid apps: Flutter / React Native / Cordova-Capacitor payload inventory (hosts, endpoints, config files, credential-format count) and a precise NOT SEEN line.
- Primary metric, real-CVE benchmark (docs/VALIDATION.md): blind, the vulnerable code was reported in 7 of 14 published advisories in scope and the fix was
  visible in 2; after this release's fixes (tuning, not blind) 11 of 14 and 4.

## Maturity protocol (after 1.2.1, versionCode unchanged)
- Phase 0: repository hygiene (binary guards, docs). Phase 1: CI (hygiene, ir tests, Gradle unit tests + lint).
- Phase 2: four-condition MUST FIX gate (high-impact sink, exported entry without a signature-level guard, no validation seen, traced proof); hash-locked self-check with top3_accuracy.
- Phase 3: context model (caller checks in provider code, provider permission context, interprocedural path-sanitizer summary).
- Phase 3.5: slash-stripping path sanitizer (file sinks only).
- Phase 4: blind validation, rounds 1 and 2 (docs/VALIDATION.md): 2 MUST FIX cards judged, 0 TP.

## 1.2.1 (versionCode 225)
- MUST FIX and CRITICAL PATH cards say what to open to confirm them ("→ to verify") and how strong their evidence is; "CHECK FIRST" below 0.9.
- QA: 11 of 12 benchmark / test APKs obtained from their projects' own repositories; self-check before / after identical on six benchmark apps; two Verdict wording bugs fixed.

## 1.2.0 (224) "The Verdict"
- Five-line verdict at the top of every report (MD, HTML, SARIF); per-card confidence with visible factors; related findings; one-sentence fixes; release self-check script. No detection change.
- QA fix: NOT SEEN names Dart / JavaScript code that is read as strings only.

## 1.1.0 (223)
- Erased generic callbacks no longer carry a source from another lambda; library prefixes for Flutter plugins and SDKs; zip-slip needs the entry name to reach a path; basename sanitizer; protected dynamic receivers; encrypted preference values.
- Attack-surface protection column; per-filter deep-link map; Java ↔ .so native map; firebase-common version probe; app-wide R8 merge facts on the device.

## 1.0.0 (222)
- R8 merged-class tags in the taint heap; shared call-site table (less allocation); MASVS authentication / update / privacy posture signals; `audit_brief` agent tool.

## 0.108.0 (221) and earlier
- 0.108.0: first real Gradle build (AGP 9.3.1, Gradle 9.8.2); install-receiver hardening.
- 0.107.0 - 0.102.0: R8 field conflation studies, SDK attribution, planner digests on disk, group cache, decoded-strings overlay, installed-apps picker, assets / Hermes scan, parser allocation work.
- Earlier versions: see `docs/internal/HANDOFF.md` and `docs/HANDOFF_ARCHIVE.md`.
