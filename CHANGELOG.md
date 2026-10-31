# Changelog

Release notes in short. The full record (measurements, what was not measured, every decision) is `docs/internal/HANDOFF.md`; numbers are in `docs/internal/PERF.md`.

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
