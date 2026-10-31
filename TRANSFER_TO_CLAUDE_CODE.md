# Transfer report: APK ReLab 0.82.0 -> Claude Code (2026-10-14)

Paste this as your first message, then let Claude Code read CLAUDE.md, docs/internal/HANDOFF.md (top entries) and BLUEPRINT.md.

## 1. What this is
An on-device Android static-analysis app (APK ReLab). Pipeline: classes -> smali -> IR -> SSA -> call graph (RTA) -> inter-procedural taint -> cards; plus text rules, manifest / resource rules, an AI triage ("Council") layer. Big apps (JustMarkets: 59,667 classes) are analysed in groups under a 256-512 MB heap.
State: version 0.82.0 (code 180). Built and run on the owner's device up to 0.80.0 (JustMarkets full deep scan finished). **0.81.0 and 0.82.0 have not been built on a device**, and the Android-only Kotlin (MainActivity.kt etc.) has never been compiled by the previous assistant.

## 2. What is verified and what is not
- Verified (sandbox, no Gradle): `ir` tests 268/268; Kotlin tests for the non-Android classes 126/126; recall on the training benchmarks unchanged since 0.75: Sieve 8/8, Allsafe 6/7 (7/7 after a known list mistake), PIVAA 21/25, Vuldroid 7/8, OVAA 19/19 present (14/19 found + 5 "no reach" in the sandbox, which has no reach labels).
- NOT verified: anything that needs the Android SDK; the AI layer (no API access in the sandbox): the 0.82.0 change that shows the AI the source method + data path of an SSA flow (`SsaBridge.Item.sourceMethod/dataPath`, `SecurityScanner.methodExcerpt`, `triageWithAi`, `Council.checkFinding`) is untested end to end. Five small edits in MainActivity (0.75.2 .. 0.82.0: re-dedupe after SSA; `reachPass` extras: lowerUnreachedHelpers, lowerNonExportedReceivers, lowerSeparateProcessDialogs, applyProviderCodeChecks, applyNetworkEvidence; appBound in ssaFindings; the triage prompt).
- First task in Claude Code: create a Gradle wrapper (none in the repo; AGP 9.3.1 / Kotlin 2.3.21 / SDK 36), build, run `testDebugUnitTest`, fix compile errors in the Android-only files, then install on a device / emulator and run a Smart scan.

## 3. Evidence trail (read these, do not re-derive)
- Training benchmarks: tools/benchmark/ (expected lists, bench.py). Held-out: Sieve only.
- Real-app precision, first runs frozen: tools/benchmark/heldout_real/PROTOCOL.md (set 1: andOTP, Password Store, Unstoppable: 1 TP / 19 HIGH before fixes), PROTOCOL_SET2..6.md (Termux, Monerujo, Ivy; DAVx5, Kiwix, Markor; Mihon, Catima, Breezy; Infinity, LibreTube, Read You; AnkiDroid, Jellyfin, Seal), JUSTMARKETS_JUDGED.md. Reports in tools/benchmark/runs/.
- Precision by card on FIRST runs: set 2 3/6, set 3 1/9, set 4 3/4, set 5 3/6, set 6 1/4 (device Termux Play build 0/2). Roughly 38% over sets 2-6, very noisy (n = 4..10 per set). Each fix round (0.76 .. 0.81) was tuned on seen apps, so those apps no longer measure anything.
- Measurements before 0.83.0: tools/benchmark/MEASUREMENTS_0820.md (grouping loses ~9% of AnkiDroid SSA sinks at the device group size, all SharedPreferences-sourced; 0 on 3 other apps; the old in-class taint engine adds 1 of 123 taint cards).
- JustMarkets (owner's product): "0 HIGH" is honest for 6.15.1; the real attack surface is a remote flag that disables trading-socket TLS pinning + an always-true hostname verifier (MEDIUM, visible) and plaintext tokens in SharedPreferences (MEDIUM). The base APK is a split with no .so: native code is not analysed (a card now says so).

## 4. Things the previous assistant got wrong (so you do not repeat them)
- Proposed an object-sensitive heap as 0.80.0; the census (FlowDump on 8 real apps) showed field conflation explains ~1 judged FP, so it was dropped. Measure first.
- Said Kiwix's remaining FP was "a lookup is not a sanitizer"; wrong: `contentUrl()` pins the origin to the app's own virtual host.
- Re-labelled two Markor cards as TP in 0.78.0; the flow dump showed they come through SharedPreferences with non-literal keys; withdrawn.
- Called an AI verdict on Termux FileReceiverActivity a true positive; the code shows the file stays inside Termux's own home after a user confirm (BY-DESIGN).
- Twice found code in the tree it had not written (provenance note in rule 6 of CLAUDE.md).

## 5. Known gaps (ordered by evidence, not by taste)
1. Blind set 7: three unseen real apps on 0.82.0 (the only measurement that ever moved the roadmap). Freeze protocol + sha256 BEFORE scanning.
2. Non-exported ACTIVITIES with an Intent source are still HIGH on purpose (OVAA / Infinity: forwarded by an exported activity; AnkiDroid PreferencesActivity is a FP). Needs "is there an exported component that forwards the caller's data to it" from the call graph, not a blanket lowering.
3. Taint through methods of R8-renamed library classes (Breezy `o02.next()`); renamed classes with no app references cannot be attributed (JustMarkets `ar.c`).
4. Jellyfin-style JS bridge through an event bus in another class; Kiwix "origin pinned by a constant prefix"; trust-all TrustManager behind an opt-in flag in another class (Read You).
5. Retire the old in-class taint engine behind a flag and re-measure the 23 apps (it adds ~1 card per 123); then delete the absorb rules in SecurityScanner.dedupe.
6. "Extra only when grouped" flows (Markor `GsFileUtils.gatherMimeType` -> Runtime.exec, AnkiDroid 3): not judged; do grouped runs create false positives?
7. Out of scope by nature and stated in the report preamble: business-logic flaws, server-side bugs, native code, cross-group flows lost to the group planner.

## 6. How to behave with this owner
Short, concrete, Egyptian Arabic in chat. When a number is bad, say it. Ask before big refactors; prefer a measurement that decides the roadmap over a new feature. Never claim a build or a test you did not run.
