# Changelog

Release notes in short. The full record (measurements, what was not measured, every decision) is `docs/internal/HANDOFF.md`; numbers are in `docs/internal/PERF.md`.

## 2.1.6 (versionCode 239)
- Engine switches ON (each measured, each with a negative twin and a mutation check): parcel round-trip, binder hosting, WebView-client edges, result-callback edges, self-call field capture, self-listener edges, strict open-redirector, AIDL Parcel under onTransact, guard predicates, ActivityResultContract result shape, app code in library-named classes, field-writer validation. Setter capture stays OFF (KeePassDX real taint drops 51 -> 59, no CVE gain).
- CVE benchmark: MUST FIX recall 8 of 13 valid in-scope cases (was 6 in 2.1.3, 7 in 2.1.5); of those 8, the patched build drops the card in 6. All 13 cases are tuning sets, so this is not a blind number.
- Blind round 4 (30 F-Droid apps, selection committed before download): 10 MUST FIX cards in 4 apps. Read in the smali / manifest: 7 cards true positive in 4 distinct issues (xw4 saveDict, gitnex unzip, gitnex attachment name, Tasker plugin service in fireflyiii = 4 cards), 3 cards false positive / low in 2 distinct issues (xw4 DictBrowse: 2 cards, reach through a base-class hub; zipline Glance receiver, exported="false"). By distinct issue: 4 of 6. Paired against the 2.1.5 engine: 7 of 30 reports differ; the only MUST FIX change is AndStatus isFileInsideFolder (a false positive, gone). AndStatus, simplenotes, Wikipedia, OsmAnd, Omni-Notes and Nextcloud Talk are tuning apps now.
- MUST FIX cap removed (999). Self-scan scan rules tightened.
- Gates: self_check 6 lock apps PASSED, recall line identical; ir tests 494 / 0; Kotlin 545 / 0; Gradle 1039 pass / 0 fail / 0 errors, assembleDebug OK; self-scan of the built APK: 0 HIGH / 0 MEDIUM in dev.apkrelab (the debug APK's own debuggable flag, one permission and a jadx MD5 helper are the only CRITICAL/MEDIUM cards).
- Not resolved: C01, C12 (card stays LOW, needs a forwarded proof), C04, C08, C11 (MEDIUM only), C14 patched build still keeps its cards. Nextcloud / ownCloud copyFile cards remain uncertain.
- Not built (stopped by a safety filter, not retried): AI Hunt, bounty report generator, website scanner.
- Device validation: not performed. The release is based on sandbox scans only.

## 2.1.5 (versionCode 238)
- Weak host validation rule: the compared value must be the host itself (getHost or getAuthority, followed through register copies); Kotlin's StringsKt.endsWith / startsWith / contains count; endsWith(".example.com") with a leading dot is the correct check and is not reported. Wikipedia (C11): 7 cards -> 3, and the MainActivity check of the advisory is now found (MEDIUM; the MUST FIX headline does not change: 7 of 13).
- self_check 6 lock apps: PASSED, recall line identical. 4 new tests (Kotlin authority suffix, $default variant, move copy, path / leading-dot twins).
- Not done: AI Hunt (an AI pass over exported components without a HIGH card) was not built in this session.
- Device validation: not performed. The release is based on sandbox scans only.

## 2.1.4 (versionCode 237)
- Module 1, step 1 (measurement, no code): why each of the 7 missed CVE cases is not in MUST FIX. Reach 2 (C01 WorkManager data written in a Conductor controller; C12 the Intent to SingleWebViewActivity is built in an R8-merged synthetic lambda), validation 1 (C05: the only check on the path is Uri.getScheme()), sink severity 1 (C04: opening a content URI is a MEDIUM sink), source 1 (C08: only a SharedPreferences flow found), IPC source 1 (C14: AIDL parameters are not a source), rule coverage 1 (C11: Kotlin StringsKt.endsWith on getAuthority, a MEDIUM rule). Aliasing through wrapper objects explains none of the 7.
- Module 1, step 2: sink-kind validation ON by default (a check counts only when it can restrict that kind of sink: a scheme / host / prefix test does not restrict a file path). CVE MUST FIX recall 6 -> 7 of 13 (C05), 0 cases lost; the patched build drops the card in 6 of 7 (the patched C05 keeps it). Its 2.1.1 loss (6 -> 5 of 13) came from the cap of 3, removed in 2.1.2.
- New MUST FIX cards on the CVE set: 11 cards in 9 reports, 4 distinct issues read in the code: C05 (true positive, the CVE), owncloudnewsreader NewFeedActivity (exported deep-link activity reads a file path from the Intent: true positive, low impact), Nextcloud FileStorageUtils.copyFile and ownCloud FileDataStorageManager.copyFile (the Intent is read in the not-exported OperationsService; the private-component rule is off for the whole app because an exported component relaunches an Intent it received: uncertain, not judged a true positive).
- Gates: self_check 6 lock apps PASSED, recall line identical; Gradle 1018 pass / 0 fail / 0 lint errors; self-scan dev.apkrelab 0 HIGH / 0 MEDIUM / 10 LOW. Corpus taint drops: unchanged by construction (the switch only changes card confidence, not propagation; not re-run).
- Not done (step 2 picked one change): C01 / C12 reach, C04 sink severity, C08 / C14 sources, C11 Kotlin string functions in the host rule.
- Device validation: not performed. The release is based on sandbox scans only.

## 2.1.3 (versionCode 236)
- Background index: pauses only when the battery is at most 5% and the phone is not charging (`PowerPolicy`); Battery Saver alone no longer pauses it (JustMarkets report: "Index paused at 2/59667"). 3 tests (5% pauses; 40% and 6% with Battery Saver do not; charging or unknown level never pauses).
- Engine: identical to 2.1.2 (no taint-analysis change). README: new section "What This Tool Does NOT Do Well (Known Limitations)".

### What This Release Does Not Do
- 7 of 13 valid CVE cases do not enter MUST FIX: C01, C04, C05, C08, C11, C12, C14 (MUST FIX recall 6 of 13; the patched build drops the card in 6 of 6).
- 1 false positive in blind round 3 stays (simplenotes `o41.J(File)`): the gate rule that removed it also removed the Axis Pay dispatcher (`viaHub`, approximate reach) shape that must stay in MUST FIX, so it was reverted.
- 2 switches stay OFF: setter summary (KeePassDX real drops 51 -> 59, +2 LOW flows) and sink-kind validation (CVE MUST FIX recall 6 of 13 -> 5 of 13, patched drops 5 -> 3).
- 3 self-scan cards outside the dev.apkrelab code on the debug APK: CRITICAL `android:debuggable="true"` (a debug build), MEDIUM `REQUEST_INSTALL_PACKAGES` in AndroidManifest.xml (the app installs rebuilt APKs), MEDIUM MD5 inside the bundled jadx library.
- Device validation: not performed. The release is based on sandbox scans only.

## 2.1.2 (versionCode 235)
- MUST FIX lists every card that passes the gate (the cap of 3 is gone). On the CVE benchmark one report (Nextcloud 3.18.0) had 5 passing cards. Recall did not change (6 of 13); C06 now shows 3 related cards in MUST FIX instead of 1.
- C03 (Omni-Notes): a check in the method that WROTE the tainted field now counts (6.2.8 calls `validatePath` before storing the Uri). Patched builds that drop the card: 6 of 6 (2.1.1: 5 of 6).
- Engine switches ON by default: Parcel round trip (Parcel real drops 76 -> 0 KeePassDX, 4 -> 0 K-9, 2 -> 0 Chaka; flows unchanged in 6 corpus apps), WebViewClient / ActivityResult / Binder bridges (0 flow and 0 drop change in 6 corpus apps; CVE 6/13 with each of the first two on; the Binder CVE run was stopped at 10 of 24 APKs).
- Still OFF: setter summary (KeePassDX real drops 51 -> 59, +2 LOW flows, 0 CVE gain) and sink-kind validation (CVE recall 5 of 13 with it on).
- Self-scan, dev.apkrelab code: HIGH 0, MEDIUM 0, LOW 10 (2.1.1: 0 / 12 / 10). Rules now need the instruction, not a string naming the API (shell exec, biometric prompt, Jackson typing, Uri host check, Firebase URL host, code identifiers in the high-entropy rule). Left: the manifest card for REQUEST_INSTALL_PACKAGES (the app installs rebuilt APKs) and MD5 inside the bundled jadx library.
- Renamed-code cards (Scope OBF) name the library packages the class uses, instead of only "run classify_class".
- Blind round 3 false positive (simplenotes `o41.J(File)`): NOT fixed. A gate rule (approximate reach + renamed code) removed it but broke the Axis Pay dispatcher shape the owner asked to keep in MUST FIX; reverted.
- Tests: Gradle 1012 pass, 0 fail, 0 lint errors (2.1.1: 1003). self_check on 6 lock apps: PASSED, recall and flow sets identical.
- Device validation: not performed. The release is based on sandbox scans only.
- versionCode 235: above the installed 234.

## 2.1.1 (versionCode 234)
- New agent tool `diff_scans` (ReportDiff): compares two saved scan reports (findings, MUST FIX, exported components, permissions, deep links). Run on 2 real pairs without error: Paperless 33 -> 32 findings (1 fixed), Zulip 20 -> 20.
- Engine: identical to 2.1.0. Real-CVE benchmark: MUST FIX recall 6 of 13, patched build drops the card in 5 of 6 (final scan identical to the 2.1.0 scan, 24 of 24 APKs).
- Six engine changes were built and measured and ship OFF by default: sink-kind validation (CVE recall 5 of 13 with it on, 6 of 13 off), setter summary (+1 MUST FIX card on Omni-Notes, +2 LOW flows on KeePassDX), Parcel round trip (Parcel drops 76 -> 0 on KeePassDX, 0 flow change on 7 apps), WebViewClient / ActivityResult / Binder call-graph bridges (0 flow change on 7 apps, 0 differing cards on 12 blind apps).
- Blind round 3: 12 apps never named before; 4 judged MUST FIX cards (3 true positive, 1 false positive); 8 HIGH+ cards (7 true positive, 1 false positive); the false positive is also in the 2.1.0 engine. The thresholds were stricter than any earlier round (>= 4 judged cards, 0 false positives); 1 false positive, so 3.0.0 and 2.2.0 were not reached.
- Tests: 1003 pass, 0 fail, 0 lint errors (2.1.0: 946). Self-scan of the debug APK: dev.apkrelab HIGH 0, MEDIUM 12, LOW 10 (1.1.0: 0 / 12 / 7).
- Device validation: not performed. The release is based on sandbox scans only.
- versionCode: 234. The owner's table gave 221 for 2.1.1; 2.1.0 is 233 and Android refuses to install a lower code over it, so the owner confirmed 234.

## 2.1.0 (versionCode 233)
- Verdict: CRITICAL PATH shows only HIGH/CRITICAL scenarios with a proven path, otherwise `none`.
- Reach: dispatcher methods (R8-merged lambdas) count as hubs (Axis Pay cards via `im2.success -> f51.run` are `YES~`); Conductor controllers, WorkManager workers and Kotlin suspend lambdas are reached.
- Precision/recall: weak substring checks are no longer counted as validation; a reflected `getIntent()` URI grant with a grantUriPermissions provider is HIGH.
- Real-CVE benchmark: MUST FIX recall 6 of 13 (4 of 13 in 2.0.2), patched build drops the card in 5 of 6.

## 2.0.2 (versionCode 232)
- Fixes from the 2.0.1 device reports: the Hybrid framework section no longer disappears when the resource scan finishes before the code scan starts; a not-exported Activity/Service's Intent flow is lowered for EVERY engine's cards unless a tainted value is proven to flow into its launching Intent (WE Wallet SignUpWebViewActivity); the approximate-reach hub rule covers R8-renamed callback interfaces (Axis Pay).
- Reach: Fragments created by a reached method have their lifecycle callbacks reached (Omni-Notes).
- Real-CVE benchmark: the headline metric is now MUST FIX recall (3 of 13 in 2.0.1, 4 of 13 in 2.0.2); "a card of any severity" is a secondary measure.

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
