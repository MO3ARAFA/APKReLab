# Plan for 3.0.0 (written 2026-11-02, from `docs/EVIDENCE_2026-11-02.md` only)

State of the evidence in two sentences: 0 commits are merged since 2.1.0; four branches (sessions 1, 2, 3a, 3b) hold the work, build together with 997 tests and 0 failures, and changed 0 flows on the 7 corpus apps except 2 LOW flows on KeePassDX. The blind state is "never measured blind on current code", with 2 judged MUST FIX cards and 0 true positives over 6 apps in the two earlier rounds.

So the scope is: integrate, prove no regression, close the named measurement gaps that gate the release, and measure on apps never seen. No new detection is proposed, because no evidence bullet shows a detection gap that can be addressed without CVE analysis (see "Out of scope").

Evidence references below are written `E:<section>/<metric>`.

### Item 1 — Integrate the four branches into one release candidate
- **What**: merge `claude/session-1-reportdiff`, `claude/session-2-shapes`, `claude/session-3a-parcel-validation`, `claude/session-3b-bridges` into one branch from main, resolving `docs/internal/HANDOFF.md` by keeping all four session entries.
- **Why**: E:Shipped/"Merged to main since 2.1.0: 0 commits"; E:Measured/"Gradle gate on main merged with the four branches — 997 tests" (the merge was tested in a throw-away worktree, not kept).
- **Acceptance test (numbers)**: Gradle `testDebugUnitTest lintDebug assembleDebug` on the branch: 997 tests, 0 failures, 0 errors, 0 lint errors; `self_check` Recall line equals `docs/evidence/2026-11-02/self_check_recall.txt:1` character for character (6 of 6 flow sets identical to the baseline); `grep -c "^- 2.2 session" docs/internal/HANDOFF.md` returns 4.
- **Failure modes**: a `HANDOFF.md` entry lost in the conflict resolution (the grep count is below 4); a test-class name or helper name used twice by two branches (compile error); a Gradle run on a stale `~/apkbuild` copy hiding a deleted file (the build directory is emptied first, as in the evidence runs).
- **Estimate**: 2 hours.

### Item 2 — Rescan the 24 CVE-benchmark APKs with the release candidate
- **What**: run `tools/benchmark/cve/run.sh` on the 24 APKs with the Item 1 build and score with `score.py --mustfix --secondary`.
- **Why**: E:Measured/"MUST FIX recall — 6 of 13" and "Patched build drops the MUST FIX card — 5 of 6" are the headline numbers of 2.1.0; E:Not measured/"C14 (OsmAnd) at MUST FIX: no run after the binder bridge was scored". This is the regression gate for the engine changes of sessions 3a and 3b.
- **Acceptance test (numbers)**: MUST FIX recall >= 6 of 13 and patch drops >= 5 of 6; a per-case table of every case whose status differs from `tools/benchmark/cve/runs/run5_210_cd1ed9a.txt` (the expected count is 0; each difference is listed with the card title and the switch responsible); the C14 row recorded with its before and after MUST FIX counts.
- **Failure modes**: recall below 6 of 13 or drops below 5 of 6 (then the responsible branch is switched off per the decision tree); a card that moves between MUST FIX and not for a reason in the reach labels (the per-case table names it); the APK set is missing a file (24 of 24 must scan).
- **Estimate**: 2.5 hours.

### Item 3 — Judge the 2 flows that the setter summary adds on KeePassDX
- **What**: read the smali chain of the 2 LOW-confidence flows in `UriHelper.getUriOutputStream` (KeePassDX) that appear with `SETTER_CAPTURE` on and classify each as `real`, `by-design` or `fp`.
- **Why**: E:Not measured/"The 2 flows added on KeePassDX by the setter summary: no smali chain was read"; E:Measured/"Session 3a.1 flows — KeePassDX 9 -> 11".
- **Acceptance test (numbers)**: 2 of 2 flows classified. If 1 or more is `fp` or not decided: `TaintIr.SETTER_CAPTURE` default is switched to off and a rerun of KeePassDX shows 9 flows. If 2 of 2 are `real` or `by-design`: the switch stays on and the classification is written to HANDOFF.
- **Failure modes**: a chain that cannot be decided from the smali (counts as not decided, so the switch goes off); switching it off also removes the `getterSetterRoundTripPreservesTaint` behaviour (that test is then marked as the documented off-state, not deleted).
- **Estimate**: 1.5 hours.

### Item 4 — Complete the corpus table (class counts, exact Parcel drops, the Zulip zero)
- **What**: extend the MeasureBig run to print classes read and the exact `android/os/Parcel` drop count for every app (owner list long enough to include it), rerun the 7 corpus apps on the Item 1 build and on main behaviour, and commit the table.
- **Why**: E:Not measured/"Zulip, `android/os/Parcel` and all real drops: 0 and 0 with 0 flows ... the number of classes the harness read for Zulip was not recorded" and "Axis Pay 3.0.1, `android/os/Parcel` drops: only known to be below 21".
- **Acceptance test (numbers)**: the table has 7 rows, each with an integer class count, an integer Parcel drop count (no "below N"), real drops and flows, for main behaviour and for the release candidate; Zulip has either a class count greater than 0 with its flow count, or the value 0 with a one-line reason read from the harness output; flows on the 7 apps equal the Item 1 expectation (K-9 0, NewPipe 1, Paperless 1, Zulip 0, Chaka 1, KeePassDX 9 or 11 per Item 3, Axis Pay 15).
- **Failure modes**: the harness cannot print a class count without a code change in `tools/sandbox/MeasureBig.java` (a tool change only, no engine change); Zulip's smali directory is unreadable by the harness (then the row says so and Zulip is dropped from the paired comparison, with 6 apps remaining).
- **Estimate**: 1.5 hours.

### Item 5 — Blind round 3: paired scan of 12 apps never named in any HANDOFF entry (THE VERSION GATE)
- **What**: choose 12 apps from the F-Droid index with `tools/benchmark/blind_select.py` (new seed, minimum size 5 MB, permission INTERNET, the touched list = every package name written in the repository, `./private`, the benchmark and recall-kit folders, and the six apps of rounds 1 and 2); commit the 12 names and the index SHA-256 of each APK BEFORE any download; scan each APK once with the release candidate and once with main behaviour (all session switches off by system property: `apkrelab.noParcelRoundTrip`, `noSetterCapture`, `noSinkKindValidation`, `noWebViewClientEdges`, `noResultCallbackEdges`, `noBinderHosting`); read in the smali every HIGH and CRITICAL card of the release candidate and every flow line that differs between the two scans.
- **Why**: E:Blind state/"Never measured blind on the current code"; E:Measured/"Round 1 — 0 of 2 judged MUST FIX cards were true positives" and "Round 2 — 0 MUST FIX cards and 0 HIGH+ cards in 3 apps" (`docs/VALIDATION.md:66` states that 2 cards over 6 apps is too few and asks for a larger round); E:Measured/"Session 3a/3b ... 0 flow changes ... on the 7 corpus apps" (all corpus apps are tuning apps, so the effect on unseen apps is unknown).
- **Acceptance test (numbers)** — all four must hold for 3.0.0:
  1. 12 of 12 selected names are absent from the touched list (a script prints 0 matches) and 12 of 12 downloaded APKs match the index SHA-256 (a failed download is the only allowed replacement, recorded).
  2. The number of judged MUST FIX cards over the 12 apps is >= 4 (judged = read in the smali and classified TP, FP or not decidable).
  3. FP among judged MUST FIX cards = 0.
  4. Paired differences: every flow line that differs between main behaviour and the release candidate is classified `real`, `by-design` or `fp`, and the number classified `fp` = 0.
  The result is written to `docs/VALIDATION.md` with the numbers per app, whatever they are.
- **Failure modes**: fewer than 4 MUST FIX cards over 12 apps (as in round 2, which had 0 over 3 apps; then item 2 of the test fails and the result is "n/a", never counted as a pass); a card whose chain cannot be decided (counts as not decidable, not as TP); the sandbox has no device reach pass, so a rule card outside an exported class has no reach label and cannot enter MUST FIX (the paired comparison still runs); the proxy blocks `f-droid.org` (HTTP 200 for `index-v1.jar` on 2026-11-02, E:Blind state); split APKs analysed as base only.
- **Estimate**: 7 hours.

### Item 6 — Device re-run package and the first device pair for ReportDiff (owner-side, does not gate the version)
- **What**: deliver the release-candidate APK and a three-line checklist for the owner to scan WE Wallet, JustMarkets and Axis Pay 3.1.0 on the phone; run `diff_scans` on each old/new report pair.
- **Why**: E:Not measured/"2.1.0, WE Wallet / JustMarkets / Axis Pay 3.1.0: NOT measured: a device run of 2.1.0"; E:Not measured/"ReportDiff, any device: NOT measured: `diff_scans` on a device".
- **Acceptance test (numbers)**: three new device reports exist; `diff_scans` finishes without error on 3 of 3 pairs; the table records, new against old: `android/os/Parcel` real drops for WE Wallet (old 151) and JustMarkets (old 132); CRITICAL PATH for WE Wallet and JustMarkets (old: a scenario listed in both); reported cards (old 41, 49, 41); MUST FIX (old: empty in all three). No target is set for these values; they are recorded.
- **Failure modes**: the owner does not run it (the gap stays "Not measured" in the release notes, which is the correct state); a report from a different scanner build; `diff_scans` on a report larger than 8 MB (the tool returns an error line, the pair is then compared by hand and noted).
- **Estimate**: 2 hours of work on this side (the device run is the owner's).

### Item 7 — Release mechanics, with numbers only in the notes
- **What**: set the version from the decision tree below; write `CHANGELOG.md` with one line per item and only numbers; update `docs/VALIDATION.md` (Item 2 and Item 5 results); run Gradle, `self_check` and a self-scan of the built APK; merge the PR when the 3 CI checks are green; send `APKReLab-<version>-debug.apk` and `APKReLab_<version>.zip`.
- **Why**: E:Measured/"Last recorded self-scan — dev.apkrelab HIGH 0, MEDIUM 12, LOW 7 (1.1.0)" and E:Not measured/"APKReLab's own APK, any version after 1.1.0: no self-scan number is recorded".
- **Acceptance test (numbers)**: Gradle 0 failures and 0 lint errors on the final commit; the self-scan prints the HIGH, MEDIUM and LOW counts of `dev.apkrelab` (recorded in HANDOFF; HIGH = 0, and if HIGH > 0 each card is read in the smali before the release); `CHANGELOG.md` has 0 lines that contain a claim without a number; 3 of 3 CI checks pass on the merged head.
- **Failure modes**: a CI check fails on the merge head only; the self-scan shows HIGH > 0 (the card is read; if it is a true positive in APKReLab's own code the release waits for the fix).
- **Estimate**: 3 hours.

Total: 19.5 hours (Item 6 counts 2 of them; the owner's device time is extra). Order: 1, then 2, 3 and 4 in any order, then 5 (it scans the build that results from Items 3 and 4 and takes no code change after the selection commit), then 7; Item 6 follows the build of Item 7.

### Out of scope for 3.0.0
- Engine changes aimed at the cases C01, C04, C05, C08, C12 and C14 that do not enter MUST FIX (E:Assumed/"3a fixes C03 / C05 / C08"): the constraint forbids CVE analysis and the evidence holds no root cause for any of the six.
- Any release-note claim that a session fixes a named CVE case: no measurement supports one (E:Assumed/"3a fixes C03 / C05 / C08").
- New taint sources for WebViewClient callbacks (`WebResourceRequest.getUrl()` and similar) and a sink for the Binder reply Parcel: no evidence bullet measures them, and 3b ruled both out as rules, not bridges.
- NEXT_GEN items B2 (Parcelables across a process boundary), B3 (reflection) and B5 (taint-loss report section): no census result exists (E:Assumed), but none gates 3.0.0.
- Intent-handling rules (nested Intent forwarding, mutable PendingIntent): no evidence bullet.
- Performance work: E:Measured/device timings (groups 118 s, 20 s, 219 s) show no regression to fix.
- Hybrid frameworks (Dart, JavaScript code analysis): no evidence bullet.
- A merge of any branch without Items 1 and 2: the branches stay unmerged if Item 1 or 2 fails.

### Version decision tree
Names: RC = the Item 1 build after Items 3 and 4.
1. Item 1 fails (Gradle not 997 tests / 0 failures, or the Recall line differs): no release; the branches stay as they are; report which gate failed.
2. Item 2 shows recall < 6 of 13 or drops < 5 of 6: switch off the switch of the branch whose pairing changed the case (3a: `noParcelRoundTrip`, `noSetterCapture`, `noSinkKindValidation`; 3b: `noWebViewClientEdges`, `noResultCallbackEdges`, `noBinderHosting`), repeat Item 2; if recall is 6 of 13 or more after switching, the release is **2.1.1** (sessions 1 and 2 plus the branches that still pass); if it is still below 6 of 13 with all engine switches off, there is no release.
3. Item 3 not decided or `fp`: `SETTER_CAPTURE` off; the release continues with that switch off (this alone does not change the version).
4. Item 5 (the version gate), after Items 1 to 4 passed:
   - tests 1 to 4 of Item 5 all hold -> **3.0.0**;
   - tests 1, 3 and 4 hold and the judged MUST FIX count is below 4 (result "n/a") -> **2.2.0**, with "not proven blind: n/a (judged MUST FIX cards: N)" in the notes;
   - FP among judged MUST FIX cards >= 1 or paired `fp` >= 1: attribute it to a switch by repeating the scan of that app with each switch off in turn; switch off the responsible one(s), rerun Item 5 once on the 12 apps (the selection stays the same, no new selection); if the rerun has FP = 0 and paired `fp` = 0 -> **2.2.0** with that switch off; if the cause cannot be attributed or the rerun still shows FP >= 1 -> **2.1.1** with all six engine switches off (sessions 1 and 2 only: ReportDiff and tests);
   - test 1 fails (a name in the touched list, or a hash mismatch) -> Item 5 is repeated with a new seed; the version is not decided until it holds.
5. Item 6 never changes the version.
6. The version in `app/build.gradle.kts` is set only after step 4, and the notes state which of tests 1 to 4 held.

### Decisions requested from the owner before execution
- The Item 5 thresholds (>= 4 judged MUST FIX cards, FP = 0, paired fp = 0, 12 apps) are proposals; they are stricter than any past round passed (round 1 had 2 of 2 false).
- `versionCode` for the release: 240 was named earlier; 3.0.0 / 2.2.0 / 2.1.1 each need one.
- Item 6 needs the owner to scan three apps on the phone; if the owner prefers not to, it is dropped and the gap stays open in the notes.
