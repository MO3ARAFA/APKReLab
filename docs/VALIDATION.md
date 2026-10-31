# Blind validation (maturity protocol, phase 4)

Every number in this file comes from apps that no QA round, recall kit or tuning step has ever touched. They are measured ONCE, with the scanner as committed
before the selection, and no rule is changed afterwards because of them. The tuning sets are `tools/benchmark/qa_120.md` and the self_check apps (Sieve aside).

## Protocol (frozen in this commit, before any blind APK was downloaded)
1. **Scanner**: the sources of this commit's parent (phase 3, 9d3246f), run with `tools/sandbox/SandboxScan.kt` (the app's Kotlin pipeline without the UI: no device
   reach pass for rule cards, no strings overlay, no AI triage). The phase 4 commit adds only this file and the selection script, no scanner code.
2. **Selection** (`tools/benchmark/blind_select.py`): the F-Droid index `index-v1.jar` downloaded on 2026-10-24 (SHA-256
   `dd2a1f626629fa866f576efa0fa1ce1a489f9ecd5b3830d605928c1cb9e9cf03`); candidates = every package not in the exclusion list (every package-like name written in the
   repository, `./private`, the recall kit's APK and smali folders; the list stays in `./private` because it holds company package names, its SHA-256 is recorded below)
   whose latest APK is 3-40 MB; sorted by name, shuffled with seed 20261031, the first three taken as they come. An app is replaced only if its download fails.
3. **Integrity**: each APK is downloaded from `https://f-droid.org/repo/<apkName>`; its SHA-256 must equal the index's hash, or it is not scanned.
4. **One scan**: each APK is scanned once. Before a report is opened, `sha256sum <report-file> > <report-file>.sha256` is run and the hash is recorded here.
5. **Blind top-3 accuracy**: the Verdict's MUST FIX cards (at most three per app) are each judged against the code of the APK: TP (the card's source, sink and
   reachability hold in the smali / manifest), FP (one of them does not, with the quote), or NOT JUDGED (cannot be decided from the code). Accuracy = TP / judged.
   An app whose MUST FIX is empty contributes nothing (it is reported as "empty", not as a hit). Because a strict gate can leave every MUST FIX empty, a SECONDARY
   number is reported and labelled as such: the same judgement on each app's three highest-priority HIGH+ cards (FindingScore order, ties by card number).
6. Reports, decoded classes and APKs stay in `./private/blind/` (not committed); this file carries the hashes so the reports can be checked later.

## Results (2026-10-31, scanner 9d3246f, protocol f78f2b6)
Exclusion list (`./private/blind/excluded_packages.txt`, 4,734 names) SHA-256 `a9546b7dfb580a265d286651e3c9002b849e8a673ee220f1cfc34aff0b9aad34`; 2,950 candidates; seed 20261031.
All three APKs matched the index hash; none was replaced.

| app (package, versionName) | APK SHA-256 | report SHA-256 (`<pkg>_<code>.report.md`, hashed before it was opened) | classes | HIGH+ cards | MUST FIX |
|---|---|---|---|---|---|
| Voice+ `com.github.mistermo_vibecode.voiceplus` 1.29 | b047541001224537d184c07e98f3eb40837e7d35534ea1a3cf15465b9c553cf9 | f09928c397aad14facea8d11ed112cabe261a5919279f937f6b029e82bea3e7a | 6,679 | 0 | empty |
| Chaka viewer `net.timelegend.chaka.viewer.app` 1.27.1a.28 | 6f68135b6ba3635d9991a42fe9b9ef792255438fcb33ddf8714e11a3be89f977 | 7275099bd5b5c4e8fc8d745d71a3cab080d7d7165ff5494411db8fbdaa83274d | 1,357 | 2 | #10, #11 |
| Bagatur Chess `com.bagaturchess` 1.3.8 | 9b3685e58c0f57cc310ac61261a286ec9385a3f8ac18b059fb8c74ac1fb8b460 | c55755218de5340c352f3009f767a47793c2b06b03e90970ab098da4c279ba35 | 1,157 | 0 | empty |

### Judgements (every MUST FIX card)
- **Chaka #10 FP** "Untrusted input is used as a file path" (SSA: Intent.getData() -> field `b1.j.b` -> `FileInputStream.<init>` in `j.b()`). The entry holds: DocumentActivity is `exported="true"` with a VIEW / BROWSABLE filter. The sink does not: before the value is stored, DocumentActivity runs `const-string v0, "[^a-zA-Z0-9\\._]+"` / `const-string v2, "_"` / `invoke-virtual {v1, v0, v2}, Ljava/lang/String;->replaceAll(...)` / `iput-object v0, p1, Lb1/j;->b:Ljava/lang/String;`, and `j.b()` opens `new File(getExternalFilesDir("bk"), j.b)`. With every `/` replaced, the name is one segment inside `bk/`; the only escapes, `.` and `..`, name directories, which FileInputStream / FileOutputStream cannot open. The card's "with ../ it leaves the intended folder" is false for this code.
- **Chaka #11 FP**, same value and the same `File(getExternalFilesDir("bk"), j.b)` construction, reaching `FileOutputStream.<init>` in `j.d()` (entry DocumentActivity.onPause).

### Blind top-3 accuracy
- **MUST FIX: 0 / 2 judged cards are TP (0%)**, from one app; the other two apps had an empty MUST FIX (and no HIGH+ card at all), which counts as neither a hit nor a miss.
- Secondary (three highest-priority HIGH+ cards per app): the same two cards, 0 / 2. No other app had a HIGH+ card.
- What this says, plainly: on these three untouched apps the scanner raised two HIGH cards and both were false; the Verdict put both in MUST FIX. The cause is one gap: a `replaceAll` with a character allow-list that drops `/` is not recognised as a path sanitizer. Per the protocol no rule is changed because of this result; the gap is recorded in NEXT_GEN_ROADMAP.md and a fix must be measured on the NEXT blind set, not on these apps (they are tuning apps from now on).
- Not measured here: recall (the apps have no expected list, so a missed issue cannot be counted); MEDIUM and lower cards (not judged); anything a device run would add (reach labels on rule cards).

### After round 1 (tuning, NOT a blind number)
Chaka viewer is a tuning app from here on. Phase 3.5 (TaintIr PATH_STRIP_SANITIZER) treats a replace whose constant pattern removes every '/' as clean for
file sinks only; re-scanned with it, Chaka viewer has 0 HIGH+ cards and an empty MUST FIX (2 HIGH with the switch off: ./private/qa120/chaka_p35_on.md / _off.md).
This is a fix measured on the app that showed the gap, so it says nothing about blind accuracy; round 2 below is the next blind number.

## Blind Holdout Round 2: protocol (frozen in this commit, before any round 2 APK was downloaded)
- Scanner: this commit's parent, beef59e (phase 3.5), built fresh, run with SandboxScan exactly as in round 1. This commit changes only this file and the selection script (new optional arguments; round 1's defaults reproduce round 1's three apps).
- Selection: the same F-Droid index (SHA-256 dd2a1f62...cf03); exclusion list `./private/blind/excluded_packages_round2.txt` (4,775 names: round 1's list plus every package named since, round 1's three apps and Paperless included), SHA-256 `aadc5907f122e763c181660ba66a29c48a1250901ecb67bdf77972f975c6fdf5`; latest APK 5-40 MB and declaring android.permission.INTERNET (apps that talk to a network: the owner asked for apps likely to produce cards; this is the only filter, read from the index before any download); seed **20261101**; the first three, taken as they come.
- Integrity, one scan, report hashes before reading, judgement and accuracy: exactly as in round 1 (steps 3 to 5 above). Round 1's results above are not edited.

## Blind Holdout Round 2: results (2026-10-31, scanner beef59e, protocol 83a5fb9)
1,258 candidates; all three APKs matched the index hash; none was replaced.

| app (package, versionName) | APK SHA-256 | report SHA-256 (hashed before it was opened) | classes | cards (LOW / MEDIUM / HIGH+) | MUST FIX |
|---|---|---|---|---|---|
| ArchForums `com.kanedias.archforums` 1.2.8 | 513bc911a1e3904cf3a54fa04fbf630f1ab69bcbc7e188529f1e420460a5c9f6 | efaa76688ac5e9794d1186cff9430f60bd72bf0e80f50ff9561682650f4b0ec7 | 7,195 | 4 / 5 / 0 | empty |
| QED `eu.jonahbauer.qed.fdroid` 3.1.4+fdroid | 70044b88ef0cb1650560d657848bf9fa6a470b8854bcf1c72336eb4455e16399 | 2a00c562aa803d5615cf9aa75098f0ad4b1048cd19fddb15c8f06fca33aea663 | 6,037 | 13 / 6 / 0 | empty |
| NFC Radio `com.trapplab.nfc_radio` 1.0.0-fdroid | ea5e877b64972a10294654390f7a5c5044527ccebb722f7edaef74a499fc36a4 | 82abab7e662f784eba3bf4f4990019c30ee9b526bdaf5cc914954e85fe67066e | 724 | 10 / 5 / 0 | empty |

### Blind top-3 accuracy, round 2
- **MUST FIX: no card to judge (n/a).** All three apps had an empty MUST FIX and no HIGH+ card, so round 2 gives no accuracy number; it is not a 100%.
- Secondary (three highest-priority HIGH+ cards per app): none, n/a.
- What it does say: on three more untouched network apps the scanner raised no HIGH card and put nothing in MUST FIX, so it did not repeat round 1's two false MUST FIX cards. Whether
  it MISSED a real issue is not measured: these apps have no expected list (recall unknown), and MEDIUM / LOW cards were not judged.
- Not measured: whether the phase 3.5 sanitizer fired on these apps (the protocol allows one scan; no second run with the switch off was made).
- Combined over both rounds: 2 MUST FIX cards judged, 0 TP. Six apps, two cards: too few to state an accuracy with any confidence; the next round should pick apps with known
  attack surface (an index filter on exported providers is not possible; a larger round is).

## Real-CVE benchmark (2.0.0 step 1): THE primary product metric
Protocol, cases, hashes and scorer frozen in c237701 before any scan (`tools/benchmark/cve/PROTOCOL.md`, `cases.json`, `score.py`): 15 published advisories
(CVE / GHSA / GHSL) in open-source Android apps, the vulnerable and the fixed release of each from f-droid.org (SHA-256 from the F-Droid index), 14 in scope.
Reports stay in `./private/cve/` (not tracked); the scores are `tools/benchmark/cve/runs/*.txt`.

### Run 1, blind (scanner 15e3d6d, before any change)
Automatic score: DETECTED 2, NOT-DIFFERENT 8, MISSED 4 (`runs/run1_blind_15e3d6d.txt`). Every matching card was then read (CLAUDE.md rule 3):
| case | auto | read | note |
|---|---|---|---|
| C02 Home Assistant MyActivity WebView | NOT-DIFFERENT | found | HIGH Intent.getData() -> WebView.loadUrl in MyActivity, the advisory's flow; still HIGH in the fixed build (its check is only "validation-like") |
| C06 Nextcloud FileContentProvider SQLi | NOT-DIFFERENT | found | HIGH provider parameter -> SQLiteDatabase.delete / update / SQLiteQueryBuilder.query |
| C07 Nextcloud DiskLru provider | DETECTED | detected | readPermission without writePermission, gone in 3.17.1 |
| C10 Element intent redirection | NOT-DIFFERENT | found | HIGH getParcelableExtra -> startActivity in MainActivity.startIntentAndFinish; the 1.6.12 allow-list is not recognised |
| C11 Wikipedia wikipedia:// | DETECTED | detected | custom scheme without host (the advisory's root cause), gone in 50585 |
| C12 Wikipedia SingleWebViewActivity | NOT-DIFFERENT | partial | right sink (extra -> loadUrl) but "no path from an exported component": the PageActivity forward is not linked |
| C14 OsmAnd AIDL service | NOT-DIFFERENT | found | exported OsmandAidlServiceV2 without a permission (CWE-926 of the advisory); the code-level caller check of the fix is not seen |
| C04 Tasks, C08 Nextcloud internal files, C13 OsmAnd open-gpx | NOT-DIFFERENT | missed | the matching card is another flow (onActivityResult / SharedPreferences sources) |
| C01 Talk, C03 Omni-Notes, C05 ownCloud, C09 News | MISSED | missed | |

**Blind result: the vulnerable code was reported in 7 of 14 in-scope cases (6 exact, 1 partial); the fix was visible (card gone or lower) in 2 of 14.**

### Run 2, after the step-2 fixes (scanner fb7850a; these 14 cases are now a TUNING set, not blind)
Automatic score: DETECTED 5, NOT-DIFFERENT 8, MISSED 1 (`runs/run2_after_fixes_fb7850a.txt`). Read: C09 (reflected setResult(getIntent())) detected; C06 detected
(the fixed build's verify* calls lower the cards to MEDIUM); C05 found (Intent stream list -> UriUploader field -> CopyAndUploadContentUrisTask openInputStream /
FileOutputStream), not differentiated; C01 partial (Talk: Intent.getData() through WorkManager Data to openInputStream in UploadAndShareFilesWorker; the
traversal write in copyFileToCache itself is still not reported), counted as found, not as detected. Still missed: C03, C04, C08, C13.
Reported in 11 of 14 (9 exact, 2 partial); fix visible in 4 of 14 (C06, C07, C09, C11).
Regression checks of the same build: self_check identical to the baseline (Recall line unchanged, SELF-CHECK PASSED); MeasureBig flow sets of K-9 (0), NewPipe (1),
KeePassDX (9), Paperless (1), Chaka (1), Axis Pay (15) identical to pillar 1 (Axis Pay: 2 LOW flows show a SharedPreferences source label instead of Intent.getExtras()).
NOT measured: any device run of these builds; apps outside these 14 cases and the 6 corpus apps.
