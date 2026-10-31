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

## Results
(filled after the scan; nothing below is edited once the reports are read except to add judgements)
