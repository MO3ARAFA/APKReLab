# APK ReLab benchmark

Checks an exported report (Markdown) against the KNOWN vulnerabilities of a test app, so every version can be compared with the
previous one instead of reading reports by eye.

    python3 tools/benchmark/bench.py oversecured_ovaa-report.md --save ovaa_0.50.1.json
    python3 tools/benchmark/bench.py oversecured_ovaa-report.md --baseline ovaa_0.50.1.json   # next version: prints regressions

Works with plain python3 (also in Termux). The expected list is picked by the package name in the report header:
`expected/<package>.json`. Entry fields: `id`, `vuln`, optional `rule` (string or list), `title_any`, `class` (substring of the
location), `min_severity`, `reach` (true = the call graph must label it reachable), `known_gap` (an accepted MISS), `hint`.

Results: FOUND, FOUND-NOREACH (found but not traced as reachable), FOUND-AI-FP (found but the AI triage called it a false
positive: read both sides), MISS, KNOWN GAP. The tool also lists HIGH/CRITICAL code findings that match no expected entry.
Exit code 1 on a MISS or a regression.

Read the numbers honestly:
- OVAA is the app the scanner was tuned on, so 19/19 there is a regression guard, not proof of accuracy.
- The lists are written from the public descriptions of these test apps. A wrong expected entry is a bug in the list, fix the list.
- To add an app: scan it, write `expected/<package>.json`, and keep real misses as `known_gap` so they stay visible.

## Taint benchmark (0.56.0): `taint_bench.py`

Scores the "Taint on SSA" export (.txt, Report chip) per flow, with the evidence level in the bucket name:

    python3 tools/benchmark/taint_bench.py b3nac_injuredandroid-taint.txt com_insecureshop-taint.txt --save taint_0.56.0.json
    python3 tools/benchmark/taint_bench.py *.txt --baseline taint_0.56.0.json      # regressions, exit code 1

Buckets: TP-verified (owner read the smali) / TP-documented (public write-up, not checked) / LIBRARY (third-party code, outside
precision) / BENIGN (reviewed, not a weakness) / UNREVIEWED (printed as a REVIEW SHEET: class, method, instruction to open in the smali).
Lists live in `expected_taint/<app>.json`. Rules that keep the numbers honest:
- Recall counts only entries marked `"independent": true`: written from the app's own vulnerability list or from reading the code BEFORE
  looking at what the tool reported. The first lists were written after seeing the reports, so recall prints `n/a`, not 100%.
- Precision is over REVIEWED flows only and always prints n and how many flows are still UNREVIEWED.
- To grow it: read the smali of each REVIEW SHEET line, add it as `verified` (TP) or `benign`; then, for recall, write the app's known
  data-flow weaknesses first and only then run the tool, and keep real misses as `known_gap`.
