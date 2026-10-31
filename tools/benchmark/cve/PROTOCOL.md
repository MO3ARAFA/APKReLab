# Real-CVE benchmark (2.0.0 step 1): protocol, frozen before the first scan

The primary product metric: of the published, fixed vulnerabilities in open-source Android apps that fall in APKReLab's scope,
how many does a scan of the vulnerable release report, and does the card go away in the fixed release.

## Sources (and nothing else)
- Advisories: GitHub Security Advisories / OSV (`api.osv.dev/v1/vulns/<CVE>`) for the fixed version, GitHub Security Lab (GHSL) pages for the component names.
- APKs: f-droid.org `repo/` or `archive/`, the file named in the F-Droid index; `fetch.sh` checks the SHA-256 from the index (copied into `cases.json`).
- Fix diffs (components only, to choose the anchors): the upstream fix PR or commit named in the advisory.

## The 15 cases (cases.json)
| id | CVE | app | before -> after | scope |
|---|---|---|---|---|
| C01 | CVE-2023-39957 | Nextcloud Talk | 13.0.0 -> 17.0.0 | in |
| C02 | CVE-2023-41898 | Home Assistant (minimal) | 2023.8.2 -> 2023.9.2 | in |
| C03 | CVE-2023-33188 | Omni-Notes FOSS | 6.2.6 -> 6.2.8 (fix 6.2.7 is not in F-Droid) | in |
| C04 | CVE-2022-39349 | Tasks.org | 12.7 -> 12.7.1 | in |
| C05 | CVE-2023-24804 | ownCloud | 2.21.2 -> 3.0 | in |
| C06 | CVE-2021-43863 | Nextcloud | 3.18.0 -> 3.18.1 | in |
| C07 | CVE-2021-41166 | Nextcloud | 3.17.0 -> 3.17.1 | in |
| C08 | CVE-2022-39210 | Nextcloud | 3.20.3 -> 3.21.0 | in |
| C09 | CVE-2021-41256 | Nextcloud News | 0.9.9.62 -> 0.9.9.63 | in |
| C10 | CVE-2024-26131 | Element (arm64) | 1.6.10 -> 1.6.12 | in |
| C11 | CVE-2026-65993 | Wikipedia | 50575 -> 50585 | in |
| C12 | CVE-2026-65994 | Wikipedia | 50575 -> 50585 | in |
| C13 | CVE-2026-65996 | OsmAnd (arm64) | 5.3.10 -> 5.4.4 | in |
| C14 | CVE-2026-65995 | OsmAnd (arm64) | 5.3.10 -> 5.4.4 | in |
| C15 | CVE-2026-65997 | OsmAnd (arm64) | 5.3.10 -> 5.4.4 | OUT: authorization logic (a settings import reachable from an exported activity); no rule models it outside FinTech |

Not taken: CVE-2023-23948 (ownCloud SQL injection: the advisory says it is still present in 3.0, so there is no fixed release to compare);
WordPress GHSL-2022-046 (F-Droid has no build of that era); Signal GHSL-2026-082/102 (not on F-Droid).

Version choices that are a judgement, written down: the GHSL 2026 advisories name no fixed release, only the date the maintainer confirmed the fix
(Wikipedia 2026-04-14, OsmAnd 2026-06-28). 'before' is the tested build or the last F-Droid release before that date, 'after' the first F-Droid
release added after it. OsmAnd 5.3.3 (tested) is not in F-Droid; 5.3.10 (2026-05-11) is used and assumed still vulnerable (the fix came later).

## Scoring (score.py; frozen)
Each in-scope case has `rules` (the rule ids of the matching family, `*` = prefix) and `anchors` (class or component names taken from the
advisory or the fix diff, never from our reports). A card matches when its rule is in `rules` and an anchor appears in the card text.
- DETECTED: a matching card at MEDIUM or above in 'before', and none at that severity or above in 'after'.
- NOT-DIFFERENT: a matching card at MEDIUM+ in 'before' and at the same or higher severity in 'after' (seen, but the fix is not visible).
- LOW-ONLY: matching cards in 'before' at LOW only. MISSED: no matching card.
The automatic verdict is then checked by reading the card (rule 3 of CLAUDE.md); a disagreement is written next to the number, the number is not edited.

## Run
One scan per APK with `tools/sandbox/SandboxScan.kt` built from the commit named in the results, reports in `private/cve/reports/` (not tracked),
results in `docs/VALIDATION.md`. A case scanned once is not re-run to change its verdict.
