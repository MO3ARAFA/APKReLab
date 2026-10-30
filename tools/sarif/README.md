# SARIF export and MASVS v2 mapping (0.92.0)

`SarifExport.kt` (0.51.0) already produced SARIF 2.1.0; 0.92.0 checked it and extended it. `Masvs.kt` ties every finding to a CONTROL of the OWASP MASVS v2 and prints which of the 24 controls the tool assesses.

## Checks (`validate.py`, the official schema from oasis-tcs/sarif-spec, `pip install jsonschema`)
Before the changes the exporter was already valid: 5 real apps, 709 results, 0 schema errors. After: 7 real apps (NetGuard, OVAA, InsecureShop, DAVx5, Session, FairEmail, Read You):
**1,320 results, 188 rules, 0 schema errors, 0 duplicate fingerprints, every rule has `security-severity`, every result has a region, 1,307 (99%) carry a MASVS control** (the 13 without are the
INFO summary cards of the posture and native sections, on purpose).
What was added for GitHub code scanning / DefectDojo: `security-severity` per rule (critical 9.5, high 8.0, medium 5.5, low 3.0, info 1.0), `partialFingerprints` (`apkrelab/v1`: rule + file + title + the start of
the detail with digits masked; the n-th identical finding in one class gets its own key, the first keeps the plain one), `region.startLine` (1: a smali class or a manifest has no line), the class as a
logical location, `ruleIndex`, `helpUri` (the CWE page), `fullDescription`, `defaultConfiguration.level`, MASVS control tags (`external/masvs/masvs-network-1`) and a `masvs` property; the placeholder
`informationUri` ("https://github.com/") was removed. A first fingerprint without the detail text made 15 findings of FairEmail collide; found by counting, fixed.

## MASVS
`controls` = the 24 control statements quoted from github.com/OWASP/masvs (CC BY-SA 4.0). **The rule -> control mapping is APKReLab's own judgement, not an OWASP publication**; native hardening and the
`testOnly` flag have no exact control in MASVS v2 and sit on the nearest one. A taint finding takes its controls from its sink (WebView -> PLATFORM-2, Intent -> PLATFORM-1, ...). Every rule registered in the
tool must be in the table (a test fails when a new rule is not).
The coverage section lists, per control: how many rules / posture signals assess it, the findings in the app's code (LOW and above), the worst severity, and the findings inside libraries (a separate column: a first
version counted 145 "STORAGE-1 findings" in Session, 141 of them INFO and 132 in libraries). **6 controls are not assessed by the tool at all** (AUTH-1, AUTH-2, AUTH-3, CODE-2, PRIVACY-3, PRIVACY-4): the
table says so, and says that "no findings" is not a pass.
