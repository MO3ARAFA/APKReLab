# Vendor credential formats (0.89.0)

`app/src/main/assets/secret_formats.json` = 206 token formats from the **gitleaks** rule set (https://github.com/gitleaks/gitleaks, **MIT license**, (c) Zachary Rice and contributors):
final regexes, keywords, minimum entropy, stop words, secretGroup, taken from `config/gitleaks.toml`. Regenerate: `python3 tools/secrets/gen_secret_formats.py <gitleaks checkout> <out> <samples out>`.
Not taken: generic key=value rules (our own entropy detector needs positive evidence), private keys / JWT (own rules), rules that apply to a file NAME (nuget.config ...), and a few noisy shapes.

Validation (`SecretFormatsTest`): gitleaks keeps true / false positives for its own rules; the ones written as literals (not built with its random generators) are extracted into
`app/src/test/resources/secret_samples.json`: **196 of 201 literal true positives detected, 0 of 169 literal false positives hit**. The 5 "missed" are fragments the extractor took for samples
(`webhook.office.com`, `hooks.slack.com`, a regex `s\.[A-Za-z]{24}` ...), not tokens. Rules whose samples are generated are not covered by this test.
Real-world check (`ScanStrings.kt` + `dexstrings.py`): 3,076,424 strings of 37 real APKs (dex string tables and text resources): **0 hits** (also 0 false positives; these are open-source apps,
which do not ship vendor tokens: the format library finds nothing there and costs 8 seconds for all of it).
The rule `secrets-vendor-tokens` (ScanRulesLegacy.kt) runs the formats on the string constants of each class; a value that is a template (`XXXXXXXX`, `your_...`, `fake`, `example`) is not reported.
