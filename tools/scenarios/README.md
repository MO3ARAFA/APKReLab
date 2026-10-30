# Attack scenarios (0.93.0)

`AttackScenarios.kt` turns findings into chains: attacker, entry point, likelihood (and why), chain of findings, impact, an adb line to try on the owner's OWN build, the fix and the MASVS controls. Deterministic (no model),
static inference only (nothing is run). A scenario needs the findings that make the chain real; the report section says that no scenario does not mean there is none.

Patterns: (1) an attacker-chosen URL in a WebView whose JavaScript bridge is in the SAME class (an inner class counts); (1b) a WebView with file access, in an exported activity or behind an exported entry (call path);
(2) certificate validation disabled in app code; (3) debuggable build or allowBackup together with DATA AT REST (plain SharedPreferences, unencrypted SQLite, world-readable file, external storage);
(4) an exported content provider, no permission, with a SQL injection or a path traversal finding.
Likelihood: HIGH when the component is exported without a permission, MEDIUM when the sink is reached from an exported component through the app's own code (the finding's call path), otherwise the chain is
dropped (a finding already says it). Severity is the finding's, never raised.

## What reading the scenarios of 16 real apps changed (the unit tests did not find any of these)
Markor: a WebView sink in one class and an unrelated editor bridge in another made a "scenario": the bridge must be in the sink's class. OVAA / Vuldroid: a WebView sink with file access but no bridge had no scenario:
pattern 1b (OVAA's WebViewActivity is NOT exported, read from its manifest entry: it is reached through an exported deep-link activity, MEDIUM). Breezy: three JWTs hard-coded in the code made a "backup" scenario: a
secret in the code is in the APK, a backup adds nothing: data at rest only. Session / Read You: the traffic scenario for a trust-all client is misleading when the payload is protected above TLS: the text now says so
(it is a caveat, not a filter: Session still gets a CRITICAL scenario and I judged its client by design, "probably", unverified).
Last run (9 apps): OVAA 3 scenarios (debuggable + plain SharedPreferences; provider openFile path; WebView file access behind an exported entry), Vuldroid 1, Sieve 3, PIVAA 2, InsecureShop 1, Session 1, Read You 1,
Breezy 0, Markor 0. Read in full: OVAA, Breezy, Markor, Vuldroid, Sieve (traffic); NOT read in full: the debuggable chains of InsecureShop, PIVAA and Sieve.
Limits: severity / likelihood rules are mine, not measured; no ground truth except the known vulnerable apps; not run on any app of the owner (no APK); not in the SARIF export; the agent has no tool for it yet.

## 0.97.0: an exported component feeds attacker data to a dangerous operation (pattern 5)
Taint flows of CRITICAL / HIGH severity that end in a shell command, an SQL statement, a file path, loaded code, a deserialization, an intent redirection, a reflective call by name, a connection to a chosen server,
or a file / content URI the app opens (WebView sinks keep patterns 1 / 1b). The component is the one that holds the SOURCE of the flow. Exported without a permission: likelihood HIGH and an adb line built from what the code
reads (`--es` / `--ei` / `--ez` / `--el` for the extras by their real names; every query parameter on a deep link, e.g. InjuredAndroid's RCE: `flag13://rce/?binary=..&combined=..&param=..`; `am startservice`; `am broadcast -a <action>`;
Parcelable / Serializable extras cannot be built by adb: the line says so instead of inventing an `--es`; a provider gets a benign `content query` probe, with a single quote in `--where` for SQL). Not exported but reached through the call path:
likelihood MEDIUM, with the writer of the extra named and the chain dropped when every writer puts a constant. A Frida snippet hooks the source method and the sink API of the kind.
Read on real apps (sandbox, no call path, so "Entry: the code in X" for internal chains; the device report has the real entry): InjuredAndroid 2 (RCE CRITICAL; redirection), Vuldroid 2 (command injection through `command`; redirection), PIVAA 2 (the exported receiver with its real action and its two extras; SQL), Sieve 1
(provider SQL probe), OVAA 1 (exported service, file path), InsecureShop 1 (redirection); clean apps: Markor 2 (a text editor that opens the file it is sent: by design, rated HIGH by the flow rule), none in K-9 Mail, Organic Maps, NetGuard, Session, DAVx5, Orbot, Read You, andOTP, Breezy or the wallet app (which proves only that the scanner sees no such chain: 90% of its classes are renamed and strings are encrypted).
