# Real-app held-out set 10 (frozen 2026-10-16, BEFORE the first scan, tool version 0.85.1, no change after freezing)

Purpose: first blind measurement after the 0.85.0 / 0.85.1 changes (installed obfuscated TLS classes, Axml fallback names, full framework attribute table). Sets 1-8 are tuning sets; set 9 is closed (owner, 2026-10-17 entry in HANDOFF).
Never scanned by APKReLab before (not in the 15-app study, sets 1-9, the vulnerable-app benchmarks, JustMarkets). Java / Kotlin apps.
| app | source | sha256 |
|---|---|---|
| AdAway 6.1.4 (ad blocker: hosts file / VPN mode, root, exported components, downloads of host lists) | github.com/AdAway/AdAway releases (v6.1.4) | 09f8e1528a53e5ffad59e57a174e90d4e10c5092bf4f6a60ab6594f046614417 |
| Nextcloud Notes 35.0.0 (sync client: account / SSO, content provider for notes, Markdown, network to a user-chosen server) | github.com/nextcloud/notes-android releases (35.0.0) | 3cf73e0906ace765332b67748a11acb2b733706fdda1bac537116e7fd99ce75e |
| Feeder 2.24.0 fdroid (RSS reader: OPML import / export, WebView article view, background sync, network) | github.com/spacecowboy/Feeder releases (2.24.0) | 7c2cbcead9734ec12722ceccea3dedfabd4664b5a1bfc87e0c0a896642a3bf23 |
Chosen for shapes not yet covered: a root / VPN network tool, a sync client against a self-hosted server, a feed reader that renders third-party HTML.
Scoring: as PROTOCOL_SET4.md (precision by card and by distinct issue; TP / TP-1CLICK / TP-low / BY-DESIGN / FP; library-scope cards apart; MEDIUM only as a sample). Scanner: `SandboxScanReach.kt` (reach-aware). First run frozen in runs/ (`*-0.85.1-sandbox-FIRST.md`).

## FIRST RUN (frozen), 0.85.1 reach-aware sandbox
Reports: `runs/adaway-0.85.1-sandbox-FIRST.md`, `runs/feeder-0.85.1-sandbox-FIRST.md`, `runs/ncnotes-0.85.1-sandbox-FIRST.md` (sha256 612ccb9c..., e99d9fba..., cef5646e...). Sandbox: kotlinc 2.3.21, JDK 21, apktool 2.10.0; Kotlin 147/147 and `ir` 281/281 re-run here before the scan.
Cards: AdAway 10 listed (0 HIGH, 3 MEDIUM), Feeder 52 (1 CRITICAL, 1 HIGH), Nextcloud Notes 58 (4 HIGH). Every HIGH / CRITICAL read in the smali.

| app | card | verdict | why |
|---|---|---|---|
| Feeder | "OpenAI API key embedded" (`ComposableSingletons$OpenAISectionKt`) | FP | the literal is `sk-test_` + 40 `X`: a Compose preview placeholder passed to `OpenAISettings(...)` |
| Feeder | "TLS certificate validation disabled" (`OkHttpBuilderExtensionsKt$trustAllCerts$trustManager$1`) | **BY-DESIGN / dead in the app** | `JsonFeedParserKt.cachingHttpClient(..., trustAllCerts: Boolean, ...)` installs it only when the flag is true; the one app call (`FeederApplication`) passes 0 (default mask 0x1c); the only other caller is the `JsonFeedParser(File, ...)` constructor nobody calls. The rule has no notion of an opt-in flag (same family as the known "trust-all behind an opt-in flag" item, Read You) |
| Nextcloud Notes | "Hardcoded sensitive field: TOKEN_RECIPIENT_CLASS" (`Recipient`) | FP | the value is a PHP class name, `OC\\Core\\Sharing\\Recipient\\TokenShareRecipientType` |
| Nextcloud Notes | "High-entropy string near a credential-like name (x3)" (`CustomLinkKt`) | FP | Jetpack Compose source-info markers, e.g. `CC(remember):CustomLink.kt#9igjgp` |
| Nextcloud Notes | "Hardcoded sensitive field: AccessControlAllowCredentials" (`io.ktor.http.HttpHeaders`) | FP | the value is the header name `Access-Control-Allow-Credentials`; the card is also scope OBF although `io.ktor` is a plain library name |
| Nextcloud Notes | "Hardcoded sensitive field: LockToken" (`io.ktor.http.HttpHeaders`) | FP | the value is the header name `Lock-Token` |

**By card: 0 TP / 6 = 0%; by distinct issue: 0 / 5.** No false negative was looked for in this run (no expected list; MEDIUM cards were not sampled).
AdAway: 0 HIGH, its 3 MEDIUM cards (allowBackup, powerful permission, tapjacking x4) are plausible configuration findings; not judged further.
New FP families (all in the secret detectors, none in the taint engine): (1) a placeholder value made of one repeated character (`XXXX...`) is matched by the key patterns, (2) a qualified class name with `\\` separators is "secret-looking", (3) Compose compiler source-info strings `CC(...)...kt#hash` are high entropy, (4) HTTP header names (`Title-Case-Hyphen`) in a field called `...Token` / `...Credentials`, (5) `io.ktor` is missing from the library list (scope OBF).
Running total, first runs on unseen apps sets 2-8 and 10: 16 TP cards / 59 judged.
