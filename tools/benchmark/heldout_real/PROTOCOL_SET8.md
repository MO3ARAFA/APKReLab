# Real-app held-out set 8 (frozen 2026-10-15, BEFORE the first scan, tool version 0.83.0, no change after freezing)

Purpose: the first blind measurement of 0.83.0 (weak flows by structure, repackaged libraries by markers). Sets 1-7 are tuning sets.
Never scanned by APKReLab before (not in the 15-app study, sets 1-7, the vulnerable-app benchmarks, JustMarkets). Java / Kotlin apps.
| app | source | sha256 |
|---|---|---|
| Quillpad 1.5.15 (notes: Markdown, backups / import / export, reminders, share targets, file access) | github.com/quillpad/quillpad releases (latest) | e5ce02074e76c92d45370e0e0bb60ff80f6c8e0f5ff7eccbd0aab889b03561a1 |
| OpenTracks 4.22.0 playstore variant (GPS track recorder: exported ContentProvider / Dashboard API for other apps, share / import of GPX / KML / FIT) | github.com/OpenTracksApp/OpenTracks releases (latest) | 8337e8099710deadb4b2843815d97bc222cf4258eccc3f18363c61f6186db34c |
| Orbot 17.9.7-RC-1 fullperm arm64-v8a (Tor VPN: VpnService, exported components, config files, a native Tor core) | github.com/guardianproject/orbot-android releases (latest; a release CANDIDATE) | 97d3a0a5181394e99fbabdda9fefb73027657cac4c7400c64ebf146a7778860b |
Chosen for shapes not yet covered: a notes app with import / export, an IPC provider for other apps, a VPN / network core. Orbot's core is native (Tor): the Java side is the UI and the service glue, and the native-code card should appear.
Scoring: as PROTOCOL_SET4.md (precision by card and by distinct issue; TP / TP-1CLICK / TP-low / BY-DESIGN / FP; library-scope cards apart; MEDIUM only as a sample). Scanner: `SandboxScanReach.kt` (reach-aware). First run frozen in runs/.

## FIRST RUN (frozen), 0.83.0 reach-aware sandbox
Reports: `runs/quillpad-0.83.0-sandbox-FIRST.md`, `runs/opentracks-0.83.0-sandbox-FIRST.md`, `runs/orbot-0.83.0-sandbox-FIRST.md`.
Cards: Quillpad 28 (1 HIGH), OpenTracks 21 (2 HIGH), Orbot 16 (2 HIGH). Every HIGH read in the smali / manifest.

| app | card | verdict | why |
|---|---|---|---|
| Quillpad | "Insecure TLS protocol requested: SSL" (`eq2`, OBF) | **TP-low, right place / wrong reason** | `eq2.a()` builds an OkHttp client with `SSLContext.getInstance("SSL")` and a custom X509TrustManager `gq2` whose `checkServerTrusted` does nothing (a trust-all client; Authorization / Cookie headers are redacted in its logging interceptor). On Android "SSL" is an alias of the default TLS context, so the card's reason (SSLv3) is overstated, but the spot is real. Whether that client is only used for an opt-in (self-signed server) option was not resolved |
| Quillpad | (NOT reported) trust-all TrustManager `gq2` | **FALSE NEGATIVE** | the `tls-trustmanager` rule did not fire: R8 inlines Kotlin's null check as `p1.getClass()` calls BEFORE `return-void`, so the "empty body" pattern no longer matches. Same blind spot class as the 0.74.0 `throws` annotation bug |
| OpenTracks | "ContentProvider.query() may build SQL by string concatenation" (`CustomContentProvider`) | FP | the provider (authorities `...playstore.content`) is `exported=false`; the rule is text-only and does not look at export |
| OpenTracks | Zip Slip, `KMZTrackImporter.readAndSaveImageFile` | FP | the entry name goes through `importNameForFilename`: `"images/" + name.substring(name.lastIndexOf('/') + 1)` with `/` replaced by `-`: a basename, no traversal (the engine models substring / replace as taint-preserving) |
| Orbot | 2 x "Untrusted input reaches an SQL statement" (`OnionServiceContentProvider.delete`, `ClientAuthContentProvider.delete`) | FP | both providers are `exported=false`, no grantUriPermissions: the "ContentProvider method parameter" source is treated as attacker input whatever the manifest says |

**By card: 1 TP-low / 5 = 20%; by distinct issue: 1 / 4 = 25%.** Plus 1 false negative found by reading.
Running total, first runs on unseen apps sets 2-8: 16 TP cards / 53 judged = 30% by card (set 8 = the first run on 0.83.0).
New FP / FN families: (1) provider source / provider SQL rule ignore the provider's exported flag (3 of 5 cards), (2) a sanitizer that is a basename idiom (substring after lastIndexOf('/')) is not recognised, (3) false negative: trust-all TrustManager with R8-inlined null checks in `checkServerTrusted`.


## After the fixes: 0.84.0 (set 8 is a TUNING set from here; these numbers are NOT blind)
HIGH/CRIT, first run 0.83.0 -> 0.84.0 (reach-aware sandbox): Quillpad 1 -> 2 (the real trust-all `gq2` is now reported, as HIGH: CRITICAL lowered one level by the "renamed, likely third-party" rule because `gq2` is a tiny class with no app references; plus the "SSL" card), OpenTracks 2 -> 0 (provider SQL card: the base class of an unexported declared provider; KMZ Zip Slip: `importNameForFilename` replaces `File.separatorChar` and takes a basename, MEDIUM left), Orbot 2 -> 0 (providers exported=false).
The false negative is closed; the two lowered families (provider flows in providers the manifest does not export, file names that lose their separators) are structural, not name lists.
