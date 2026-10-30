# Real-app held-out set 5 (frozen 2026-10-13, BEFORE the first scan, tool version 0.79.0, SAME version as set 4, no change in between)

Purpose: check whether set 4's precision (3/4 by card) holds on more unseen apps with the same build.
Never scanned by APKReLab before. Java / Kotlin apps.
| app | source | sha256 |
|---|---|---|
| Infinity for Reddit 8.3.3 "Infinity+" (OAuth login, account tokens, WebView, deep links) | github.com/Docile-Alligator/Infinity-For-Reddit releases (latest) | 0cb9980c8590c86d28041280dc9fb36f70f8ab14b980b21e356f24bbea48c015 |
| LibreTube 32.1 (YouTube front-end: streams, downloads, deep links) | github.com/libre-tube/LibreTube releases (latest) | 437dbb55540ac573f864938fc3595f69fc13df5d568b237aded9935559fe1353 |
| Read You 0.16.2 (RSS reader with Fever / FreshRSS / Google Reader accounts) | github.com/ReadYouApp/ReadYou releases (latest) | a27f6da6961f2d5cd27b515349dc71844a0d20cfacc38b5fc398152fa034ce5e |

Scoring as PROTOCOL.md / SET4 (precision by card and by distinct issue; TP / TP-1CLICK / BY-DESIGN / FP; first run frozen in runs/).

## FIRST RUN (frozen), 0.79.0 sandbox (same build as set 4)
Reports: `runs/infinity-0.79.0-sandbox-FIRST.md`, `runs/libretube-0.79.0-sandbox-FIRST.md`, `runs/readyou-0.79.0-sandbox-FIRST.md`.
Cards: Infinity 71 (5 HIGH), LibreTube 18 (2 HIGH), Read You 85 (1 CRITICAL, 3 HIGH). No library card among the HIGH.

| app | card | verdict | why |
|---|---|---|---|
| Infinity | Cleartext traffic allowed | BY-DESIGN | media / link hosts over HTTP |
| Infinity | Intent -> WebView.loadUrl, WebViewActivity (2 cards: in-class + SSA, same issue) | **TP-low** | WebViewActivity is not exported, but the exported `LinkResolverActivity` (explicit Intents ignore its reddit-host filter) forwards the caller's URI to it (`n1`) when the user's link setting is "in-app": the caller chooses the page shown in the app's own WebView (JavaScript on, no JS bridge, no file access): phishing in the app's chrome |
| Infinity | Intent.getData -> File.delete, DownloadedMediaDeleteActionBroadcastReceiver (2 cards, same issue) | FP | the receiver is NOT exported (no intent-filter, no exported attribute): only the app's own notification action reaches it |
| LibreTube | NSC cleartext / user CAs (2) | BY-DESIGN | user-chosen (self-hosted) Piped instances |
| Read You | Cleartext traffic allowed | BY-DESIGN | RSS feeds over HTTP |
| Read You | CRITICAL trust-all TrustManager (OkHttpClientModuleKt.setupSsl) | BY-DESIGN | installed only when the account's "ignore TLS errors" option (boolean parameter) is on: opt-in for self-hosted servers |
| Read You | Hardcoded sensitive field `secret` (DESUtils) | **TP** | account secrets are "encrypted" with DES and a key compiled into the APK (`mJn':4Nbk};AMV...`): anyone with the APK and the database can decrypt them |
| Read You | Hardcoded sensitive field `INJECTION_TOKEN` | FP | the value is the path marker "/android_asset_font/" |

**Precision by card: 3 TP / 6 = 50%; by distinct issue: 2 (DES key, WebView redirect) / 4 = 50%.** 5 BY-DESIGN.

### Sets 4 + 5 together (both 0.79.0, both unseen): by card 6 / 10 = 60%; by distinct issue 3 / 6 = 50%.
FP families left: (1) the in-class taint rule does not know a receiver / activity is not exported (and the SSA card of the same issue
doubles it), (2) taint through R8-renamed classes outside the default package (Ivy, Breezy), (3) a path-like literal taken for a secret.
Severity notes: a trust-all TrustManager behind an opt-in flag and NSC user-CA trust for self-hosted servers are reported CRITICAL / HIGH;
they are true observations but BY-DESIGN in 5 of the 18 cards of sets 4-5.


## After the fixes: 0.80.0 (sets 4 and 5 are TUNING apps from here)
| app | HIGH/CRIT 0.79.0 -> 0.80.0 | left |
|---|---|---|
| Infinity | 5 -> 2 | cleartext (BY-DESIGN), WebView redirect (TP-low, one card now) |
| Read You | 4 -> 3 | cleartext (BY-DESIGN), opt-in trust-all (BY-DESIGN, still CRITICAL), DES key (TP) |
| Breezy | 4 -> 4 | 3 JWT (TP), the objectbox cleanup (FP: through an R8-renamed iterator's METHOD, not a field, so the new rule does not cover it) |
| Catima / Mihon / LibreTube | 1 / 2 / 2 -> same | BY-DESIGN |
Left on sets 4+5: 5 TP cards, 1 FP card, 8 BY-DESIGN. Not fixed: severity of opt-in / self-hosted configurations (8 BY-DESIGN HIGH/CRIT cards).
