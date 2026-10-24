# Real-app set 10b (a parallel set 10 run by another session; frozen 2026-10-17, BEFORE the first scan, tool version 0.85.0 incl. the Axml fix, `SandboxScanReach`, no change after freezing)

Purpose: the first blind measurement of 0.84.0 / 0.85.0 (trust-all restore, unexported providers, separator-cleaned file names, Axml fallback names) on public open-source apps. Never scanned by APKReLab before (not in the 15-app study, sets 1-8, the vulnerable-app benchmarks, JustMarkets). Set 9 (owner-supplied closed apps) is excluded by the owner.
| app | source | sha256 | dex / classes | .so |
|---|---|---|---|---|
| NetGuard 2.337 (no-root firewall: VpnService, SQLite, exported receivers / providers, many preferences) | github.com/M66B/NetGuard releases (latest) | 150a0362f04408c2d3cc7fb38d7e126445019d523489c8d82df6fb456c4e6ad2 | 1 / 2,603 | 4 |
| Session 1.33.7 arm64-v8a play-release (messenger: account keys, attachments, link previews, WebRTC; Kotlin + native) | github.com/session-foundation/session-android releases (latest) | 0f9890ba1b46d27cfa4d65a88b3b16973d53495219b9a7e92fe605677dc0cb9b | 2 / 15,078 | 8 |
| Nextcloud Notes 35.0.0 (notes + sync with a Nextcloud server: account storage, SSO library, share targets) | github.com/nextcloud/notes-android releases (latest) | 3cf73e0906ace765332b67748a11acb2b733706fdda1bac537116e7fd99ce75e | 7 / 44,015 | 4 |
Scoring as PROTOCOL_SET4.md (precision by card and by distinct issue; TP / TP-1CLICK / TP-low / BY-DESIGN / FP; library-scope cards apart; MEDIUM only as a sample). First run frozen in runs/. Native code of Session / NetGuard / Notes is not analysed (a card says so).

## FIRST RUN (frozen), 0.85.0 reach-aware sandbox
Reports: `runs/netguard-0.85.0-sandbox-FIRST.md`, `runs/session-0.85.0-sandbox-FIRST.md`, `runs/ncnotes-0.85.0-sandbox-FIRST.md`.
Cards: NetGuard 19 (0 HIGH), Session 41 (1 CRITICAL, 3 HIGH), Nextcloud Notes 42 (4 HIGH). Every HIGH / CRITICAL read in the smali.

| app | card(s) | verdict | why |
|---|---|---|---|
| Session | CRITICAL trust-all `HttpClientsKt$createRegularNodeOkHttpClient$trustManager$1` + HIGH all-true hostname verifier (`HttpClientsKt$$ExternalSyntheticLambda0`) + HIGH `SSLContext.getInstance("SSL")` (Dagger provider) | **TRUE OBSERVATION, probably BY-DESIGN** (one issue, 3 cards) | the client is the "regular node" client: Session talks to service nodes with self-signed certificates and relies on the onion-request encryption to the node's key, not on TLS validation. The classes are exactly what the rules describe (both read: `checkServerTrusted` returns at once, `verify` returns true). The "service nodes use self-signed certs" design is from my knowledge of Session, NOT verified in this session |
| Session | high-entropy string near a credential name, `FirebaseTokenFetcher` | FP | the 29-char string is the thread name `Firebase-Messaging-Network-Io` |
| Nextcloud Notes | high-entropy x3, `CustomLinkKt` | FP | Compose compiler source-info strings (`CC(remember):CustomLink.kt#9igjgp`) |
| Nextcloud Notes | hardcoded sensitive field `TOKEN_RECIPIENT_CLASS` | FP | a constant naming a server-side PHP class (`OC\...`) used as a recipient type |
| Nextcloud Notes | hardcoded sensitive field `AccessControlAllowCredentials`, `LockToken` in `io.ktor.http.HttpHeaders` (scope OBF) | FP | ktor header-name constants (`Access-Control-Allow-Credentials`, `Lock-Token`); ktor is missing from the library list |
| NetGuard | none | - | 0 HIGH |

**Precision by card: 0 TP / 5 (3 more cards are the by-design Session client); by distinct issue: 0 / 4.**
Running total of first runs on unseen open-source apps, sets 2-8 + 10 (set 9 excluded): 16 TP cards / 58 judged = 28%.
FP families: (1) the secret detectors on public strings: hyphenated names (`Firebase-Messaging-Network-Io`, `Access-Control-Allow-Credentials`), Compose source-info strings, backslash-separated class names; (2) ktor (an HTTP library) is not in the library list. NetGuard (a VPN firewall with an SQLite database and exported components) gave 0 HIGH.

## Note added when the two lines of work were merged (2026-10-17)
This set was run in a second session at the same time as PROTOCOL_SET10.md (AdAway, Feeder, Nextcloud Notes on 0.85.1). Both started from 0.85.0 (commit d60b102); the 0.85.1 / 0.85.2 line is the one that continues. Nextcloud Notes is in both sets and gave the same four FP cards in both. No code was changed because of NetGuard or Session.
Re-run on 0.85.2 (reach-aware sandbox, not blind any more for Nextcloud Notes): NetGuard identical (0 HIGH), Session loses exactly the `Firebase-Messaging-Network-Io` thread-name FP (the 0.85.2 header-name filter, written for other apps, also fixes this one: an independent check of that filter); the by-design node client (3 cards) stays.
