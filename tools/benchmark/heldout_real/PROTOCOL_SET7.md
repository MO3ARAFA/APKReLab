# Real-app held-out set 7 (frozen 2026-10-14, BEFORE the first scan, tool version 0.82.0, working tree as of the transfer snapshot, no change after freezing)

Purpose: the first blind measurement of 0.82.0 (app-bound renamed code, native card, network severity, provider code checks, JS bridge helpers, ...).
Never scanned by APKReLab before (not in the 15-app study, sets 1-6, the vulnerable-app benchmarks, JustMarkets). Java / Kotlin apps.
| app | source | sha256 |
|---|---|---|
| Tusky v29.0 (Mastodon client: OAuth tokens, accounts, deep links, share targets) | github.com/tuskyapp/Tusky releases (latest, asset 133.apk) | efef094716f236465324cdda173f337aa630903ae9784eac7511e1b607c6a1ab |
| FairEmail 1.2338a github-release (mail client: account credentials, IMAP / SMTP, OpenPGP / S/MIME, many exported components, WebView mail rendering) | github.com/M66B/FairEmail releases (latest) | 666b9f4ada53f69199355f1ccc2bed73e01fa23786fc0189cf81cc51932dc5a9 |
| Shizuku 13.6.0 (privileged service via Binder / adb: AIDL, Parcel sources, exported provider + service) | github.com/RikkaApps/Shizuku releases (latest) | 6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f |
Substitutions decided before scanning: AntennaPod and Cryptomator publish no APK on GitHub; Tusky / FairEmail / Shizuku replace them.

Scoring as PROTOCOL_SET4.md (precision by card and by distinct issue; TP / TP-1CLICK / TP-low / BY-DESIGN / FP; library-scope cards apart; MEDIUM only as a sample). First run frozen in runs/. A fix made because of one of these apps makes it a tuning app.

## FIRST RUN (frozen), 0.82.0 sandbox
Reports: `runs/shizuku-0.82.0-sandbox-FIRST.md`, `runs/tusky-0.82.0-sandbox-FIRST.md`, `runs/fairemail-0.82.0-sandbox-FIRST.md`.
Cards: Shizuku 19 (2 HIGH), Tusky 31 (0 HIGH), FairEmail 130 (19 HIGH). Every HIGH was read in the smali / manifest; some verdicts rest on a partial read (said below).

| app | card(s) | verdict | why |
|---|---|---|---|
| Shizuku | 2 x "selects a class by name" (`rikka.shizuku.Kc`, `Tk`) | FP | `Kc` is androidx FragmentFactory.loadClass ("Unable to instantiate fragment ..."), `Tk` is androidx.savedstate Restarter; R8 repackaged them INTO the app's own package (`rikka.shizuku`), so scope = APP, not a library |
| Tusky | none | - | 0 HIGH |
| FairEmail | "Credential stored in plain SharedPreferences" `cloud_password` (FragmentOptionsBackup) | **TP-low** | the cloud-backup password sits in plain SharedPreferences |
| FairEmail | 3 x "Hostname verification disabled" (EmailProvider$5 / $6, ConnectionHelper$1) | **TP-low** | an all-true HostnameVerifier is installed on HttpsURLConnections for auxiliary fetches: `ConnectionHelper.openConnectionUnsafe` (named "Unsafe"; used by ContactInfo avatars, print dialog and ImageHelper images) and the provider settings discovery `getISPDB`. A MITM can swap images / suggest wrong mail server settings; deliberate trade-off, not the mail connection itself |
| FairEmail | broadcast `NEW_MESSAGE_COUNT` without permission (ServiceSynchronize$14) | BY-DESIGN | unread-count integration for other apps / widgets (extras not read one by one) |
| FairEmail | Intent -> WebView.loadDataWithBaseURL (ActivityAMP, exported VIEW of text/x-amp-html) | BY-DESIGN | an AMP viewer renders the content it is given; the WebView JS state was not resolved (constants in registers) |
| FairEmail | broadcast in `me.leolin.shortcutbadger.impl.VivoHomeBadger` | FP | the ShortcutBadger library, launcher badge count |
| FairEmail | hardcoded `KEY_LAST_TOKEN_RESPONSE` (net.openid.appauth.AuthState) | FP | AppAuth library, a JSON key name |
| FairEmail | 12 cards: file path / intent redirection / class by name through `SimpleTask$2.a()` (= the shared `data:Object` field of every task result) and `EntityAttachment.getFile` (attachments dir keyed by a Long id; the name part was not read) | FP (probable) | one root cause: a generic result holder (`SimpleTask.data`, Object-typed, readable package so not weak) joins unrelated task results, so a Parcelable / Intent source reaches 12 unrelated sinks (ActivityBase.startActivity, processUri, DebugHelper, EntityAttachment.zip, FragmentCompose ...) |
| FairEmail | `w71` Class.forName from Intent extra through `gt.next()` | FP | `w71` is a ServiceLoader implementation (META-INF/services), R8-renamed library |

**By card: 4 TP / 19 = 21%; 2 BY-DESIGN; 13 FP.** By distinct issue: 2 TP / 8 = 25% (FP issues: androidx Fragment, androidx savedstate, ShortcutBadger, AppAuth, SimpleTask conflation, ServiceLoader).
First runs on unseen real apps, sets 2-7 together: 15 TP cards / 48 judged = 31% (sets: 3/6, 1/9, 3/4, 3/6, 1/4, 4/19).
New FP families: (1) library code repackaged into the APP's own package is scoped APP (Shizuku; the opposite of the JustMarkets problem), (2) Object-typed shared result fields in readable packages conflate heavily in apps with a generic task / result holder (FairEmail: 12 of 19 HIGH): this CONTRADICTS the census of PROTOCOL_SET3 ("field conflation ~1 FP"), which had no such app, (3) well-known libraries missing from the library list (ShortcutBadger, AppAuth), (4) ServiceLoader-style class loading from resource files.


## After the fixes: 0.83.0 (set 7 is a TUNING set from here; these numbers are NOT blind)
Reach-aware sandbox (`tools/sandbox/SandboxScanReach.kt`: reach labels from the call graph + `lowerUnreachedHelpers`, like the device). HIGH/CRIT:
| app | first run 0.82.0 | 0.83.0 | left |
|---|---|---|---|
| Shizuku | 2 | 0 | |
| Tusky | 0 | 0 | |
| FairEmail | 19 | 7 | cloud_password (TP-low), 3 hostname verifiers (TP-low), broadcast (BY-DESIGN), 2 `file path` from Intent extras (ActivityBase.processUri: the name goes through `Helper.sanitizeFilename`, so likely FP; FragmentCompose$68: not read) |
Recount of the same 7 cards: 4 TP-low or BY-DESIGN + 1 BY-DESIGN, 2 likely FP.
Other apps (HIGH/CRIT first-run 0.82.0 -> 0.83.0): Termux 7 -> 6 (the `ExecutionCommand.toString` FP; the real FileReceiverActivity `Intent.getData` card stays), Breezy 5 -> 4 (objectbox FP), Kiwix 1 -> 0 (FP), Ivy 1 -> 0 (FP), AnkiDroid 1 -> 1 (the k73 FP is gone; the remaining card is `CardContentProvider.insert` -> file write in w87, a real flow behind a dangerous permission, judged TP-low / BY-DESIGN, the file-name sanitising not read). Everything else unchanged (Sieve 8/8, Allsafe 6/7, PIVAA 21/25, Vuldroid 7/8; OVAA 16/19 found with reach labels in the sandbox, 14/19 without: not comparable with older rows).
