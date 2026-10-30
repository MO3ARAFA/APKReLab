# Real-app held-out set 6 (frozen 2026-10-14, BEFORE the first scan, tool version 0.80.0, no change after freezing)

Purpose: measure 0.80.0 (fixes from sets 4 + 5) on apps never seen. Java / Kotlin apps, never scanned by APKReLab before.
| app | source | sha256 |
|---|---|---|
| AnkiDroid 2.25.2 arm64-v8a (flashcards: content provider + permission API for other apps, JavaScript API in a WebView) | github.com/ankidroid/Anki-Android releases (latest) | 430ff81da13f9afe965b2d6e474663324a3d84c72dbdb066bdbcd8b5317e4c4a |
| Jellyfin 2.7.3 libre release (media client: the UI is a WebView with a JavaScript bridge) | github.com/jellyfin/jellyfin-android releases (latest) | f9f4b3ab46cc9434df811194c2d4351417f4db83a4c1a0facd0a662d69533f7f |
| Seal 1.13.1 arm64-v8a (video downloader: runs yt-dlp, writes files, share intents) | github.com/JunkFood02/Seal releases (latest) | 23112395e489da4655fe3f6e5be2a47bca8ab3b406cc5ed7590a00b4548faa37 |

Scoring as PROTOCOL_SET4.md (precision by card and by distinct issue; TP / TP-1CLICK / TP-low / BY-DESIGN / FP; first run frozen in runs/).

## FIRST RUN (frozen), 0.80.0 sandbox
Reports: `runs/seal-0.80.0-sandbox-FIRST.md`, `runs/jellyfin-0.80.0-sandbox-FIRST.md`, `runs/anki-0.80.0-sandbox-FIRST.md`.
Cards: Seal 16 (0 HIGH), Jellyfin 37 (3 HIGH), AnkiDroid 108 (6 HIGH). No library-scope card among the HIGH (two are OBF = R8-renamed).

| app | card | verdict | why |
|---|---|---|---|
| Jellyfin | JavaScript-exposed method, bridge.NativeInterface | **TP-low** | the bridge exposes openUrl, downloadFiles, getDeviceInformation, execCast, exitApp ... to the server's web UI; the server is the user's, but HTTP and user CAs are allowed, so a MITM on a plain-HTTP server can drive them. (The rule named only hideMediaSession; openUrl / downloadFiles reach their APIs through helpers it does not follow) |
| Jellyfin | NSC cleartext / user CAs (2) | BY-DESIGN | self-hosted media servers on the LAN |
| AnkiDroid | Cleartext traffic allowed + NSC cleartext / user CAs (3) | BY-DESIGN | self-hosted sync servers |
| AnkiDroid | Exported provider without a permission (CardContentProvider) | FP | no manifest permission, but the code enforces `com.ichi2.anki.permission.READ_WRITE_DATABASE` (dangerous) with `checkCallingPermission` + `getCallingPackage`; the manifest rule cannot see a code-level check |
| AnkiDroid | file path, jx2 (OBF) via ACRA CrashReportDialog | FP | ACRA's crash dialog (R8-renamed library), exported=false, own `:acra` process; the Intent comes from ACRA itself |
| AnkiDroid | class by name, k73 (OBF = androidx FragmentFactory) | FP | `initial_fragment` extra of PreferencesActivity, which is exported=false and only started by the app |

**Precision by card: 1 TP / 4 = 25%; by distinct issue: 1 / 4 = 25%.** 5 BY-DESIGN. Seal: no HIGH at all.
FP families: (1) Intent sources in NON-exported ACTIVITIES (2 of 3; 0.80.0 lowers receivers / services only, on purpose); (2) the manifest
provider rule does not see code-level permission checks (1).
Running total of FIRST runs on unseen real apps since the first fixes (sets 2-6): 11 TP cards / 29 judged = 38% by card.


## After the fixes: 0.81.0 (set 6 is a TUNING set from here)
| app | HIGH/CRIT 0.80.0 -> 0.81.0 | left |
|---|---|---|
| AnkiDroid | 6 -> 1 | network config cards MEDIUM (no plain-HTTP URL in the app's code), CardContentProvider card LOW (every data method checks the caller in code), ACRA crash-dialog flow MEDIUM (separate-process, non-exported dialog); left: k73 / PreferencesActivity (FP: non-exported activity in the main process, kept on purpose) |
| Jellyfin | 3 -> 1 | NSC cards MEDIUM; left: the bridge (TP-low). The helper following does NOT reach openUrl: it emits an event to `ActivityEventHandler` (another class, an event bus) |
| Seal | 0 -> 0 | |
