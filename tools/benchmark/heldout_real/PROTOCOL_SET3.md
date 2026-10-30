# Real-app held-out set 3 (frozen 2026-10-13, BEFORE the first scan, tool version 0.77.0)

Never scanned by APKReLab before (not in the 15-app study, set 1, set 2 or the tuning set). Chosen for different shapes: sync / accounts,
a WebView-based reader, a notes / file editor. All three are Java / Kotlin apps (no React Native / Go / browser-engine core).
| app | source | sha256 |
|---|---|---|
| DAVx5 4.5.19-ose (CalDAV / CardDAV sync: accounts, sync adapters, content providers) | github.com/bitfireAT/davx5-ose releases | 4e8f1cd0d2f47f95a1003365340a30c99cb27173476c367d90ba9e14f97a3e10 |
| Kiwix 3.14.1 arm64-v8a standalone (offline Wikipedia reader on WebView, ZIM files, deep links) | github.com/kiwix/kiwix-android releases | 62a9910be260030e642465c17d642537e6ee4ee5f2d4596c248267c2766a88b8 |
| Markor 2.16.1 flavorDefault (markdown notes / file editor, share intents) | github.com/gsantner/markor releases | e88cdcced7aa3dca25e6b9c7a9bdcfad3e3988ee545be951f42bf9441b5e46bf |

Replacements (decided before scanning): Fulguris (first choice for the browser) publishes no APK on GitHub -> Kiwix (also WebView);
DAVx5: the stable 4.5.19 instead of the newest release candidate.
Scoring: as PROTOCOL.md (precision only; every HIGH / CRITICAL in app scope + manifest read in the smali / manifest and classified TP /
BY-DESIGN / FP; library cards counted apart; MEDIUM only as a sample said as a sample). First run frozen in runs/ before any change.
New this time: a TP that needs a user action (a confirm click) is TP-1CLICK, counted as TP but listed apart.

## FIRST RUN (frozen), 0.77.0 sandbox
Reports: `runs/davx5-0.77.0-sandbox-FIRST.md`, `runs/kiwix-0.77.0-sandbox-FIRST.md`, `runs/markor-0.77.0-sandbox-FIRST.md`.
Cards: DAVx5 36 (2 HIGH, SSA 0 flows), Kiwix 25 (3 HIGH), Markor 36 (7 HIGH). No library card among the HIGH.

| app | card | verdict | why |
|---|---|---|---|
| DAVx5 | NSC cleartext permitted | BY-DESIGN | base-config allows HTTP for self-hosted CalDAV / CardDAV servers |
| DAVx5 | NSC trusts user CAs | BY-DESIGN | self-hosted servers with their own CA (documented use) |
| Kiwix | addJavascriptInterface, CoreReaderFragment | FP | the bridges expose TOC parsing, text-to-speech start / stop / speakAloud and a service-worker callback: no file, Intent or data access |
| Kiwix | addJavascriptInterface, VideoEnabledWebView | FP | fullscreen-video notification bridge only |
| Kiwix | Intent extra -> VideoEnabledWebView.loadUrl | FP | the extra is a search TITLE looked up with `Archive.getEntryByTitle`; the URL loaded is the ZIM entry's, not the caller's string |
| Markor | Cleartext traffic allowed | BY-DESIGN | markdown preview of the user's own notes with http links / images |
| Markor | addJavascriptInterface, DocumentEditAndViewFragment | FP | `webViewJavascriptCallback` only handles "toast" |
| Markor | file path, GsFileUtils.writeFile (via contentColumnData) | **TP-1CLICK** (low impact) | DocumentActivity (exported, VIEW / EDIT) takes the file path from the `_data` column of the CALLER's content provider (`extractFileFromIntent`, `checkPath` only tests canRead): Markor opens a file the caller names, including its own private files, and writes it back when the document is saved |
| Markor | file path, GsFileUtils.copyUriToFile | FP | destination is `cacheDir/<timestamp><ext>` (extractResultFromActivityResult), not the caller's |
| Markor | file path, GsFileUtils copyFile / touch / isContentsPlainText (3 cards) | FP | chains through `AppSettings.getAttachmentFolder` / `getSnippetsDirectory`: the app's own settings, reached by field-level taint |

**Precision TP / (TP + FP) = 1 / 9 = 11%** (3 BY-DESIGN; the one TP needs a save and its impact is low).
Running total of FIRST runs on real apps: set 1 1/19, set 2 3/6 (sandbox) + 0/2 (device, other build), set 3 1/9 -> 5 TP of 36 judged = about 14%.
Remaining FP families: (1) `webview-js-interface` is HIGH whatever the bridge exposes (3 of 8 FP here); (2) SSA flows through settings getters
/ unrelated objects of one class (field-based heap, 4 of 8); (3) a lookup (`getEntryByTitle`) is not a sanitizer in the model (1).


## Correction to my own verdicts: WITHDRAWN (0.79.0)
I first re-labelled Markor cards 26 / 28 (copyFile / touch through `AppSettings.getAttachmentFolder`) as consequences of the TP. The flow
dump (`tools/sandbox/FlowDump.java`) shows their source is SharedPreferences read with a non-literal key, i.e. the settings conflation of the
first verdict. The first verdicts stand: **1 TP / 9 = 11%**. (Whether getAttachmentFolder(doc) can also return the caller's directory is a
separate path, not verified.)

## After the fixes: 0.78.0 (DAVx5, Kiwix, Markor are TUNING apps from here)
| app | HIGH/CRIT 0.77.0 -> 0.78.0 | left |
|---|---|---|
| DAVx5 | 2 -> 2 | 2 BY-DESIGN (NSC) |
| Kiwix | 3 -> 1 | the bridges are MEDIUM; left: the title-lookup loadUrl (FP, a lookup is not modelled as a sanitizer) |
| Markor | 7 -> 5 | cleartext (BY-DESIGN), 3 cards of the `_data` root (TP-chain: open / read / write of the caller-named file), copyUriToFile (FP) |


## 0.79.0
| app | HIGH/CRIT 0.78.0 -> 0.79.0 | cards | why |
|---|---|---|---|
| Markor | 5 -> 3 | 36 -> 33 | the two cards of the caller-file root (DocumentActivity.handleLaunchingIntent) are one card; copyUriToFile from `extractResultFromActivityResult` is an activity result now (LOW) |
| Kiwix | 1 -> 1 | 25 -> 23 | Fetch2 is a library; the remaining HIGH is NOT a lookup problem (my first diagnosis was wrong): an extra starting with "A/" is used as the article path directly, but `contentUrl()` pins it to the app's own virtual host, so the WebView cannot be sent to another origin. Not fixed (needs an "origin fixed by a constant prefix" model) |
Left HIGH on set 3: DAVx5 2 BY-DESIGN, Kiwix 1 FP, Markor 1 BY-DESIGN + 2 TP-root cards (read and write of the caller-named file).

## Field-conflation census (decides 0.80.0)
`FlowDump` over 8 real apps (Unstoppable does not fit the sandbox): 56 flows, 14 through a heap field. Of those 14: 6 in R8-renamed library
code of Ivy (Parcel sources, MEDIUM), 2 in the Fetch2 library (Kiwix, now a library), 4 in Termux RunCommandService (fields really written
by the permission-guarded caller: BY-DESIGN), 1 Termux ReportActivity (internal), 1 Password Store `by lazy` delegate (the TP).
Among the 14 HIGH/CRITICAL FP cards judged in sets 1-3, ONE comes from field conflation (Termux `ExecutionCommand.toString`).
**Conclusion: an allocation-site (object-sensitive) heap would remove about 1 of the judged FPs; the memory cost is not justified now.**
