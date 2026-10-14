# Real-app held-out set 2 (frozen 2026-10-13, BEFORE the first scan, tool version 0.76.0)

Never scanned by APKReLab before; not in the 15-app study, not in set 1 (andOTP, Password Store, Unstoppable), not in the tuning set.
| app | source | sha256 |
|---|---|---|
| Termux 0.119.0-beta.3 (terminal, RUN_COMMAND IPC, file sharing), github debug arm64-v8a | github.com/termux/termux-app releases | 8586dd359400b4208447f8148e023bc6d4114b74fa8c1e114d7d435989fd2ac4 |
| Monerujo 4.1.7 (Monero wallet) universal | github.com/m2049r/xmrwallet releases | 0b31ad7f0b1f677daa6dfeff95730241222467c33c4465469c7a0d820beb260a |
| Ivy Wallet v2025.07.17-206 (personal finance, Kotlin / Compose) | github.com/Ivy-Apps/ivy-wallet releases | 88bee8ab82b1f890a31eda4f01b5bb16927fbdd0db25d25c3d82d2ba3fd00c0b |

Same scoring as set 1 (PROTOCOL.md): precision only, every HIGH / CRITICAL in app scope read in the smali and classified TP / BY-DESIGN / FP,
library-scope cards counted separately, MEDIUM only as a sample said as a sample. The first run is frozen in runs/ before any change.
Note: Termux is a debug build (no R8); its purpose (run shell commands, share files with other apps) makes some findings BY-DESIGN by nature.

## FIRST RUN (frozen), 0.76.0 sandbox (SandboxScan, SSA without library classes like the device)
Reports: `runs/termux-0.76.0-sandbox-FIRST.md`, `runs/monerujo-0.76.0-sandbox-FIRST.md`, `runs/ivy-0.76.0-sandbox-FIRST.md`.
Cards: Termux 48 (2 CRIT, 7 HIGH), Monerujo 26 (2 HIGH), Ivy 54 (2 HIGH). No library-scope card among the HIGH / CRITICAL.

Every HIGH / CRITICAL read in the smali / manifest:
| app | card | verdict | why |
|---|---|---|---|
| Termux | Debuggable build | BY-DESIGN | the GitHub builds are published as debug builds |
| Termux | Zip Slip, TermuxInstaller$1 | FP | the zip is the bootstrap embedded in the app (`loadZipBytes()`), not attacker input |
| Termux | CRITICAL shell command, AppShell (from RunCommandService) | BY-DESIGN | RunCommandService needs the dangerous permission `com.termux.permission.RUN_COMMAND` (user grant) + allow-external-apps; running commands is its purpose |
| Termux | file path, FileReceiverActivity.onResume (Intent.getData) | BY-DESIGN | exported share/view target opens the file:// it is given, inside Termux |
| Termux | file path, FileReceiverActivity.saveStreamWithName | **TP** (sink right, chain wrong) | `File(~/downloads, name)` with no normalisation; `name` is the sharer's `_display_name` (attacker-controlled, prefilled in a confirm dialog), so `../.bashrc` writes outside downloads (user must press OK). The engine reached it through an unrelated chain (ExecutionCommand.toString); `ContentResolver` `_display_name` is NOT a modelled source |
| Termux | file path, FileUtils (resultDirectoryPath) x2 | BY-DESIGN | RunCommandService caller (permission holder) chooses where results go |
| Termux | file path, FileUtils (ReportActivity) | FP | ReportActivity is exported=false (internal source) |
| Termux | file path, TermuxShellUtils (executable) | BY-DESIGN | permission-holding caller picks the executable |
| Monerujo | Cleartext traffic allowed | BY-DESIGN | wallet talks to user-chosen Monero nodes (plain RPC / onion) |
| Monerujo | Hardcoded credential: JWT (ExolixApiImpl) | **TP** | `Bearer eyJ...` exchange-partner API token in the code (expires 2028), sent as Authorization header |
| Ivy Wallet | Cleartext traffic allowed | **TP** (config, severity overstated) | usesCleartextTraffic=true globally; no http:// URL in the app's own code, so impact not shown |
| Ivy Wallet | class by name, S1.b (OBF) | FP | androidx.glance ActionCallbackBroadcastReceiver (R8-renamed library), exported=false, and it checks the class implements ActionCallback |

**Precision TP / (TP + FP) = 3 / 6 = 50%** on HIGH / CRITICAL (7 more are BY-DESIGN; n = 13, small). Set 1 before its fixes: 1 / 19 = 5%.
Remaining weaknesses seen: (1) a missing source: ContentResolver query columns (`_display_name`) of a content URI received from another app; (2) taint chains through unrelated fields / toString explanations; (3) the class-local zip-slip rule cannot tell an embedded archive from an attacker's; (4) a non-exported OBF library receiver and a non-exported activity still produce HIGH flows in the sandbox (check on device: the device passes the same entries).

## Device run (owner, 0.76.0 Smart scan): a DIFFERENT Termux build
The device APK is the Google Play build `googleplay.2026.10.09` (versionCode 142, minSdk 32, 996 classes, one dex; source
github.com/termux-play-store/termux-apps, no APK published there), not the GitHub 0.119.0-beta.3 debug build of the sandbox run, so the
two runs are not comparable card by card. Report: `runs/termux-googleplay-2026.10.09-0.76.0-device.md`. 29 cards: 3 HIGH, 14 MEDIUM, 12 LOW.
The three HIGH, read against the tagged source:
| card | AI | verdict | why |
|---|---|---|---|
| TermuxFileReceiverActivity.onResume: Intent.getData() -> FileInputStream (reachable, exported) | TRUE POSITIVE | BY-DESIGN (I disagree with the AI) | for a file:// URI the activity opens the given path and, after the user confirms a name, copies it into Termux's own home; nothing goes back to the caller, the saved name is `File(path).getName()` (no traversal). No boundary is crossed |
| KeystoreAPI$2.writeResult (not reached from an exported component) | NEEDS REVIEW | FP | the only way in is TermuxService, protected by `com.termux.permission.TERMUX_INTERNAL`, protectionLevel signature: the caller is Termux's own CLI, not another app |
| StorageGetAPI$StorageActivity.onActivityResult (exported=false) | NEEDS REVIEW | FP | same TERMUX_INTERNAL signature path; `termux-storage-get <file>` writes where the user asked |
Device precision on this build: 0 TP / 2 FP (1 BY-DESIGN). Two engine points from it: in-class taint flows that the call graph does not
reach from an exported component stay HIGH (they should drop a level, like unreachable SSA flows); a service protected by a signature-level
permission is an internal entry, so flows from it are not "untrusted input".


## After the fixes: 0.77.0 (Termux, Monerujo, Ivy Wallet are TUNING apps from here)
- Termux sandbox: the Zip Slip FP (embedded bootstrap) is now a LOW "archive from inside the APK" card: HIGH/CRIT 9 -> 8. The other cards are
  unchanged. The real `_display_name` path traversal is still reported only through the wrong chain: the name goes through the confirm DIALOG
  (EditText), so no static flow from the cursor reaches `saveStreamWithName` even with the new cursor model (and that dialog is also why the
  bug needs a user click).
- Device-only effect (needs reach labels, not in the sandbox): Termux Play `KeystoreAPI$2` (helper class, reach NO) drops HIGH -> MEDIUM;
  `StorageGetAPI$StorageActivity` stays HIGH because it is a component (OVAA WebViewActivity, also exported=false, is reached through a
  forward the graph does not see, so components are never lowered).
- Monerujo, Ivy unchanged (their HIGH cards were a TP, a BY-DESIGN, a TP-config and one FP in an R8-renamed Glance receiver, not touched).
- Not fixed: taint through unrelated objects of the same class (`ExecutionCommand.toString`): the heap is field-based (one taint per
  class.field for every object); object sensitivity is a larger change.
