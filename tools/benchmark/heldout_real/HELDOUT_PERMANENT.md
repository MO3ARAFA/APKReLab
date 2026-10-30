# Permanent held-out set H (frozen 2026-10-18, tool version 0.86.1 = commit d584647, `SandboxScanReach`, snapshot built from that commit)

Purpose: a blind measure that is NEVER used for tuning, so that first-run precision on it can be compared between scanner versions.
Rules (written before any scan):
1. No code, rule list, library list, filter or severity of the scanner is changed because of what a scan of these apps shows. Not now, not in later versions. (A defect seen here is written in "Known issues seen on H, not fixed" below and may be fixed only after the SAME defect shows up independently in a tuning app or in the recall kit.)
2. The apps are scanned by every scanner version that is released from now on, with the same pipeline; the first card list of each version is frozen in `runs/H-<app>-<version>.md`; changes between versions are counted, not tuned.
3. Verdicts (TP / TP-low / BY-DESIGN / FP) are made by reading the smali / manifest, as in the other sets; a verdict is final once written; a later correction is added as a new line, the old one is kept.
4. The APKs are the files with the hashes below; a newer release of the same app is a different app and does not replace them.
Never used before in any set, study or benchmark of this project (checked against the lists in HANDOFF / PROTOCOL files).
| id | app | source | sha256 | dex / classes | .so | why this one |
|---|---|---|---|---|---|---|
| H1 | Trail Sense 8.2.0 | github.com/kylecorry31/Trail-Sense releases | b5fb5bef2e89b2ae2992a20bc53496fb2e986cb41ac4af659a6e36a479c29516 | 2 / 7,008 | 16 | small, Kotlin, offline: sensors, files, backup / export, widgets, no account (the opposite of a network client) |
| H2 | Proton Mail 3.0.17 (the legacy Android app) | github.com/ProtonMail/proton-mail-android releases | 54a6a5e42e33088b68fda0a7cd9f3345ce039546b379b26ea5b225171bbb22a3 | 7 / 28,531 | 12 | large, Kotlin, account + crypto + attachments + WebView mail rendering, Hilt / Room, third-party libraries |
| H3 | Syncthing-Fork 2.1.6.0 arm64-v8a (Catfriend1 fork, published under researchxxl) | github.com/researchxxl/syncthing-android releases | 15f17037805d87f67d9407eef436691e458ea4185b42871889297c7e98bbfd67 | 5 / 35,750 | 2 | Java UI around a native Go daemon: VpnService-free network service, WebView GUI, exported components, config files, native code outside the scan |
Also frozen: the recall-kit results of this version (tools/recall/results-*.md) are the second, separate measure: they are NOT a held-out.

## First run of 0.86.1 (frozen: runs/H-trailsense-0.86.1.md, runs/H-syncthing-0.86.1.md, runs/H-protonmail-0.86.1.md)
| app | cards | HIGH / CRITICAL |
|---|---|---|
| H1 Trail Sense | 34 (7 MEDIUM, 27 LOW) | 0 |
| H2 Proton Mail | 72 (22 MEDIUM, 49 LOW, 1 HIGH) | 1 |
| H3 Syncthing-Fork | 33 (20 MEDIUM, 13 LOW) | 0 |
Verdict on the one HIGH card: Proton Mail "Weak cipher mode: ECB (AES)" in `s6.a` = `SecureSharedPreferences.kt` (read in the smali): the app's own class encrypts SharedPreferences values with `Cipher.getInstance("AES")` (ECB by default on Android) and a key that is SHA-256 of a `char[]` the caller passes in. **TP-low**: a real weakness (identical values give identical ciphertext, no integrity), impact limited by the fact that it needs the preferences file. NOT read: where the caller gets that secret from. (A first reading of mine said the key came from the constant "sekrit": wrong, "sekrit" is the constructor PARAMETER NAME checked by a Kotlin null check.)
Precision on HIGH / CRITICAL: 1 TP-low of 1 (n = 1: no information). The MEDIUM cards were listed by title only, not judged one by one (Trail Sense: 4 file-path flows from Parcel / ZipEntry in renamed classes, backup allowed, deep link; Syncthing-Fork: shell execution x2, WebView ignores TLS errors behind a condition, file-path flows from onActivityResult, WebView URL from an Intent extra; Proton Mail: deserialization x5, plaintext SharedPreferences x2, WebView TLS errors, MD5, cleartext permitted). Recall on H is unknown by construction (no list of the real weaknesses of these apps).

## Re-run with the corrected harness (0.86.2, same day)
The first run above used a sandbox harness that took the MANIFEST package as the app's code package; the device uses `SecurityScanner.codePackage`. Re-run of the same three APKs with the device's behaviour (and the 0.86.2 `codePackage` fix, which does not change any of these three): Trail Sense 34 cards, 0 HIGH (identical); Proton Mail 72 cards, 1 HIGH (identical); Syncthing-Fork 34 cards (+1: the code package is `com.nutomic`, not the manifest's), 0 HIGH. The first-run numbers stand. Reports: runs/H-*-0.86.2-harness-corrected.md. No scanner change was made because of these apps.

## Known issues seen on H, not fixed
(none written yet: the MEDIUM cards were not judged; any defect found when they are judged goes here, not into the code)
