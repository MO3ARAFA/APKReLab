# Working on APKReLab from the phone (Termux / proot-distro Ubuntu + Claude Code CLI)

Since 0.101.1 the project is developed by Claude Code running on the owner's phone: no PC, no Mac. The APK is built by Code on the Go (it brings its own Gradle); the agent edits files, runs what can run on a phone, and the owner builds and sends reports.

## What runs on the phone, what does not
| task | how | status |
|---|---|---|
| `ir` unit tests (plain Java, 285) | `bash tools/termux/run_ir_tests.sh` (needs a JDK) | verified on Linux, not yet on the phone |
| Kotlin unit tests (277) | need `kotlinc` 2.3.x + the stubs: `tools/sandbox/SETUP_FROM_SCRATCH.md` | heavy on a phone: do it only when a Kotlin file changed |
| Gradle build / APK | Code on the Go (the owner) | the only real compile of `MainActivity.kt`, `Ui.kt` |
| scan speed measurements (`tools/sandbox/MeasureBig.java`, JFR) | a decoded app + `java -Xmx...` | an 18k-class app wants about 1 GB: close other apps, do not run it together with a Gradle build |

## Memory and CPU rules for the agent (measured, see docs/internal/PERF.md)
- The phone is MEMORY-bound, not CPU-bound: at a 1 GB heap about half of a scan was garbage collection and two analysis threads cost more than one. Never add threads or caches without a heap measurement at 1 GB (`java -Xmx1000m`).
- Claude Code itself uses several hundred MB: a measurement and the agent can compete for RAM. Use `-Xmx` explicitly and run one heavy job at a time.
- Run-to-run variation of the same scan on the phone is about 36%: judge a speed change by CPU counters, by the identical flow list, and by two device runs, never by one.

## Getting the APK and its splits on a phone (no adb, no PC)
- Base APK: `pm path <package>` works in Termux only on some devices; the app's own **Select APK** can open a file picked from the Files app.
- Splits (`split_config.*.apk`): a Play Store app is several files. Options: an app that exports installed apps as `.apks` / `.xapk` (APKReLab opens those), or wireless debugging from Termux to the same phone (`pkg install android-tools`, then `adb pair` / `adb connect` with the Developer options > Wireless debugging code, then `adb shell pm path <package>` and `adb pull`). An in-app "installed apps" picker is on the roadmap (it can read `ApplicationInfo.sourceDir` and `splitSourceDirs` directly).

## Privacy
Company app reports, APKs and decoded folders never go into git: `.gitignore` covers them, put reports in `./private/`. The GitHub repository must be PRIVATE.
