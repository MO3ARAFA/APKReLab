# Sandbox measurement harness (0.68.5) (not part of the app, never compiled by Gradle)

Runs the REAL `ir` package (CallGraph + TaintIr) on apktool-decoded APKs, with the same library filter as the Deep scan
(`SecurityScanner.scopeOf`, copied into `Scope.java` by `gen_scope.py`). The Kotlin scanner, Smart scan and the benchmark are NOT run.
Needs only a JDK 21 (a JRE with the `jdk.compiler` module is enough: `java -m jdk.compiler/com.sun.tools.javac.Main`).

    # 1. unit tests (JUnit stub, no junit jar needed)
    SRC=app/src; javac -d out tools/sandbox/junit-stub/org/junit/*.java tools/sandbox/junit-stub/RunAll.java \
        $(find $SRC/main/java/dev/apkrelab/ir -name '*.java') $(find $SRC/test/java -name '*.java'); java -cp out RunAll out
    # 2. harness
    (cd tools/sandbox && python3 gen_scope.py) ; javac -d h app/src/main/java/dev/apkrelab/ir/*.java tools/sandbox/Scope.java tools/sandbox/Measure.java
    # 3. per app: apktool d -f -r -o dec/X X.apk   (smali)   and   apktool d -f -s -o decm/X X.apk   (text manifest, needed for package + entries)
    java -Xmx4g -cp h Measure dec/X decm/X/AndroidManifest.xml          # add -Drescue=true or -Dchain=true for the experiments below

Apps (GitHub releases, `releases/latest`; the API is rate-limited, use `releases/expanded_assets/<tag>`): oversecured/ovaa 1.0.0 `app-debug.apk`,
satishpatnayak/AndroGoat v2.0.1, B3nac/InjuredAndroid v1.0.12, optiv/InsecureShop v1.0, rewanthtammana/Damn-Vulnerable-Bank v1.1.0,
TeamNewPipe/NewPipe v0.29.1, and `InsecureBankv2.apk` from raw.githubusercontent.com/dineshshetty/Android-InsecureBankv2/master.
Decode in a LOOP, not in parallel with `-Xmx1g` (two parallel decodes failed with a ZipFile error).

Baseline 0.68.3 (distinct flow lines): OVAA 3, InsecureBankv2 3, AndroGoat 3, InjuredAndroid 4, InsecureShop 6, DVBank 1, NewPipe 1.
`r8scan.py <decoded dir> <package>`: counts LIB-scoped classes that mention app-package types (the R8 "app code merged into a library-named class" signal).

## Big apps (the real Deep scan pipeline)
`MeasureBig <decoded dir> <text manifest> [threads]` = `ScopePlanner.groups` (apps over 6000 non-library classes) + `SsaGroups.run`, like `MainActivity.ssaFindings`.
`-Downers=40` prints the top real-drop owners (use the diagnostic TaintIr from `diag_patch.py` to get `owner.method`). `Measure` (one group, whole app) can give a
different flow count (InsecureShop 6 vs 4) because the merge in `SsaGroups` keeps distinct flows per sink; compare only like with like.
Memory: the sandbox has about 4 GB; run big apps one at a time (`-Xmx5g` is fine for one). Bitwarden = 26 groups, about 2 min with 2 threads.
`mergedscan.py <dec dir> cls.method ...` tells whether a method is an R8 "merged" switch method (`iget-byte` + `packed-switch`).
More apps (GitHub releases): thunderbird/thunderbird-android `k9mail-24.0.apk`, mastodon/mastodon-android `mastodon-githubRelease.apk`,
wikimedia/apps-android-wikipedia `app-alpha-universal-release.apk` (tag `latest`), bitwarden/android `com.x8bit.bitwarden.apk`,
element-hq/element-x-android `app-fdroid-arm64-v8a-release-signed.apk`.

Grouped-harness flows, 0.68.4: OVAA 3, InsecureBankv2 4, AndroGoat 3, InjuredAndroid 4, InsecureShop 4, DVBank 1, NewPipe 1, Mastodon 3, K-9 0, Wikipedia 5, Element 0 (Bitwarden 20, mostly false: see HANDOFF "Open").

0.68.5: `MeasureBig` prints `[severity/confidence]` per flow line, so a before/after diff shows confidence changes. Compare two builds by compiling the `ir` package of each into its own folder (`hbase`, `hnew`) and diffing the `FLOWS` block (cut the text after ` | Data from`).
Grouped-harness flows, 0.68.5: same flow counts as 0.68.4 on all apps; Bitwarden 20 flows, all LOW confidence now (0.68.4: 12 HIGH, 7 MEDIUM, 1 LOW).

## 0.69.1: guarded components (`GuardList` + `MeasureBig -Dguard.file`)
`GuardList.java` runs the REAL Kotlin `ManifestContext` + `PermissionGuard` on a text manifest and writes the exported components behind a signature-level permission (one smali type per line). It needs the Kotlin classes:
download `kotlin-compiler-2.3.21.zip` from the JetBrains/kotlin GitHub release, add a tiny `android.content.Context` / `pm.PackageManager` / `pm.PermissionInfo` / `res.AssetManager` Java stub (only the methods `PermissionGuard` and `ScanLibraries` touch), `org.json` from the apt package `libandroid-json-org-java`, then
`kotlinc -cp stubs:json.jar -d kout <every src/main/.../dev/apkrelab/*.kt that has no android/androidx import, except Rebuild.kt> PermissionGuard.kt`, `javac -cp kout:kotlin-stdlib.jar -d gl GuardList.java`,
`java -cp gl:kout:stubs:kotlin-stdlib.jar:json.jar GuardList decm/X/AndroidManifest.xml g_X.txt`, then `java -Dguard.file=g_X.txt -cp h MeasureBig dec/X decm/X/AndroidManifest.xml 2`. Without `-Dguard.file` the harness behaves as before.
Permissions this manifest does not declare are resolved by a table in `GuardList` (`android.permission.BIND_*` = signature); unknown = WEAK. Baseline 0.69.1: flows identical to 0.68.6 on 15 apps (see HANDOFF).
