# Rebuilding the sandbox toolchain from nothing (what the previous assistant used; ~10 minutes)

Needs: JDK 21 (javac), python3, curl, unzip. No Android SDK, no Gradle.

    mkdir -p ~/tc && cd ~/tc
    # Kotlin compiler 2.3.21
    curl -L -o kotlin.zip https://github.com/JetBrains/kotlin/releases/download/v2.3.21/kotlin-compiler-2.3.21.zip && unzip -q kotlin.zip
    # apktool (decode APKs to smali and to a text manifest)
    curl -L -o apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar
    # org.json (Android flavour) from the Debian package libandroid-json-org-java: apt-get download it, dpkg-deb -x, use usr/share/java/json-android.jar
    # Android stubs (the few classes the non-UI Kotlin touches): already in this repo
    javac -d stubs_out $(find <repo>/tools/sandbox/android-stubs -name '*.java')
    # JUnit stub + runner
    javac -d jout <repo>/tools/sandbox/junit-stub/org/junit/*.java <repo>/tools/sandbox/junit-stub/RunAll.java

Compile the Java `ir` package, then the Kotlin sources that do NOT import android/androidx (and not Rebuild.kt), plus PermissionGuard.kt:

    javac -nowarn -d irk <repo>/app/src/main/java/dev/apkrelab/ir/*.java
    FILES=$(cd <repo>/app/src/main/java/dev/apkrelab && grep -L "^import android\|^import androidx" *.kt | grep -v '^Rebuild.kt$' | sed "s#^#<repo>/app/src/main/java/dev/apkrelab/#")
    kotlinc -nowarn -cp stubs_out:json-android.jar:irk -d kout $FILES <repo>/app/src/main/java/dev/apkrelab/PermissionGuard.kt
    kotlinc -nowarn -cp jout:kout:irk:stubs_out:json-android.jar -Xfriend-paths=kout -d tall $(find <repo>/app/src/test/java -name '*.kt')
    java -cp jout:tall:kout:irk:stubs_out:kotlin-stdlib.jar:json-android.jar RunAll tall      # Kotlin tests
    javac -d irout <repo>/tools/sandbox/junit-stub/org/junit/*.java <repo>/tools/sandbox/junit-stub/RunAll.java $(find <repo>/app/src/main/java/dev/apkrelab/ir -name '*.java') $(find <repo>/app/src/test/java -name '*.java'); java -cp irout RunAll irout   # ir tests

Scanning an APK like the Smart scan without the UI: decode (`apktool d -f -r -o dec_X X.apk` and `apktool d -f -s -o decm_X X.apk`), compile `tools/sandbox/SandboxScan.kt` against kout:irk:stubs_out, then
`java -Xmx3g -cp ss:kout:irk:stubs_out:kotlin-stdlib.jar:json-android.jar SandboxScanKt dec_X X.apk report.md [nossa|withlibs]` and `python3 tools/benchmark/bench.py report.md --expected tools/benchmark/expected_heldout/<app>.json --measure`.
Practical limits seen in a 4 GB / 5 minute-per-command sandbox (a normal PC will not have them): apps over ~20k non-library classes do not fit whole-app SSA (use `nossa`); run scans detached (setsid nohup) and poll; never rebuild `kout`/`irk` while a scan is running.
Always decode in a loop, not in parallel (two parallel apktool runs failed with a ZipFile error).
