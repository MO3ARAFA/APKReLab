# Real Gradle build (0.108.0)

The owner builds APKReLab on the phone with Code on the Go. To verify a change on a Linux PC or container:

    tools/sandbox/gradle_build.sh                      # assembleDebug + testDebugUnitTest + lintDebug
    tools/sandbox/gradle_build.sh :app:assembleDebug   # any tasks

Verified versions (0.108.0, 2026-10-24): AGP 9.3.1 (built-in Kotlin, no Kotlin plugin applied in :app), Gradle 9.8.2, OpenJDK 21, compileSdk 36,
build-tools 36.1.0 (AGP also fetches 36.0.0 itself). Results: assembleDebug OK (debug APK about 12.9 MB), testDebugUnitTest 648 tests / 0 failures
(= the two sandbox harnesses: Kotlin 340 + ir 308), lintDebug 0 errors (198 warnings, mostly hard-coded UI strings).

Notes:
- No Gradle wrapper is committed (Code on the Go brings its own Gradle).
- Maven Central answered HTTP 429 to the sandbox; the script puts Google's mirror of Maven Central first in a build-local init script.
- The build runs on a copy (`~/apkbuild`): `private/` (company APKs and reports) is never copied.
