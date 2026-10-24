# Version inference (0.88.0): what was measured

Corpus: 37 real APKs (30 with an apktool decode for the class text of the probe classes). Inventory as the app builds it: exact versions + package-path rows (version "?").
Unknown-version libraries before: 164 of 2,101 in the 30 apps (198 of 2,637 in 37).

Facts found first (they decided the design):
- None of the 21 most frequent unknown-version libraries (Guava, Okio, Gson, jsoup, Retrofit, protobuf-javalite, slf4j, Glide, commons-io, ...) has an exact-version row in ANY of the 37 APKs.
  So there is no ground truth in the corpus to build or test a class-set fingerprint on, and Maven Central / OSV / maven.google.com are not reachable from the sandbox to get jars.
  A fingerprint table built without that data would be invented numbers; it was NOT built.
- What the APKs do carry is the library's own constants: `com.google.gson.internal.GsonBuildConfig.VERSION` (9 of 37 APKs), `kotlin.KotlinVersion` / `KotlinVersionCurrentValue` (three ints given to a
  constructor), a library's root `BuildConfig.VERSION_NAME` (Conscrypt, firebase-common) - plain text in the smali.

Result of the probes on the 30 decoded apps: 9 unknown versions resolved (Gson 6, firebase-common 2, Conscrypt 1) = 5.5% of the 164, + 10 new Kotlin-stdlib rows (not in the inventory before).
Remaining unknown: androidx-libraries 30 (aggregate, no single version), Guava 15, Okio 12, jitpack-libraries 11, play-services 9, jsoup 6, slf4j 6, Glide 6, transport-runtime 6, Retrofit 6, Coil 5, commons-io 5.
Vulnerabilities newly visible through a probed version (all version-based, reach not checked): InsecureShop Gson 2.8.6 (CVE-2022-25647, HIGH), InsecureShop Kotlin stdlib 1.3.72 (2 advisories), Termux Kotlin stdlib 1.5.10 (1 advisory).
Cross-check of one value against the project's own build file: Markor `gson:2.10.1` in its app/build.gradle = the value read from the APK. Two probed versions of the first design were WRONG and were
caught by this run: an aggregate group ("androidx-libraries 1.0", "jitpack-libraries 1.6.0") and a BuildConfig of a sub-package (firebase-installations read as firebase-common): fixed (root package of a single library only).

For the libraries that stay unknown, the report now ends the SCA table with a "check the resolved version in the project" block: one `./gradlew :app:dependencyInsight --dependency <artifact>` per library that
has advisories, most severe first, with "safe from X".
