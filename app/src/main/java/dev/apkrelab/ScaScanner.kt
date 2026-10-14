package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.47.0: package-path heuristics for software composition analysis (SCA), the second detection layer
 * on top of LibraryScanner (ScanLibraries.kt, which reads exact versions from META-INF, native strings
 * and dex string constants).
 *
 * Why a second layer: R8 release builds strip META-INF/maven and AGP strips most markers, so most plain
 * Java libraries (Gson, Retrofit, Jackson ...) leave NO version anywhere in the APK. But the CODE of the
 * library is still there, and with shrinking disabled the package path survives: `okhttp3/`,
 * `retrofit2/`, `com/google/gson/`. From the path we know WHICH library is bundled (and sometimes the
 * major version family: okhttp3/ vs com/squareup/okhttp/ = OkHttp 3.x vs 2.x), even when the exact
 * version is unknown. Detection without a version cannot be matched against version ranges, so those
 * libraries go to the inventory (SBOM) with version "?" and source "package path"; libraries that are
 * known-bad in EVERY version (unmaintained, or a CVE that affects the whole line) still raise a finding.
 *
 * Memory: this runs over the class TYPE LIST only (classDefs.map { it.type }, strings already in
 * memory for the Classes tab) - no dex bytes, no smali text, no regex per class, one prefix table walk.
 * It is O(classes x prefixes) on plain strings and adds nothing measurable to RAM or scan time.
 *
 * Output contract (same as LibraryScanner):
 *  - detected libraries merge into LibraryScanner.inventory via [LibraryScanner.mergeInventory];
 *  - findings carry `file` (the evidence path), so they travel with the resource/SCA findings in
 *    MainActivity.scanResourcesAsync and are re-published on every scan.
 */
object ScaScanner {

    /**
     * One package prefix -> one library. [pkg] is a smali package prefix (slash form, no leading L).
     * A path proves presence, not a version, so no version family is recorded (okhttp3/ is 3.x and 4.x alike;
     * the exact OkHttp version, when present, comes from the User-Agent dex string via LibraryScanner).
     */
    private class PkgRule(
        val pkg: String,
        val group: String,
        val artifact: String,
        val display: String = "$group:$artifact",
        /** 0.47.1: present in nearly every APK; stays in the SBOM but never leads the INFO summary and sorts last in the report table. */
        val lowSignal: Boolean = false
    )

    // Hand-checked prefixes of the libraries that actually show up in APKs. Keep it focused: every row
    // here is either on the vulnerable-version list, commonly security-relevant, or large enough that a
    // pentester wants it on the SBOM. Prefixes must be specific enough to not hit app code.
    private val rules: List<PkgRule> = listOf(
        // --- networking ---
        PkgRule("okhttp3/", "com.squareup.okhttp3", "okhttp"),
        PkgRule("com/squareup/okhttp/", "com.squareup.okhttp", "okhttp"),          // OkHttp 1.x/2.x (legacy line)
        PkgRule("okio/", "com.squareup.okio", "okio"),
        PkgRule("retrofit2/", "com.squareup.retrofit2", "retrofit"),
        PkgRule("retrofit/RestAdapter", "com.squareup.retrofit", "retrofit"),      // Retrofit 1.x (RestAdapter is its entry class; plain "retrofit/" could hit app code)
        PkgRule("io/netty/", "io.netty", "netty-codec-http"),
        PkgRule("org/apache/http/", "org.apache.httpcomponents", "httpclient"),    // legacy Apache HttpClient
        PkgRule("com/android/volley/", "com.android.volley", "volley"),
        PkgRule("io/grpc/", "io.grpc", "grpc-core"),
        PkgRule("io/socket/", "io.socket", "socket.io-client"),
        // --- JSON / serialization ---
        PkgRule("com/google/gson/", "com.google.code.gson", "gson"),
        PkgRule("com/fasterxml/jackson/", "com.fasterxml.jackson.core", "jackson-databind"),
        PkgRule("com/squareup/moshi/", "com.squareup.moshi", "moshi"),
        PkgRule("org/json/", "org.json", "json"),
        PkgRule("com/google/protobuf/", "com.google.protobuf", "protobuf-javalite"),
        PkgRule("org/simpleframework/", "org.simpleframework", "simple-xml"),
        // --- compression / archives (zip-slip family) ---
        PkgRule("org/apache/commons/compress/", "org.apache.commons", "commons-compress"),
        PkgRule("org/zeroturnaround/zip/", "org.zeroturnaround", "zt-zip"),
        PkgRule("net/lingala/zip4j/", "net.lingala.zip4j", "zip4j"),
        PkgRule("org/apache/commons/io/", "commons-io", "commons-io"),
        // --- crypto ---
        PkgRule("org/bouncycastle/", "org.bouncycastle", "bcprov-jdk15on"),
        PkgRule("org/conscrypt/", "org.conscrypt", "conscrypt"),
        PkgRule("net/sqlcipher/", "net.zetetic", "sqlcipher-android"),
        // --- image loading ---
        PkgRule("com/squareup/picasso/", "com.squareup.picasso", "picasso"),
        PkgRule("com/bumptech/glide/", "com.github.bumptech.glide", "glide"),
        PkgRule("com/facebook/fresco/", "com.facebook.fresco", "fresco"),
        PkgRule("coil/ImageLoader", "io.coil-kt", "coil"),
        PkgRule("coil3/", "io.coil-kt.coil3", "coil"),
        // --- reactive / utils ---
        PkgRule("io/reactivex/", "io.reactivex.rxjava2", "rxjava"),
        PkgRule("com/google/common/", "com.google.guava", "guava"),
        PkgRule("org/apache/commons/lang3/", "org.apache.commons", "commons-lang3"),
        PkgRule("org/apache/commons/text/", "org.apache.commons", "commons-text"),
        PkgRule("commons/collections/", "commons-collections", "commons-collections"),
        PkgRule("org/apache/commons/collections4/", "org.apache.commons", "commons-collections4"),
        PkgRule("org/apache/commons/collections/", "commons-collections", "commons-collections"),
        PkgRule("org/apache/logging/log4j/", "org.apache.logging.log4j", "log4j-core"),
        PkgRule("org/slf4j/", "org.slf4j", "slf4j-api"),
        PkgRule("org/jsoup/", "org.jsoup", "jsoup"),
        PkgRule("org/joda/time/", "joda-time", "joda-time"),
        PkgRule("org/threeten/bp/", "org.threeten", "threetenbp"),
        // --- google / firebase / play ---
        PkgRule("com/google/firebase/", "com.google.firebase", "firebase-common"),
        PkgRule("com/google/android/gms/", "com.google.android.gms", "play-services"),
        PkgRule("com/google/android/play/core/", "com.google.android.play", "core"),
        PkgRule("com/google/android/datatransport/", "com.google.android.datatransport", "transport-runtime"),
        // --- UI / DI / misc ---
        PkgRule("com/google/android/material/", "com.google.android.material", "material", lowSignal = true),
        PkgRule("androidx/", "androidx", "androidx-libraries", "androidx (Jetpack)", lowSignal = true),
        PkgRule("com/android/support/", "com.android.support", "support-library", "Android Support Library (legacy)"),
        PkgRule("dagger/", "com.google.dagger", "dagger"),
        PkgRule("com/jakewharton/", "com.jakewharton", "jakewharton-libraries", lowSignal = true),
        PkgRule("com/squareup/leakcanary/", "com.squareup.leakcanary", "leakcanary-android"),
        PkgRule("io/realm/", "io.realm", "realm-android"),
        PkgRule("com/github/", "com.github", "jitpack-libraries", "JitPack libraries (com.github.*)", lowSignal = true),
        // --- analytics / ads / crash reporting (large SDKs a pentester wants listed) ---
        PkgRule("com/crashlytics/", "com.crashlytics", "crashlytics"),
        PkgRule("io/sentry/", "io.sentry", "sentry-android"),
        PkgRule("com/appsflyer/", "com.appsflyer", "af-android-sdk"),
        PkgRule("com/adjust/", "com.adjust.sdk", "adjust-android"),
        PkgRule("com/onesignal/", "com.onesignal", "OneSignal-Android-SDK"),
        PkgRule("com/amplitude/", "com.amplitude", "analytics-android"),
        PkgRule("com/mixpanel/", "com.mixpanel.android", "mixpanel-android"),
        PkgRule("com/unity3d/", "com.unity3d", "unity3d-sdk"),
        PkgRule("com/applovin/", "com.applovin", "applovin-android-sdk"),
        PkgRule("com/facebook/", "com.facebook.android", "facebook-android-sdk")
    )

    /** Longest prefix wins, so put nothing here in an order that matters - matching sorts by length. */
    private val rulesByLength = rules.sortedByDescending { it.pkg.length }

    private val lowSignalKeys: Set<String> = rules.filter { it.lowSignal }.mapTo(HashSet()) { it.group + ":" + it.artifact }

    /** 0.47.1: true for libraries present in nearly every APK (androidx, material, JitPack ...): SBOM only, no summary noise. */
    fun isLowSignal(lib: DetectedLib): Boolean = lowSignalKeys.contains(lib.group + ":" + lib.artifact)

    /**
     * Scans the class type list (baksmali types "Lcom/x/Y;", already in memory) and returns one
     * [DetectedLib] per library whose package prefix is present. Version is "?" - the path proves
     * presence, not a version. `evidence` is the package path, `source` is "package path".
     * A library already identified with an exact version by LibraryScanner is NOT duplicated here:
     * merge happens in [LibraryScanner.mergeInventory].
     */
    fun scanPackages(types: List<String>, appPkg: String = ""): List<DetectedLib> {
        val found = LinkedHashMap<String, DetectedLib>()
        val seen = HashSet<String>()   // prefixes already hit: one class of a lib is enough
        // 0.47.1: exclude only the app's OWN full package (was: its first two segments, which for e.g.
        // com.google.android.apps.x hid gms/firebase/guava). And a rule is dropped when the app itself
        // lives inside that library's namespace (e.g. the app is com.facebook.katana) - app code and
        // library code cannot be told apart there.
        val appPath = if (appPkg.isNotEmpty()) appPkg.replace('.', '/') + "/" else ""
        val activeRules = if (appPath.isEmpty()) rulesByLength else rulesByLength.filter { !appPath.startsWith(it.pkg) }
        for (t in types) {
            val p = if (t.startsWith("L")) t.substring(1) else t
            if (appPath.isNotEmpty() && p.startsWith(appPath)) continue
            for (r in activeRules) {
                if (!seen.contains(r.pkg) && p.startsWith(r.pkg)) {
                    seen.add(r.pkg)
                    found[r.group + ":" + r.artifact] = DetectedLib(
                        r.group, r.artifact, "?", r.pkg + "**", "package path")
                    break   // longest match already found; no need to test shorter prefixes for this class
                }
            }
        }
        return found.values.toList()
    }

    /**
     * Findings for libraries that are flagged REGARDLESS of version (a path-only detection has no
     * version to match): the unmaintained list is evaluated here by LibraryScanner.findingsFor already,
     * so this only adds one aggregated INFO card so the UI shows the heuristic layer ran.
     */
    fun summaryFinding(pathLibs: List<DetectedLib>, exactLibs: Int): Finding? {
        val signal = pathLibs.filter { !isLowSignal(it) }   // 0.47.1: androidx/material/JitPack stay in the SBOM only
        if (signal.isEmpty()) return null
        val names = signal.take(10).joinToString(", ") { it.displayOrLabel() } +
            (if (signal.size > 10) " and " + (signal.size - 10) + " more" else "")
        return Finding(Severity.INFO,
            "Libraries identified by package path: " + signal.size,
            "These libraries are bundled in the APK (their package names survive in the dex code) but no exact version marker was found, so they cannot be matched against version-specific CVEs: " + names +
                ". " + (if (exactLibs > 0) "$exactLibs other librar(y/ies) have exact versions (META-INF / native / dex strings) and were matched." else "No library exposed an exact version marker.") +
                " Versionless detection is a lower bound: check the app build files (build.gradle) for the real dependency versions before concluding anything.",
            "Get the exact versions from the project's dependency tree (./gradlew app:dependencies) or a full SBOM build, then re-check them against the CVE list.",
            file = "APK dex packages")
            .also { it.ruleId = "sca-package-heuristics"; it.confidence = "MEDIUM" }
    }

    private fun DetectedLib.displayOrLabel(): String = label
}
