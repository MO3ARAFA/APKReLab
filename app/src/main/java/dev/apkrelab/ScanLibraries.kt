package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Properties
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * 0.45.0: software composition analysis (SCA). Finds the third-party libraries inside a BUILT apk, lists them (SBOM) and compares
 * each one with a SMALL, hand-checked table of known vulnerable versions. Fully offline: no network, no database download.
 *
 * Where a library and its version can be read from (in order of reliability):
 *  1. `META-INF/<group>_<artifact>.version`  (AndroidX, Google / Play services, Android Support Library: the file holds the version);
 *  2. `META-INF/maven/<group>/<artifact>/pom.properties` (kept by some build setups; AGP strips it by default);
 *  3. native libraries: version strings inside the .so files under `lib/<abi>/` (OpenSSL, libcurl, zlib, libpng);
 *  4. dex string constants: `okhttp/<version>` (the User-Agent literal).
 * Most plain Java libraries (Gson, Retrofit, Jackson ...) leave NO version marker in a release APK, so they are listed only when
 * source 2 exists. THIS IS A LIMIT: an empty result is not proof that the app is clean.
 *
 * Findings carry `file` (the evidence path), so they travel with the resource findings (MainActivity replaces them on every scan).
 * To add a vulnerability: one entry in `assets/vulns.json` (0.47.2; the built-in list in [builtinVulns] is only the fallback). Ranges are [from, to) and "" means unbounded.
 * 0.47.0: package-path heuristics (ScaScanner.kt) add versionless libraries to [inventory] via [mergeInventory];
 * [findingsFor] is public so MainActivity can regenerate the findings after that merge (unmaintained libraries
 * are flagged even without a version).
 */

// ---------------------------------------------------------------------------------------------------------------------
// versions
// ---------------------------------------------------------------------------------------------------------------------

class LibVersion(val parts: List<Int>, val raw: String) : Comparable<LibVersion> {
    override fun compareTo(other: LibVersion): Int {
        val n = maxOf(parts.size, other.parts.size)
        for (i in 0 until n) {
            val a = if (i < parts.size) parts[i] else 0
            val b = if (i < other.parts.size) other.parts[i] else 0
            if (a != b) return a.compareTo(b)
        }
        return 0
    }

    companion object {
        private val plain = Regex("^v?(\\d+(?:\\.\\d+){0,4})")
        private val ssl = Regex("^(\\d+)\\.(\\d+)\\.(\\d+)([a-z]{0,3})$")

        /** "2.17.1", "4.1.71.Final", "1.2.11" -> numeric prefix; qualifiers (-beta, .Final) are ignored. */
        fun parse(s: String): LibVersion? {
            val t = s.trim()
            val m = plain.find(t) ?: return null
            val nums = m.groupValues[1].split('.').mapNotNull { it.toIntOrNull() }
            if (nums.isEmpty()) return null
            return LibVersion(nums, t)
        }

        /** OpenSSL letter releases: 1.1.1k -> [1,1,1,11]; 1.0.2zd -> [1,0,2,30] (each 'z' counts 26). */
        fun parseOpenSsl(s: String): LibVersion? {
            val t = s.trim()
            val m = ssl.find(t) ?: return parse(t)
            val g = m.groupValues
            val a = g[1].toIntOrNull() ?: return null
            val b = g[2].toIntOrNull() ?: return null
            val c = g[3].toIntOrNull() ?: return null
            var letter = 0
            for (ch in g[4]) letter += if (ch == 'z') 26 else (ch - 'a' + 1)
            return LibVersion(listOf(a, b, c, letter), t)
        }

        fun parseFor(group: String, artifact: String, s: String): LibVersion? =
            if (group == "native" && artifact == "openssl") parseOpenSsl(s) else parse(s)
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// data
// ---------------------------------------------------------------------------------------------------------------------

class DetectedLib(val group: String, val artifact: String, val version: String, val evidence: String, val source: String) {
    // 0.47.1: a path-only detection ("?") has no version: emit a purl without "@?" (which is not a valid purl)
    val purl: String get() {
        val v = if (version == "?") "" else "@$version"
        return if (group == "native") "pkg:generic/$artifact$v" else "pkg:maven/$group/$artifact$v"
    }
    val label: String get() = if (group == "native") artifact else "$group:$artifact"
}

/** One known vulnerability (or end-of-life notice) of a library. [ranges] are [from, to) pairs, "" = unbounded. */
class LibVuln(
    val group: String,
    val artifact: String,
    val ranges: List<Pair<String, String>>,
    val id: String,
    val severity: Severity,
    val summary: String,
    val fixed: String,
    val note: String = "",
    val cwe: String = "CWE-1395",
    val advisory: Boolean = false
) {
    fun affects(v: LibVersion): Boolean {
        for (r in ranges) {
            val lo = if (r.first.isEmpty()) null else LibVersion.parseFor(group, artifact, r.first)
            val hi = if (r.second.isEmpty()) null else LibVersion.parseFor(group, artifact, r.second)
            if (r.first.isNotEmpty() && lo == null) continue
            if (r.second.isNotEmpty() && hi == null) continue
            if (lo != null && v < lo) continue
            if (hi != null && v >= hi) continue
            return true
        }
        return false
    }
}

class LibScanResult(val findings: List<Finding>, val stats: String)

// ---------------------------------------------------------------------------------------------------------------------
// scanner
// ---------------------------------------------------------------------------------------------------------------------

object LibraryScanner {
    private const val MAX_SO = 24_000_000L
    private const val MAX_DEX = 64_000_000L
    private const val MAX_TOTAL = 160_000_000L
    private const val MAX_MILLIS = 25_000L

    /** Libraries found in the last scanned APK (read by the report). Replaced at the start of every scan. */
    @Volatile var inventory: List<DetectedLib> = emptyList()

    // ----- known vulnerable versions: ONLY entries that were checked by hand; this is not a full database -----
    private val builtinVulns: List<LibVuln> = listOf(
        LibVuln("org.apache.logging.log4j", "log4j-core", listOf("2.0" to "2.15.0"), "CVE-2021-44228", Severity.CRITICAL,
            "Log4Shell: remote code execution through JNDI lookups in logged messages", "2.17.1 or newer",
            "Rare on Android; it matters only if untrusted text is logged through Log4j."),
        LibVuln("org.apache.logging.log4j", "log4j-core", listOf("2.15.0" to "2.17.0"), "CVE-2021-45046 / CVE-2021-45105", Severity.HIGH,
            "incomplete Log4Shell fix (lookup bypass) and denial of service through recursive lookups", "2.17.1 or newer"),
        LibVuln("org.apache.commons", "commons-text", listOf("1.5" to "1.10.0"), "CVE-2022-42889", Severity.HIGH,
            "Text4Shell: StringSubstitutor interpolation can run script / DNS / URL lookups on untrusted input", "1.10.0 or newer",
            "Exploitable only if untrusted text goes through StringSubstitutor.createInterpolator()."),
        LibVuln("com.squareup.okhttp", "okhttp", listOf("" to "2.7.5"), "CVE-2016-2402", Severity.MEDIUM,
            "certificate pinning can be bypassed by a man-in-the-middle", "2.7.5 or newer (preferably OkHttp 4)"),
        LibVuln("com.squareup.okhttp3", "okhttp", listOf("3.0.0" to "3.2.0"), "CVE-2016-2402", Severity.MEDIUM,
            "certificate pinning can be bypassed by a man-in-the-middle", "3.2.0 or newer (preferably OkHttp 4)"),
        LibVuln("com.google.code.gson", "gson", listOf("" to "2.8.9"), "CVE-2022-25647", Severity.HIGH,
            "denial of service while deserializing untrusted JSON (unbounded recursion)", "2.8.9 or newer"),
        // 0.47.0: wider insecure-deserialization / archive / networking coverage
        LibVuln("com.fasterxml.jackson.core", "jackson-databind", listOf("" to "2.9.10"), "CVE-2017-7525 / CVE-2019-12384", Severity.CRITICAL,
            "polymorphic deserialization gadget chains: a JSON payload from the network can run code when default typing (or an open @JsonTypeInfo) is enabled", "2.9.10.8 or newer (and never enable default typing for untrusted input)",
            "Exploitable only when default typing / polymorphic handling is turned on for attacker-controlled JSON."),
        LibVuln("com.fasterxml.jackson.core", "jackson-databind", listOf("2.9.10" to "2.13.0"), "advisory", Severity.LOW,
            "this Jackson line is behind a long series of deserialization and denial-of-service fixes", "2.13.2.1 or newer (current 2.17.x line)", advisory = true),
        LibVuln("com.squareup.okhttp3", "okhttp", listOf("" to "3.12.1"), "advisory", Severity.LOW,
            "this OkHttp 3.x release predates the modern TLS defaults and is no longer fixed", "OkHttp 4.x (4.12.0 or newer)", advisory = true),
        LibVuln("org.apache.commons", "commons-compress", listOf("" to "1.21"), "CVE-2021-35515 / CVE-2021-35516 / CVE-2021-35517 / CVE-2021-36090", Severity.HIGH,
            "crafted archive (7z/TAR) exhausts CPU or memory while unpacking (denial of service); classic Zip Slip sink when entries are extracted without path checks", "1.21 or newer (current 1.26.x line)"),
        LibVuln("org.apache.commons", "commons-compress", listOf("1.21" to "1.26.0"), "CVE-2024-25710 / CVE-2024-26308", Severity.MEDIUM,
            "infinite loop / out-of-memory while unpacking a crafted archive", "1.26.0 or newer"),
        LibVuln("org.zeroturnaround", "zt-zip", listOf("" to "1.13"), "CVE-2018-1002201", Severity.HIGH,
            "ZipUtil.unpack writes entries outside the target directory when the archive contains ../ paths", "1.13 or newer"),
        LibVuln("net.lingala.zip4j", "zip4j", listOf("" to "2.11.3"), "CVE-2023-22899", Severity.MEDIUM,
            "the MAC of an AES-encrypted zip entry is not always verified when decrypting, so a tampered archive can be accepted", "2.11.3 or newer"),
        LibVuln("com.google.guava", "guava", listOf("" to "32.0.0"), "CVE-2023-2976 / CVE-2020-8908", Severity.MEDIUM,
            "Files.createTempDir gives world-readable temp folders (local information disclosure on shared devices)", "32.1.2-android or newer"),
        LibVuln("com.google.protobuf", "protobuf-java", listOf("" to "3.19.2"), "CVE-2021-22569 / CVE-2022-1941", Severity.HIGH,
            "denial of service while parsing a crafted message", "3.19.2+ / 3.21.7+ (current 4.x line)"),
        LibVuln("com.google.protobuf", "protobuf-javalite", listOf("" to "3.21.7"), "CVE-2022-1941", Severity.HIGH,
            "denial of service while parsing a crafted message", "3.21.7 or newer"),
        LibVuln("org.jsoup", "jsoup", listOf("" to "1.14.2"), "CVE-2021-37714", Severity.MEDIUM,
            "cross-site scripting when cleaning crafted HTML", "1.14.2 or newer"),
        LibVuln("com.fasterxml.jackson.core", "jackson-databind", listOf("2.13.0" to "2.13.2.1"), "CVE-2020-36518", Severity.HIGH,
            "denial of service through deeply nested JSON (stack overflow)", "2.12.6.1 / 2.13.2.1 or newer"),
        LibVuln("commons-collections", "commons-collections", listOf("" to "3.2.2"), "CVE-2015-6420", Severity.HIGH,
            "unsafe deserialization gadget chain (InvokerTransformer)", "3.2.2 or newer",
            "Exploitable only if the app deserializes untrusted data with ObjectInputStream."),
        LibVuln("org.apache.commons", "commons-collections4", listOf("4.0" to "4.1"), "CVE-2015-6420", Severity.HIGH,
            "unsafe deserialization gadget chain (InvokerTransformer)", "4.1 or newer",
            "Exploitable only if the app deserializes untrusted data with ObjectInputStream."),
        LibVuln("com.squareup.retrofit2", "retrofit", listOf("2.0.0" to "2.5.0"), "CVE-2018-1000850", Severity.HIGH,
            "path traversal through a user-controlled @Path parameter (../ is not neutralised)", "2.5.0 or newer"),
        LibVuln("io.netty", "netty-codec-http", listOf("" to "4.1.71"), "CVE-2021-43797", Severity.MEDIUM,
            "HTTP request smuggling through control characters in header names", "4.1.71.Final or newer"),
        LibVuln("com.google.android.play", "core", listOf("" to "1.7.2"), "CVE-2020-8913", Severity.HIGH,
            "Play Core local code execution: another app can make this app load its code", "1.7.2 or newer (the library is also deprecated)"),
        LibVuln("org.bouncycastle", "bcprov-jdk15on", listOf("" to "1.66"), "CVE-2020-15522", Severity.MEDIUM,
            "timing side channel in ECDSA signature verification", "1.66 or newer (bcprov-jdk18on)"),
        // native libraries (versions read from strings inside the .so files of lib/<abi>/)
        LibVuln("native", "openssl", listOf("1.0.1" to "1.0.1g"), "CVE-2014-0160", Severity.CRITICAL,
            "Heartbleed: the server or client leaks process memory (keys, session data)", "1.0.1g or newer (use a supported branch)"),
        LibVuln("native", "openssl", listOf("1.0.2" to "1.0.2zd", "1.1.1" to "1.1.1n", "3.0.0" to "3.0.2"), "CVE-2022-0778", Severity.HIGH,
            "infinite loop while parsing a crafted certificate (denial of service)", "1.0.2zd / 1.1.1n / 3.0.2 or newer"),
        LibVuln("native", "openssl", listOf("" to "1.1.1"), "EOL", Severity.MEDIUM,
            "this OpenSSL branch (1.0.x / 1.1.0 or older) has not received security fixes for years", "a supported release (3.x)",
            "", "CWE-1104"),
        LibVuln("native", "openssl", listOf("1.1.1" to "1.1.2"), "EOL", Severity.LOW,
            "OpenSSL 1.1.1 reached end of life in September 2023", "a supported release (3.x)", "", "CWE-1104"),
        LibVuln("native", "curl", listOf("7.69.0" to "8.4.0"), "CVE-2023-38545", Severity.HIGH,
            "heap buffer overflow in the SOCKS5 proxy handshake (long host name)", "8.4.0 or newer",
            "Reachable only when the app uses curl through a SOCKS5 proxy."),
        LibVuln("native", "zlib", listOf("" to "1.2.12"), "CVE-2018-25032", Severity.HIGH,
            "memory corruption while compressing input with many distant matches", "1.2.12 or newer"),
        LibVuln("native", "zlib", listOf("" to "1.2.13"), "CVE-2022-37434", Severity.HIGH,
            "heap overflow in inflate() with a large gzip header extra field", "1.2.13 or newer",
            "Reachable only when the code calls inflateGetHeader()."),
        LibVuln("native", "libpng", listOf("" to "1.6.37"), "CVE-2019-7317", Severity.MEDIUM,
            "use-after-free in png_image_free", "1.6.37 or newer")
    )

    /**
     * 0.47.2: the table in use. Starts as [builtinVulns] (fallback); [loadDb] replaces it with `assets/vulns.json`
     * so a new CVE needs no Kotlin change. KEEP THE TWO IN SYNC when editing (the JSON is the one to edit first).
     */
    @Volatile private var vulns: List<LibVuln> = builtinVulns
    @Volatile var dbSource: String = "built-in"

    fun loadDb(ctx: android.content.Context) {
        try {
            val text = ctx.assets.open("vulns.json").use { it.readBytes() }.toString(Charsets.UTF_8)
            val arr = JSONObject(text).getJSONArray("vulns")
            val out = ArrayList<LibVuln>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val rj = o.getJSONArray("ranges")
                val ranges = ArrayList<Pair<String, String>>()
                for (k in 0 until rj.length()) {
                    val pr = rj.getJSONArray(k)
                    ranges.add(Pair(pr.getString(0), pr.getString(1)))
                }
                out.add(LibVuln(o.getString("group"), o.getString("artifact"), ranges, o.getString("id"),
                    Severity.valueOf(o.getString("severity")), o.getString("summary"), o.getString("fixed"),
                    o.optString("note", ""), o.optString("cwe", "CWE-1395"), o.optBoolean("advisory", false)))
            }
            if (out.isNotEmpty()) {
                vulns = out
                dbSource = "assets/vulns.json (" + out.size + ")"
            }
        } catch (_: Throwable) {
            vulns = builtinVulns
            dbSource = "built-in"
            RuleRegistry.noteError("sca-db")
        }
    }

    /** Libraries that are deprecated / unmaintained as a whole. [minVersion] "" = every version. */
    private class Unmaintained(val group: String, val artifact: String, val minVersion: String, val title: String, val text: String)

    private val unmaintained: List<Unmaintained> = listOf(
        Unmaintained("com.android.support", "", "", "Legacy Android Support Library",
            "The android.support.* libraries ended at version 28.0.0 and get no security fixes; AndroidX replaces them."),
        Unmaintained("com.squareup.okhttp", "okhttp", "", "OkHttp 1.x / 2.x (end of life)",
            "The okhttp (2.x) line has not been fixed since 2016; OkHttp 4.x is the maintained successor."),
        Unmaintained("com.squareup.retrofit", "retrofit", "", "Retrofit 1.x (end of life)",
            "Retrofit 1.x is unmaintained since 2016; Retrofit 2.x is the successor."),
        Unmaintained("org.apache.httpcomponents", "httpclient", "", "Legacy Apache HttpClient",
            "The Android-bundled Apache HttpClient was removed from the SDK and gets no security fixes; use OkHttp or HttpURLConnection."),
        Unmaintained("com.google.android.play", "core", "1.7.2", "Play Core (deprecated)",
            "Google deprecated the monolithic Play Core library; use the split Play libraries (feature-delivery, app-update, review).")
    )

    // ----- native / dex string patterns -----
    private class StrPat(val artifact: String, val anchor: String, val rx: Regex)

    private val nativePats: List<StrPat> = listOf(
        StrPat("openssl", "OpenSSL ", Regex("OpenSSL (\\d\\.\\d\\.\\d{1,2}[a-z]{0,3}) +\\d{1,2} [A-Z][a-z]{2} \\d{4}")),
        StrPat("curl", "libcurl/", Regex("libcurl/(\\d+\\.\\d+\\.\\d+)")),
        StrPat("zlib", "flate ", Regex("(?:de|in)flate (\\d\\.\\d\\.\\d{1,2}(?:\\.\\d{1,2})?) Copyright")),
        StrPat("libpng", "libpng version ", Regex("libpng version (\\d\\.\\d+\\.\\d+)"))
    )
    private val okhttpPat = StrPat("okhttp", "okhttp/", Regex("okhttp/(\\d+\\.\\d+\\.\\d+(?:-[A-Za-z0-9.]+)?)"))
    // 0.49.2: BouncyCastleProvider's INFO literal ("BouncyCastle Security Provider v1.70"); the jdk15on line ended at 1.70
    private val bcPat = StrPat("bcprov", "BouncyCastle Security Provider v", Regex("BouncyCastle Security Provider v(\\d+\\.\\d+)"))

    // ----- helpers -----

    private fun indexOf(hay: ByteArray, needle: ByteArray, from: Int): Int {
        if (needle.isEmpty() || hay.size < needle.size) return -1
        val first = needle[0]
        val last = hay.size - needle.size
        var i = from
        while (i <= last) {
            if (hay[i] == first) {
                var j = 1
                while (j < needle.size && hay[i + j] == needle[j]) j++
                if (j == needle.size) return i
            }
            i++
        }
        return -1
    }

    /** Every match of [p] in [bytes] (at most [cap] anchors looked at). */
    private fun versionsIn(bytes: ByteArray, p: StrPat, cap: Int): List<String> {
        val out = ArrayList<String>()
        val anchor = p.anchor.toByteArray(Charsets.ISO_8859_1)
        var from = 0
        var n = 0
        while (n < cap) {
            val idx = indexOf(bytes, anchor, from)
            if (idx < 0) break
            val start = maxOf(0, idx - 3)
            val len = minOf(110, bytes.size - start)
            val window = String(bytes, start, len, Charsets.ISO_8859_1)
            val m = p.rx.find(window)
            if (m != null) out.add(m.groupValues[1])
            from = idx + anchor.size
            n++
        }
        return out.distinct()
    }

    private fun pickAbi(entries: List<ZipEntry>): String? {
        val abis = HashSet<String>()
        for (e in entries) {
            val seg = e.name.split('/')
            if (seg.size >= 3 && seg[1].isNotEmpty()) abis.add(seg[1])
        }
        for (pref in listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")) if (abis.contains(pref)) return pref
        return abis.sorted().firstOrNull()
    }

    // ----- detection -----

    fun detect(apk: File, counts: IntArray): List<DetectedLib> {
        val found = LinkedHashMap<String, DetectedLib>()
        fun add(l: DetectedLib, slot: Int) {
            if (found.putIfAbsent(l.group + ":" + l.artifact + ":" + l.version, l) == null) counts[slot]++
        }
        val started = System.currentTimeMillis()
        ZipFile(apk).use { zip ->
            val soEntries = ArrayList<ZipEntry>()
            val dexEntries = ArrayList<ZipEntry>()
            for (e in zip.entries()) {
                if (e.isDirectory) continue
                val n = e.name
                try {
                    if (n.startsWith("META-INF/maven/") && n.endsWith("/pom.properties") && e.size > 0 && e.size <= 16384L) {
                        val p = Properties()
                        zip.getInputStream(e).use { p.load(it) }
                        val v = p.getProperty("version")?.trim().orEmpty()
                        var g = p.getProperty("groupId")?.trim().orEmpty()
                        var a = p.getProperty("artifactId")?.trim().orEmpty()
                        if (g.isEmpty() || a.isEmpty()) {
                            val seg = n.removePrefix("META-INF/maven/").split('/')
                            if (seg.size >= 2) {
                                if (g.isEmpty()) g = seg[0]
                                if (a.isEmpty()) a = seg[1]
                            }
                        }
                        if (v.isNotEmpty() && g.isNotEmpty() && a.isNotEmpty()) add(DetectedLib(g, a, v, n, "pom.properties"), 1)
                    } else if (n.startsWith("META-INF/") && n.endsWith(".version") && n.indexOf('/', 9) < 0 && e.size > 0 && e.size <= 256L) {
                        val base = n.removePrefix("META-INF/").removeSuffix(".version")
                        val us = base.indexOf('_')
                        if (us > 0 && us < base.length - 1) {
                            val text = zip.getInputStream(e).use { it.readBytes() }.toString(Charsets.UTF_8)
                                .trim().lineSequence().firstOrNull().orEmpty().trim()
                            if (text.isNotEmpty() && text.length <= 40 && text[0].isDigit()) {
                                add(DetectedLib(base.substring(0, us), base.substring(us + 1), text, n, "version file"), 0)
                            }
                        }
                    } else if (n.startsWith("lib/") && n.endsWith(".so")) {
                        soEntries.add(e)
                    } else if (n.endsWith(".dex") && n.indexOf('/') < 0) {
                        dexEntries.add(e)
                    }
                } catch (_: Throwable) {
                    RuleRegistry.noteError("sca-meta")
                }
            }

            var total = 0L
            // native libraries: one ABI only (the same libraries are repeated for every ABI)
            val abi = pickAbi(soEntries)
            if (abi != null) {
                for (e in soEntries) {
                    if (System.currentTimeMillis() - started > MAX_MILLIS || total > MAX_TOTAL) break
                    if (!e.name.startsWith("lib/$abi/")) continue
                    if (e.size < 4096L || e.size > MAX_SO) continue
                    try {
                        val bytes = zip.getInputStream(e).use { it.readBytes() }
                        total += bytes.size
                        for (p in nativePats) {
                            for (v in versionsIn(bytes, p, 40)) add(DetectedLib("native", p.artifact, v, e.name, "native string"), 2)
                        }
                    } catch (_: Throwable) {
                        RuleRegistry.noteError("sca-native")
                    }
                }
            }
            // dex string constants (okhttp User-Agent literal)
            for (e in dexEntries) {
                if (System.currentTimeMillis() - started > MAX_MILLIS || total > MAX_TOTAL) break
                if (e.size < 1024L || e.size > MAX_DEX) continue
                try {
                    val bytes = zip.getInputStream(e).use { it.readBytes() }
                    total += bytes.size
                    for (v in versionsIn(bytes, okhttpPat, 20)) {
                        val major = v.substringBefore('.').toIntOrNull() ?: 0
                        val g = if (major >= 3) "com.squareup.okhttp3" else "com.squareup.okhttp"
                        add(DetectedLib(g, "okhttp", v, e.name, "dex string"), 3)
                    }
                    for (v in versionsIn(bytes, bcPat, 5)) {
                        val minor = v.substringAfter('.').toIntOrNull() ?: 0
                        val art = if (v.substringBefore('.') == "1" && minor <= 70) "bcprov-jdk15on" else "bcprov-jdk18on"
                        add(DetectedLib("org.bouncycastle", art, v, e.name, "dex string"), 3)
                    }
                } catch (_: Throwable) {
                    RuleRegistry.noteError("sca-dex")
                }
            }
        }
        return found.values.toList()
    }

    // ----- matching and findings -----

    fun matches(l: DetectedLib): List<LibVuln> {
        val v = LibVersion.parseFor(l.group, l.artifact, l.version) ?: return emptyList()
        return vulns.filter { it.group == l.group && it.artifact == l.artifact && it.affects(v) }
    }

    /**
     * 0.49.2: for a library whose version is unknown ("?"), the hand-checked CVE entries that exist for the same coordinates,
     * so the report can say "not checked, but these CVEs exist for older versions" instead of a bare OK.
     */
    fun watchFor(l: DetectedLib): List<LibVuln> =
        if (l.version != "?") emptyList() else vulns.filter { it.group == l.group && it.artifact == l.artifact && !it.advisory }

    private fun confidenceOf(l: DetectedLib): String =
        if (l.source == "version file" || l.source == "pom.properties") "HIGH" else "MEDIUM"

    private fun make(f: Finding, rule: String, conf: String): Finding {
        f.ruleId = rule
        f.confidence = conf
        return f
    }

    /**
     * 0.47.0: merges package-path detections (ScaScanner, version "?") into the inventory.
     * A library already identified with an exact version is NOT duplicated (exact wins);
     * a versionless row is dropped if the same group:artifact is already listed with a version.
     * Returns the new inventory.
     */
    @Synchronized
    fun mergeInventory(extra: List<DetectedLib>): List<DetectedLib> {
        if (extra.isEmpty()) return inventory
        val cur = inventory.toMutableList()
        val have = cur.mapTo(HashSet()) { it.group + ":" + it.artifact }
        // 0.49.2: a versioned bcprov-jdk15on / jdk18on already known: do not add the path-only twin under the other name
        for (l in cur) if (l.artifact.contains("-jdk")) have.add(l.group + ":" + l.artifact.substringBefore("-jdk") + "-jdk*")
        for (l in extra) {
            val key = l.group + ":" + l.artifact
            val twin = if (l.artifact.contains("-jdk")) l.group + ":" + l.artifact.substringBefore("-jdk") + "-jdk*" else key
            if (l.version == "?" && have.contains(twin)) continue
            if (have.add(key)) cur.add(l)
        }
        inventory = cur
        return cur
    }

    @Synchronized
    fun scanApk(apk: File): LibScanResult {
        inventory = emptyList()
        val counts = IntArray(4)   // version files, pom.properties, native strings, dex strings
        val libs = detect(apk, counts)
        inventory = libs
        val stats = "libraries " + libs.size + " (version files " + counts[0] + ", pom " + counts[1] + ", native " + counts[2] +
            ", dex " + counts[3] + ")"
        return LibScanResult(findingsFor(libs), stats)
    }

    /**
     * Builds the vulnerability / unmaintained / SBOM findings for a library list. Public since 0.47.0 so
     * MainActivity can regenerate them after ScaScanner's package-path detections were merged in.
     * Libraries with version "?" (path-only) skip version matching but still count for unmaintained and the SBOM.
     */
    fun findingsFor(libs: List<DetectedLib>): List<Finding> {
        val out = ArrayList<Finding>()
        var vulnerable = 0

        for (l in libs) {
            try {
                val all = matches(l)
                // 0.47.2: general advisories (no CVE id) are reported separately, as a LOW "outdated" notice
                val adv = all.filter { it.advisory }
                if (adv.isNotEmpty()) {
                    val txt = l.label + " " + l.version + " found by " + l.source + " in " + l.evidence + ".\n" +
                        adv.joinToString("\n") { "- " + it.summary + " (recommended: " + it.fixed + ")" } +
                        "\nThis is a general advisory, not a specific CVE."
                    out.add(make(Finding(Severity.LOW, "Outdated library: " + l.artifact + " " + l.version, txt,
                        "Upgrade " + l.label + " to " + adv.map { it.fixed }.distinct().joinToString(" / ") + ".",
                        cwe = "CWE-1104", file = l.evidence), "sca-outdated", confidenceOf(l)))
                }
                val ms = all.filter { !it.advisory }
                if (ms.isEmpty()) continue
                vulnerable++
                val top = ms.minByOrNull { it.severity.rank } ?: continue
                val ids = ms.map { it.id }
                val title = "Vulnerable library: " + l.artifact + " " + l.version + " (" + ids.first() +
                    (if (ids.size > 1) " +" + (ids.size - 1) + " more" else "") + ")"
                val sb = StringBuilder()
                sb.append(l.label).append(' ').append(l.version).append(" found by ").append(l.source).append(" in ").append(l.evidence).append(".\n")
                for (m in ms) {
                    sb.append("- ").append(m.id).append(": ").append(m.summary).append(" (fixed: ").append(m.fixed).append(")")
                    if (m.note.isNotEmpty()) sb.append(". ").append(m.note)
                    sb.append('\n')
                }
                sb.append("The version is vulnerable; whether this app reaches the vulnerable code path is NOT checked.")
                val rec = "Upgrade " + l.label + " to a fixed release (" + ms.map { it.fixed }.distinct().joinToString(" / ") +
                    ") or remove the dependency, then rebuild."
                out.add(make(Finding(top.severity, title, sb.toString(), rec, cwe = top.cwe, file = l.evidence), "sca-known-vuln", confidenceOf(l)))
            } catch (_: Throwable) {
                RuleRegistry.noteError("sca-match")
            }
        }

        // deprecated / unmaintained libraries (aggregated: one finding per rule)
        for (u in unmaintained) {
            try {
                val hits = libs.filter { l ->
                    l.group == u.group && (u.artifact.isEmpty() || l.artifact == u.artifact) && run {
                        // 0.47.0: a versionless path detection (version "?") counts as present - the
                        // library is deprecated as a whole, so ANY version would match minVersion.
                        if (l.version == "?") true
                        else if (u.minVersion.isEmpty()) true else {
                            val v = LibVersion.parse(l.version)
                            val min = LibVersion.parse(u.minVersion)
                            v != null && min != null && v >= min
                        }
                    }
                }
                if (hits.isEmpty()) continue
                val names = hits.take(8).joinToString(", ") { it.artifact + " " + it.version }
                val more = if (hits.size > 8) " and " + (hits.size - 8) + " more" else ""
                out.add(make(Finding(Severity.LOW, "Unmaintained library: " + u.title + " (" + hits.size + " module(s))",
                    u.text + " Found: " + names + more + ".",
                    "Migrate to the maintained replacement and remove the old dependency.", cwe = "CWE-1104", file = hits.first().evidence),
                    "sca-unmaintained", "HIGH"))
            } catch (_: Throwable) {
                RuleRegistry.noteError("sca-unmaintained")
            }
        }

        // inventory (SBOM) as one INFO finding
        if (libs.isNotEmpty()) {
            val sb = StringBuilder()
            for (l in libs.take(60)) sb.append(l.label).append(' ').append(l.version).append("  [").append(l.source).append("]\n")
            if (libs.size > 60) sb.append("... and ").append(libs.size - 60).append(" more (see the Markdown report)\n")
            sb.append("Libraries without a version marker are not listed (most plain Java jars after R8), so this list is a lower bound.")
            out.add(make(Finding(Severity.INFO, "Embedded libraries detected: " + libs.size + " (SBOM)", sb.toString(),
                "Keep this list as the app's software bill of materials and re-check it when dependencies change.",
                file = "APK libraries (META-INF, lib/, classes.dex)"), "sca-inventory", "LOW"))
        }

        return out
    }

    // ----- SBOM export -----

    fun cycloneDx(): String {
        return try {
            val comps = JSONArray()
            for (l in inventory.take(500)) {
                val c = JSONObject()
                c.put("type", "library")
                if (l.group != "native") c.put("group", l.group)
                c.put("name", l.artifact)
                if (l.version != "?") c.put("version", l.version)
                else {
                    // path-only detection: the artifact id is the library's most likely Maven artifact, not a proven one
                    val props = JSONArray()
                    props.put(JSONObject().put("name", "apkrelab:detection").put("value", "package path; version unknown; artifact id is a best guess"))
                    c.put("properties", props)
                }
                c.put("purl", l.purl)
                comps.put(c)
            }
            val root = JSONObject()
            root.put("bomFormat", "CycloneDX")
            root.put("specVersion", "1.5")
            root.put("version", 1)
            root.put("components", comps)
            root.toString(2)
        } catch (_: Throwable) {
            ""
        }
    }

    /** Markdown block for the report; empty when the last scan found no library. */
    fun sbomMarkdown(): String {
        val inv = inventory
        if (inv.isEmpty()) return ""
        val sb = StringBuilder()
        sb.append("### Libraries (SBOM)\n\n")
        sb.append(inv.size).append(" component(s) found from version files, pom.properties, native strings and dex strings. ")
        sb.append("Libraries without a version marker cannot be listed, so this is a lower bound, not proof that nothing else is bundled.\n\n")
        sb.append("| Component | Version | Source | Evidence |\n|---|---|---|---|\n")
        for (l in inv.take(300)) {
            sb.append("| ").append(l.label).append(" | ").append(l.version).append(" | ").append(l.source)
                .append(" | `").append(l.evidence).append("` |\n")
        }
        val bom = cycloneDx()
        if (bom.isNotEmpty()) sb.append("\nCycloneDX 1.5 (JSON):\n\n```json\n").append(bom).append("\n```\n")
        sb.append('\n')
        return sb.toString()
    }
}
