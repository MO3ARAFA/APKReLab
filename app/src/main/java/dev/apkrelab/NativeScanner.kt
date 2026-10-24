package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import java.util.zip.ZipFile

/**
 * 0.90.0: the native libraries of an APK (lib/<abi>/NAME.so), read with [ElfAnalyzer]: hardening of the ELF files, the 16 KB page-size requirement of Android 15+, the unsafe C functions
 * a library imports, and the credentials / private keys in its data sections. The native CODE is not analysed (no disassembly): what happens inside a JNI function is unknown.
 *
 * The list of known third-party libraries holds only GENERIC libraries many apps bundle (runtime, codecs, crypto, databases, frameworks); a name specific to one app is
 * "unclassified" by design: it is treated as the app's own, which is the safe direction.
 *
 * Noise policy (calibrated on 222 real libraries of 37 apps, tools/native): modern NDK builds are NX + full RELRO in 100% of them, so those flags rarely fire; a missing stack canary
 * (22 of 100) and an import of strcpy / sprintf (17 of 100) are normal in libraries the app only bundles, so they are summarised in ONE card per APK and only an app-own
 * library (not a well-known third-party one) raises a card of its own, at LOW. Only the 16 KB alignment, which Google Play enforces for apps that target Android 15+, and
 * a real hardening defect (executable stack, text relocations, no RELRO, RPATH) get MEDIUM.
 */
object NativeScanner {

    /** Libraries the app bundles but did not write: findings about them are about the dependency, one level lower. */
    private val thirdParty = Regex("^lib(c\\+\\+_shared|c\\+\\+abi|sqlcipher.*|conscrypt.*|flutter|reactnativejni.*|react_.*|hermes.*|jsc.*|jsi.*|folly.*|fbjni|mmkv|realm.*|jnidispatch|sentry.*|crashlytics.*|firebase.*|" +
        "ffmpeg.*|ffprobe.*|av(codec|format|util|filter|device)|sw(scale|resample)|tensorflow.*|tflite.*|opencv.*|gojni|go\\..*|sodium|libsodium|signal.*|zstd.*|lz4.*|xz.*|zip.*|python.*|webp.*|gif.*|jpeg.*|png.*|" +
        "image_processing_util_jni|androidx\\..*|datastore_.*|mlkit.*|barhopper.*|cronet.*|mapbox.*|sqlite.*|sqliteJni|ssl|crypto|curl.*|openssl.*|boringssl.*|protobuf.*|v8.*|unity|il2cpp|mono.*|bugsnag.*|" +
        "ssl_.*|wireguard.*|wg-go|pthread|log|android|jni|vlc.*|mpv.*|exoplayer.*|media3.*|ijk.*)\\.so$")

    fun isThirdParty(file: String): Boolean = thirdParty.matches(file)

    private val dartUrl = Regex("https?://([A-Za-z0-9][A-Za-z0-9.-]{1,80}\\.[A-Za-z]{2,24})(?::\\d+)?(?:/[^\\s\"'<>]{0,80})?")
    // documentation, schema and licence hosts that every Dart snapshot carries from its packages
    /** 0.105.0: an SPKI pin (sha256/ + base64 of 32 bytes) or a colon-separated SHA-256 fingerprint (32 hex pairs), the two forms pinning code carries. */
    private val pinRe = Regex("sha256/[A-Za-z0-9+/]{43}=|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
    private val noiseHosts = listOf("dart.dev", "flutter.dev", "pub.dev", "w3.org", "apache.org", "github.com", "githubusercontent.com", "mozilla.org", "unicode.org", "iana.org", "ietf.org",
        "example.com", "example.org", "ibm.com", "localhost", "schemas.android.com", "xmlns.com", "opensource.org", "wikipedia.org", "developer.android.com", "stackoverflow.com", "creativecommons.org",
        "gnu.org", "whatwg.org", "fb.me", "reactjs.org", "facebook.github.io", "opengis.net", "topografix.com", "sil.org", "npmjs.com", "sourceforge.net", "googlecode.com", "json-schema.org", "mit-license.org", "goo.gl", "bit.ly", "firebase.google.com", "support.google.com", "developers.google.com", "material.io", "chromium.org")
    internal fun noiseHost(h: String): Boolean = noiseHosts.any { h == it || h.endsWith(".$it") } || h.matches(Regex("^[0-9.]+$"))

    class Lib(val path: String, val abi: String, val name: String, val info: ElfAnalyzer.ElfInfo, val source: ZipFile? = null, val fromSplit: String? = null)

    /** 0.99.0: the split archives of the APK being scanned (split_config.arm64_v8a.apk ...), set by the importer; their libraries are read as if they were in the base APK. */
    @Volatile var extraArchives: List<java.io.File> = emptyList()

    /** The ELF libraries of [zip], one ABI per library name (arm64-v8a first), analysed; entries that are not ELF (a zip stored as .so) and files over 64 MB are skipped. */
    internal fun readLibs(zip: ZipFile, label: String? = null): Pair<List<Lib>, Int> {
        val byName = LinkedHashMap<String, MutableList<java.util.zip.ZipEntry>>()
        for (e in zip.entries()) {
            if (e.isDirectory || !e.name.startsWith("lib/") || !e.name.endsWith(".so")) continue
            byName.getOrPut(e.name.substringAfterLast('/')) { ArrayList() }.add(e)
        }
        val order = listOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86", "armeabi")
        val out = ArrayList<Lib>(); var notElf = 0
        for ((name, es) in byName) {
            val e = es.minByOrNull { order.indexOf(it.name.split('/')[1]).let { i -> if (i < 0) 99 else i } } ?: continue
            if (e.size > 64L * 1024 * 1024) continue
            val bytes = try { zip.getInputStream(e).use { it.readBytes() } } catch (_: Throwable) { continue }
            val info = ElfAnalyzer.parse(bytes)
            if (info == null) { notElf++; continue }
            out.add(Lib(e.name, e.name.split('/')[1], name, info, zip, label))
        }
        return out to notElf
    }

    /** RPATH / RUNPATH entries that are relative, empty, "." or under shared / world-writable locations; "$ORIGIN" and private package directories are fine. */
    internal fun searchPathRisky(sp: String): Boolean = sp.split(':').any { e ->
        e.isEmpty() || e == "." || (!e.startsWith("/") && !e.startsWith("$")) || e.startsWith("/sdcard") || e.startsWith("/storage") || e.startsWith("/data/local/tmp") || e.startsWith("/tmp") || e.startsWith("/mnt")
    }

    fun targetSdk(manifest: String?): Int? = manifest?.let { Regex("targetSdkVersion\\s*=\\s*\"(\\d+)\"").find(it)?.groupValues?.get(1)?.toIntOrNull() }

    /** All native findings of the APK (the coverage card included); empty when the APK has no .so and no sign of native code. */
    fun scan(zip: ZipFile, manifest: String?): List<Finding> {
        val opened = ArrayList<ZipFile>()
        try {
            val (b, bn) = try { readLibs(zip) } catch (_: Throwable) { return emptyList() }
            var libs0: List<Lib> = b; var notElf0 = bn
            for (x in extraArchives) {
                try { val zf = ZipFile(x); opened.add(zf); val (xl, xn) = readLibs(zf, x.name); libs0 = libs0 + xl; notElf0 += xn } catch (_: Throwable) { }
            }
            // one ABI per library name across the base and the splits (arm64-v8a first)
            val order = listOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86", "armeabi")
            libs0 = libs0.groupBy { it.name }.values.map { g -> g.minByOrNull { order.indexOf(it.abi).let { i -> if (i < 0) 99 else i } }!! }
            return scanLibs(zip, manifest, libs0, notElf0)
        } finally { for (z in opened) try { z.close() } catch (_: Throwable) { } }
    }

    private fun scanLibs(zip: ZipFile, manifest: String?, libs: List<Lib>, notElf: Int): List<Finding> {
        if (libs.isEmpty() && notElf == 0) return emptyList()
        val out = ArrayList<Finding>()
        val tsdk = targetSdk(manifest)
        fun f(sev: Severity, id: String, title: String, detail: String, rec: String, cwe: String, file: String) =
            Finding(sev, title, detail, rec, null, -1, -1, cwe, file).also { it.ruleId = id; it.confidence = "HIGH" }

        // ---- real hardening defects
        val defects = ArrayList<String>(); var ownDefect = false; val benignPaths = ArrayList<String>()
        for (l in libs) {
            val i = l.info; val why = ArrayList<String>()
            if (!i.gnuStack) why.add("no GNU_STACK header (the stack may be executable)") else if (i.stackExecutable) why.add("executable stack")
            if (i.textrel) why.add("text relocations")
            if (i.relro == "none") why.add("no RELRO")
            val sp = listOfNotNull(i.rpath, i.runpath).joinToString(":")
            if (sp.isNotEmpty()) {
                if (searchPathRisky(sp)) why.add("RPATH / RUNPATH to a location another app or the user can write ($sp)")
                else benignPaths.add(l.name + ": " + sp.take(90))
            }
            if (why.isNotEmpty()) { defects.add(l.name + " (" + l.abi + "): " + why.joinToString(", ")); if (!isThirdParty(l.name)) ownDefect = true }
        }
        if (defects.isNotEmpty())
            out.add(f(if (ownDefect) Severity.MEDIUM else Severity.LOW, "native-hardening", "Native libraries without basic hardening (${defects.size})",
                "These libraries lack a protection every current toolchain enables by default: " + defects.take(10).joinToString("; ") + (if (defects.size > 10) "; ..." else "") + ".",
                "Rebuild the library with a current NDK (non-executable stack, -z relro -z now, no text relocations) or update the dependency that ships it.", "CWE-693", "lib/"))

        // a search path that only names the app's own or another package's private directory is information (it leaks a build path), not a defect
        if (benignPaths.isNotEmpty())
            out.add(f(Severity.INFO, "native-rpath", "Native libraries with a built-in library search path (${benignPaths.size})",
                "The dynamic section of these libraries sets RPATH / RUNPATH: " + benignPaths.take(6).joinToString("; ") + ". Private directories of another package cannot be written by other apps, so this is not exploitable by itself, but it shows the build environment.",
                "Link without an RPATH (the app's own directory is searched by default).", "CWE-426", "lib/"))

        // ---- 16 KB pages
        val unaligned = libs.filter { !it.info.aligned16k }
        if (unaligned.isNotEmpty()) {
            val own = unaligned.filter { !isThirdParty(it.name) }.map { it.name }; val dep = unaligned.filter { isThirdParty(it.name) }.map { it.name }
            val enforced = tsdk != null && tsdk >= 35
            out.add(f(if (enforced) Severity.MEDIUM else Severity.INFO, "native-16kb-alignment", "Native libraries not aligned for 16 KB pages (${unaligned.size})",
                "Android 15 devices can use 16 KB memory pages, and Google Play requires apps that target Android 15 (API 35) or newer to support them: every 64-bit library must have LOAD segments aligned to at least 16 KB. " +
                    "Not aligned: " + (own.take(8).joinToString(", ").takeIf { it.isNotEmpty() }?.let { "the app's own or unclassified: $it" } ?: "") +
                    (if (own.isNotEmpty() && dep.isNotEmpty()) "; " else "") + (dep.take(8).joinToString(", ").takeIf { it.isNotEmpty() }?.let { "bundled dependencies: $it" } ?: "") + "." +
                    (if (tsdk == null) " The target SDK was not read, so this is shown as information." else if (!enforced) " The target SDK is $tsdk (below 35), so the requirement does not apply yet." else " The target SDK is $tsdk, so the requirement applies."),
                "Rebuild your own libraries with NDK r28 or newer (16 KB alignment is the default) or link with -Wl,-z,max-page-size=16384; update each dependency to a release that supports 16 KB pages.", "CWE-1104", "lib/"))
        }

        // ---- unsafe C functions: only libraries the app is likely to have written
        val unsafe = libs.filter { !isThirdParty(it.name) && it.info.dangerous.isNotEmpty() }
        if (unsafe.isNotEmpty())
            out.add(f(Severity.LOW, "native-unsafe-imports", "Native libraries import unsafe C functions (${unsafe.size})",
                "These libraries import functions with no bounds checking or that run a shell: " + unsafe.take(8).joinToString("; ") { it.name + ": " + it.info.dangerous.take(5).joinToString(", ") } + ". " +
                    "An import shows the library CAN call the function, not that the call is reachable or exploitable; the native code itself is not analysed.",
                "Review the call sites: use snprintf / strlcpy / fgets instead, never pass app or network data to system() / popen().", "CWE-676", "lib/"))

        // ---- credentials in the data sections
        val seen = HashSet<String>()
        val secrets = SecretFormats.loaded()
        for (l in libs) {
            val src = l.source ?: zip
            val bytes = try { src.getInputStream(src.getEntry(l.path)).use { it.readBytes() } } catch (_: Throwable) { continue }
            val third = isThirdParty(l.name)
            ElfAnalyzer.forEachString(bytes, 8) { s ->
                if (s.length > 2000) return@forEachString
                try { PostureScanner.observeNative(l.path, s, third) } catch (_: Throwable) { }       // 0.107.0: native root / hooking / debugger checks
                if (s.length < 12 || !secrets) return@forEachString
                for (h in SecretFormats.scan(s)) {
                    if (SecretFormats.looksLikePlaceholder(h.secret) || !seen.add(l.name + h.ruleId + h.secret)) continue
                    out.add(f(Severity.HIGH, "native-secrets", "Hardcoded credential in a native library: " + h.desc.take(60).trimEnd('.', ' '),
                        "The data of ${l.path} contains a string in the format \"${h.ruleId}\" (${h.secret.take(4)}… , ${h.secret.length} chars). Native code is not safer than Java for a secret: the file is read in plain text.",
                        "Never ship a live credential in the app, native or not: fetch a short-lived token from your own backend, or scope it down and rotate it now.", "CWE-798", l.path))
                }
                if (s.contains("-----BEGIN") && Regex("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\s\\\\nr]*[A-Za-z0-9+/]{40,}").containsMatchIn(s) && seen.add(l.name + "pem"))
                    out.add(f(Severity.CRITICAL, "native-secrets", "Private key in a native library",
                        "The data of ${l.path} contains a PEM private key block with its body.", "Remove the key from the app; use a server-side secret or the Android Keystore.", "CWE-321", l.path))
            }
        }

        // ---- Flutter: the Dart code is compiled into libapp.so; its string table names the endpoints the app talks to
        libs.firstOrNull { it.name == "libapp.so" }?.let { app ->
            val src = app.source ?: zip
            val bytes = try { src.getInputStream(src.getEntry(app.path)).use { it.readBytes() } } catch (_: Throwable) { null }
            if (bytes != null) {
                val hosts = HashMap<String, Int>(); val clear = LinkedHashSet<String>()
                val pins = LinkedHashSet<String>(); var certs = 0
                ElfAnalyzer.forEachString(bytes, 8) { str ->
                    if (str.length > 4000) return@forEachString
                    // 0.105.0: certificate pinning material (Dart's HttpClient ignores the network security config: pinning, if any, is in the Dart code)
                    for (m in pinRe.findAll(str)) if (pins.size < 50) pins.add(m.value)
                    if (str.contains("-----BEGIN CERTIFICATE-----")) certs++
                    for (m in dartUrl.findAll(str)) {
                        val h = m.groupValues[1].lowercase()
                        if (noiseHost(h)) continue
                        hosts[h] = (hosts[h] ?: 0) + 1
                        if (m.value.startsWith("http://", true)) clear.add(h)
                    }
                }
                val top = hosts.entries.sortedByDescending { it.value }.take(25).joinToString(", ") { it.key }
                out.add(f(Severity.INFO, "native-flutter", "Flutter app: the Dart code is compiled into libapp.so and is NOT analysed",
                    "The business logic, the API client and the deep-link router of this app are Dart code inside ${app.path}${if (app.fromSplit != null) " (from " + app.fromSplit + ")" else ""}: this scanner reads only the Java plug-in layer and the strings of the Dart snapshot. " +
                        (if (hosts.isEmpty()) "No endpoint was found in the snapshot strings (they may be encrypted by a protector)."
                        else "Hosts named in the snapshot (${hosts.size}; they can come from the app or from its packages, and a string in the snapshot is not proof that it is used): $top.") +
                        (if (pins.isEmpty() && certs == 0) " No certificate pinning material in the snapshot strings (no sha256/ SPKI pin, no colon-separated SHA-256 fingerprint, no PEM certificate): unless pins live in an asset, in native code or in encrypted strings, the Dart HTTP client trusts the system CAs."
                        else " Certificate pinning material in the snapshot: ${pins.size} pin(s)" + (if (pins.isNotEmpty()) " (" + pins.take(3).joinToString(", ") { it.take(24) + "…" } + ")" else "") + ", $certs PEM certificate(s): pinning is probably done in Dart; check that every API host is covered."),
                    "Review the Dart code for what it does with deep links, tokens and certificates (Dart's HTTP stack does not use the network security config; pinning has to be done in Dart), and test the endpoints listed here.", "", app.path))
                if (clear.isNotEmpty())
                    out.add(f(Severity.LOW, "native-flutter-cleartext", "Cleartext http:// endpoints named in the Dart snapshot (${clear.size})",
                        "The snapshot strings contain http:// (not https://) URLs for: " + clear.take(10).joinToString(", ") + ". On Android 9+ cleartext is blocked by default, so such a call fails unless the manifest or a network security config allows it, or the host is only a default of a package.",
                        "Use https for every endpoint; if one is really used over http, find out why and fix the server.", "CWE-319", app.path))
            }
        }

        // ---- what was looked at (replaces the 0.82.0 "not analysed" card when there are libraries)
        val third = libs.count { isThirdParty(it.name) }
        val noCanary = libs.filter { !it.info.stackCanary && it.info.imports.isNotEmpty() }
        out.add(f(Severity.INFO, "native-coverage", "Native libraries analysed: ${libs.size} ELF file(s)",
            "ELF headers and dynamic symbols of ${libs.size} libraries (" + third + " recognised third-party, " + (libs.size - third) + " app-own or unclassified) and the strings of their data sections were checked. " +
                "Without a stack canary: ${noCanary.size}; without any FORTIFY (_chk) import: ${libs.count { it.info.fortified.isEmpty() }}; not 16 KB aligned: ${unaligned.size}. " +
                (if (notElf > 0) "$notElf file(s) named .so are not ELF (an archive stored as a library). " else "") +
                (libs.filter { it.fromSplit != null }.let { sp -> if (sp.isEmpty()) "" else "${sp.size} of them came from split archives (" + sp.map { it.fromSplit }.distinct().joinToString(", ") + "). " }) +
                "The native CODE is not analysed: what a JNI function does with the data the app hands it is unknown.",
            "Review the native code separately (a disassembler, the library's source) and check what the app passes to its JNI methods.", "", "lib/"))
        return out
    }
}
