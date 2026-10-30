package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import java.util.zip.ZipFile

/**
 * 0.103.0: the `assets/` folder. No rule read it before: React Native keeps its whole JS bundle there (`index.android.bundle`, plain JS or Hermes bytecode), Cordova / Capacitor / Ionic
 * keep the web app (`assets/www`), Flutter keeps `flutter_assets/` (an `.env` shipped as an asset is a classic), and many apps ship JSON / properties configs. Text files are scanned for
 *  - vendor tokens and credential formats (the 206 formats of [SecretFormats], same placeholder filter as the native scan) and PEM private keys,
 *  - cleartext `http://` hosts (one aggregated LOW card), Firebase Realtime Database URLs,
 *  - Cordova's `<access origin="*">` / `<allow-navigation href="*">` (`res/xml/config.xml`, or `assets/www/config.xml`).
 * Hermes bytecode is NOT decoded: an INFO card says so (its strings are not scanned yet). Binary files (media, fonts, databases), files over the size caps, source maps and the
 * licence / notice files are skipped. Everything is streamed: one file in memory at a time, at most MAX_FILE bytes.
 */
object AssetScanner {
    private const val MAX_FILE = 3_000_000L
    private const val MAX_BUNDLE = 10_000_000L          // a React Native bundle is one big text file
    private const val MAX_HERMES_PREFIX = 48_000_000L   // 0.104.1: a Hermes bundle is read only up to the end of its string storage, whatever the file size
    private const val MAX_TOTAL = 48_000_000L
    private const val MAX_FILES = 600
    private const val MAX_MILLIS = 20_000L
    private const val MAX_HITS = 200

    private val textExt = setOf("js", "mjs", "cjs", "json", "xml", "html", "htm", "txt", "properties", "cfg", "conf", "config", "ini", "yaml", "yml", "env", "toml", "plist", "csv", "bundle", "jsbundle", "md", "sh", "pem", "key")
    private val line = Regex("^\\s*[A-Za-z0-9_.\\-]{2,60}\\s*[=:]\\s*(\\S[^\\r\\n]{6,400})$", RegexOption.MULTILINE)
    private val literal = Regex("\"([^\"\\\\\\r\\n]{8,500})\"|'([^'\\\\\\r\\n]{8,500})'")
    // an endpoint the app can FETCH has a path ("http://api.x.net/v1/..."); a bare host in a string is a link or an XML namespace. Only quoted literals of script / config files count
    // (code comments, HTML anchors, licence and readme text are not connections).
    private val httpUrl = Regex("^http://([A-Za-z0-9][A-Za-z0-9.-]{1,80}\\.[A-Za-z]{2,24})(?::\\d+)?/[^\\s\"'<>\\\\]{2,}")
    private val urlExt = setOf("js", "mjs", "cjs", "json", "xml", "properties", "cfg", "conf", "config", "ini", "yaml", "yml", "env", "toml", "plist", "bundle", "jsbundle")
    private val firebase = Regex("https://([a-zA-Z0-9_-]+)\\.(?:firebaseio\\.com|firebasedatabase\\.app)")
    private val pem = Regex("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\s\\\\nr]*[A-Za-z0-9+/]{40,}")
    private val fakeFirebase = setOf("project-id", "your-project", "yourproject", "my-project", "example", "demo")
    private val privateHost = Regex("^(?:localhost|127\\..*|10\\..*|192\\.168\\..*|172\\.(?:1[6-9]|2\\d|3[01])\\..*|0\\.0\\.0\\.0)$")
    private val skipName = Regex("(?i)(^|/)(licen[sc]e|notice|copying|authors|changelog|thirdpartynotices?)[^/]*$|\\.map$")

    private fun f(sev: Severity, id: String, title: String, detail: String, rec: String, cwe: String, file: String, conf: String = "HIGH") =
        Finding(sev, title, detail, rec, null, -1, -1, cwe, file).also { it.ruleId = id; it.confidence = conf }

    private fun ext(n: String): String = n.substringAfterLast('/').let { if (it.contains('.')) it.substringAfterLast('.').lowercase() else "" }

    /** Hermes bytecode: magic 0x1F1903C103BC1FC6 (little endian), then the bytecode version. */
    /** Hermes bytecode: the magic and the version (see HermesStrings). */
    internal fun hermesVersion(head: ByteArray): Int? = HermesStrings.version(head)

    private fun hasNul(b: ByteArray, n: Int): Boolean { for (i in 0 until minOf(n, b.size)) if (b[i].toInt() == 0) return true; return false }

    /** [head] followed by the next bytes of [ins], in ONE array of [total] bytes (a big prefix must not exist twice in a 512 MB heap). */
    private fun readRest(ins: java.io.InputStream, head: ByteArray, total: Int): ByteArray {
        val out = ByteArray(total); System.arraycopy(head, 0, out, 0, minOf(head.size, total)); var got = minOf(head.size, total)
        while (got < total) { val r = ins.read(out, got, total - got); if (r < 0) break; got += r }
        return if (got == total) out else out.copyOf(got)
    }

    /** Up to [n] bytes from [ins] (fewer only at the end of the stream). */
    private fun readUpTo(ins: java.io.InputStream, n: Int): ByteArray {
        val out = ByteArray(maxOf(0, n)); var got = 0
        while (got < out.size) { val r = ins.read(out, got, out.size - got); if (r < 0) break; got += r }
        return if (got == out.size) out else out.copyOf(got)
    }

    class Result(val findings: List<Finding>, val stats: String)

    fun scan(zip: ZipFile): Result {
        val out = ArrayList<Finding>()
        val started = System.currentTimeMillis()
        var files = 0; var read = 0; var skippedBig = 0; var binary = 0; var total = 0L; var hits = 0
        var hybrid = false; val hybridKinds = LinkedHashSet<String>()
        val seen = HashSet<String>()
        val clear = LinkedHashMap<String, String>()          // host -> first file
        val fire = LinkedHashMap<String, String>()           // url -> first file

        fun fireCheck(path: String, text: String) {
            for (m in firebase.findAll(text)) {
                val pid = m.groupValues[1]
                if (pid in fakeFirebase || pid.contains("your") || pid.contains("xxxx")) continue
                fire.putIfAbsent(m.value, path)
            }
        }

        fun urlCheck(path: String, lit: String) {
            if (!lit.startsWith("http://")) return
            val u = httpUrl.find(lit) ?: return
            val h = u.groupValues[1].lowercase()
            if (!NativeScanner.noiseHost(h) && !privateHost.matches(h)) clear.putIfAbsent(h, path)
        }

        fun secrets(path: String, s: String) {
            if (s.length < 8 || s.length > 2000) return
            for (h in SecretFormats.scan(s)) {
                if (SecretFormats.looksLikePlaceholder(h.secret) || !seen.add(path + h.ruleId + h.secret) || ++hits > MAX_HITS) continue
                out.add(f(Severity.HIGH, "assets-secrets", "Hardcoded credential in app assets: " + h.desc.take(60).trimEnd('.', ' '),
                    "The asset $path contains a string in the format \"${h.ruleId}\" (${h.secret.take(4)}… , ${h.secret.length} chars). Files under assets/ are shipped in the APK in plain text (a JS bundle, a config, an .env): anyone who unzips the APK reads them.",
                    "Never ship a live credential in the app: fetch a short-lived token from your own backend, or scope it down and rotate it now.", "CWE-798", path))
            }
        }

        for (e in zip.entries()) {
            val name = e.name
            if (e.isDirectory || !name.startsWith("assets/")) continue
            if (System.currentTimeMillis() - started > MAX_MILLIS || total > MAX_TOTAL || files >= MAX_FILES) break
            files++
            val x = ext(name)
            val bundleLike = name.endsWith(".bundle") || name.endsWith(".jsbundle") || name.contains("index.android")
            if (name.contains("/www/") && (name.endsWith("cordova.js") || name.endsWith("capacitor.js") || name.endsWith("cordova_plugins.js"))) { hybrid = true; hybridKinds.add("Cordova / Capacitor web app") }
            if (name.contains("flutter_assets/")) { hybrid = true; hybridKinds.add("Flutter assets") }
            if (skipName.containsMatchIn(name)) continue
            if (x !in textExt && !bundleLike) { binary++; continue }
            val cap = if (bundleLike) MAX_BUNDLE else MAX_FILE
            // 0.104.1: a bundle over the cap was skipped without a word (production React Native bundles are often 15-40 MB). If it is Hermes bytecode, only the header, the tables
            // and the string storage are needed, and they come first: read that prefix. Anything else over the cap is still skipped (and counted).
            val bytes = if (e.size <= cap) {
                try { zip.getInputStream(e).use { it.readBytes() } } catch (_: Throwable) { RuleRegistry.noteError("assets-read"); continue }
            } else if (bundleLike) {
                val pre = try {
                    zip.getInputStream(e).use { ins ->
                        val head = readUpTo(ins, 128)
                        val need = HermesStrings.prefixNeeded(head, e.size)
                        if (need == null || need > MAX_HERMES_PREFIX) null else readRest(ins, head, need.toInt())
                    }
                } catch (_: Throwable) { RuleRegistry.noteError("assets-read"); null }
                if (pre == null) { skippedBig++; continue }
                pre
            } else { skippedBig++; continue }
            total += bytes.size
            val hv = HermesStrings.version(bytes)
            if (hv != null) {
                hybrid = true
                // 0.104.0: the string table of a version-96 file is read (no function is decoded) and goes through the same checks as a text bundle
                val hs = HermesStrings.read(bytes, if (e.size >= 0) e.size else bytes.size.toLong())
                if (hs != null) {
                    hybridKinds.add("React Native (Hermes bytecode v$hv, string table scanned)")
                    for (str in hs.strings) {
                        secrets(name, str)
                        urlCheck(name, str)
                        if (str.contains("firebaseio.com") || str.contains("firebasedatabase.app")) fireCheck(name, str)
                        if (str.contains("-----BEGIN") && pem.containsMatchIn(str) && seen.add("$name#pem"))
                            out.add(f(Severity.CRITICAL, "assets-private-key", "Private key in app assets",
                                "The Hermes bundle $name contains a PEM private key block with its body in its string table.", "Remove the key from the app; use a server-side secret or the Android Keystore.", "CWE-321", name))
                    }
                    out.add(f(Severity.INFO, "assets-hermes", "React Native bundle is Hermes bytecode: its string table was scanned, its code was not",
                        "$name is compiled Hermes bytecode (version $hv). Its ${hs.total} string constants were read and checked for credential formats, private keys, cleartext endpoints and Firebase URLs. The JavaScript logic itself (what the app does with them, injection, insecure storage) is NOT analysed: a string-level scan cannot show that.",
                        "Review the JavaScript source with its own tools (eslint-plugin-security, npm audit) on your build.", "", name, "HIGH"))
                } else {
                    hybridKinds.add("React Native (Hermes bytecode v$hv)")
                    out.add(f(Severity.INFO, "assets-hermes", "React Native bundle is Hermes bytecode: its strings are NOT scanned",
                        "$name is compiled Hermes bytecode (version $hv)." + (if (hv != HermesStrings.SUPPORTED_VERSION) " Only bytecode version ${HermesStrings.SUPPORTED_VERSION} is read; this scanner does not know the layout of version $hv." else " The file is not self-consistent, so its string table was not read.") +
                            " The app logic and its string constants live in this file; only the Java / native layer and the other assets were read. A \"0 findings\" about secrets, URLs or API endpoints in the JavaScript layer is therefore not a pass.",
                        "Dump the strings with a Hermes disassembler (hbctool / hermes-dec) on your own build and review them; or scan the plain JS bundle of a debug build.", "", name, "HIGH"))
                }
                continue
            }
            if (hasNul(bytes, 1024)) { binary++; continue }
            read++
            val text = String(bytes, Charsets.UTF_8)
            if (bundleLike && x != "json") { hybrid = true; hybridKinds.add("React Native JS bundle (plain text)") }
            val urlFile = x in urlExt || bundleLike
            for (m in literal.findAll(text)) secrets(name, m.groupValues[1].ifEmpty { m.groupValues[2] })     // a secret in a comment is still a leak: the full text
            if (urlFile) {
                val code = if (x == "js" || x == "mjs" || x == "cjs" || bundleLike) stripComments(text) else text
                for (m in literal.findAll(code)) urlCheck(name, m.groupValues[1].ifEmpty { m.groupValues[2] })
            }
            if (x != "js" && x != "mjs" && x != "cjs" && !bundleLike) for (m in line.findAll(text)) { val v = m.groupValues[1].trim().trim('"', '\'', ','); secrets(name, v); if (urlFile) urlCheck(name, v) }
            if (text.contains("-----BEGIN") && pem.containsMatchIn(text) && seen.add("$name#pem"))
                out.add(f(Severity.CRITICAL, "assets-private-key", "Private key in app assets",
                    "The asset $name contains a PEM private key block with its body. Anyone can unzip the APK and read it.", "Remove the key from the app; use a server-side secret or the Android Keystore.", "CWE-321", name))
            if (text.contains("firebaseio.com") || text.contains("firebasedatabase.app")) fireCheck(name, text)
            if (name.endsWith("/config.xml") && name.contains("www")) out.addAll(cordovaConfig(name, text))
        }
        // Cordova's config.xml is a compiled resource in the APK
        try {
            zip.getEntry("res/xml/config.xml")?.let { ce ->
                val xml = Axml.decode(zip.getInputStream(ce).use { it.readBytes() })
                if (xml != null && (xml.contains("<access") || xml.contains("<allow-"))) { hybrid = true; hybridKinds.add("Cordova config"); out.addAll(cordovaConfig("res/xml/config.xml", xml)) }
            }
        } catch (_: Throwable) { RuleRegistry.noteError("assets-cordova") }

        if (clear.isNotEmpty()) out.add(f(Severity.LOW, "assets-cleartext-url", "Cleartext http:// endpoints in app assets (" + clear.size + ")",
            "The assets name these hosts with plain http:// (first file in brackets): " + clear.entries.take(8).joinToString(", ") { it.key + " [" + it.value.substringAfterLast('/') + "]" } + (if (clear.size > 8) " and ${clear.size - 8} more" else "") +
                ". Documentation and schema hosts are left out. Traffic to these hosts can be read and changed by anyone on the network unless the app blocks cleartext traffic.",
            "Use https:// and keep cleartextTrafficPermitted=false in the network security config.", "CWE-319", clear.values.first(), "MEDIUM"))
        for ((url, file) in fire.entries.take(3)) out.add(f(Severity.MEDIUM, "assets-firebase-db", "Firebase Realtime Database URL in app assets",
            "The asset $file contains $url. The URL is not secret, but if the database rules are public, anyone can read or change the data with a plain HTTPS request.",
            "Open \"$url/.json\" from a browser you control: data (or \"null\") without a login means public rules. Require auth != null in the Firebase console.", "CWE-284", file))
        if (hybrid && hybridKinds.isNotEmpty()) out.add(f(Severity.INFO, "assets-coverage", "Hybrid app layer scanned as text: " + hybridKinds.joinToString(", "),
            "The files under assets/ ($read text files read, $binary binary / media skipped, $skippedBig over the size cap) were scanned for credential formats, private keys, cleartext hosts and Firebase URLs. This is a string-level scan: the JavaScript / Dart logic is not analysed for vulnerabilities such as injection or insecure storage.",
            "Review the web / JS layer with its own tools (npm audit, eslint-plugin-security) on the source.", "", "assets/", "HIGH"))
        return Result(out, "assets: $read text files read of $files, $binary binary skipped, $skippedBig over the cap" + (if (hits > MAX_HITS) ", hit cap reached" else ""))
    }

    /** JS with its block comments and whole-line `//` comments removed (for the URL check only: a link in a doc comment is not a connection). */
    internal fun stripComments(js: String): String {
        val sb = StringBuilder(js.length)
        var i = 0
        while (i < js.length) {
            val a = js.indexOf("/*", i)
            if (a < 0) { sb.append(js, i, js.length); break }
            val b = js.indexOf("*/", a + 2)
            sb.append(js, i, a).append(' ')
            if (b < 0) break                                   // an unterminated comment: the rest is not code
            i = b + 2
        }
        return sb.toString().replace(Regex("(?m)^\\s*//.*$"), "")
    }

    /**
     * 0.104.1: the agent's `search_assets` tool. `search_code` reads smali only; the JavaScript / web / config layer under assets/ (and the string table of a Hermes bundle) was
     * invisible to the agent. Same reading rules as [scan]: text files under the caps, licence files skipped, a Hermes bundle read up to its string storage. Case-insensitive,
     * at most 5 hits per file and [max] in all, each with about 80 characters around it.
     */
    fun search(zip: ZipFile, query: String, max: Int): String {
        val q = query.trim()
        if (q.length < 3) return "error: the query must be at least 3 characters"
        val out = ArrayList<String>(); var files = 0; var hermes = 0; var skipped = 0
        loop@ for (e in zip.entries()) {
            val name = e.name
            if (e.isDirectory || !name.startsWith("assets/") || skipName.containsMatchIn(name)) continue
            val x = ext(name)
            val bundleLike = name.endsWith(".bundle") || name.endsWith(".jsbundle") || name.contains("index.android")
            if (x !in textExt && !bundleLike) continue
            val bytes = try {
                zip.getInputStream(e).use { ins ->
                    if (e.size in 0..(if (bundleLike) MAX_BUNDLE else MAX_FILE)) ins.readBytes()
                    else if (bundleLike) { val head = readUpTo(ins, 128); val need = HermesStrings.prefixNeeded(head, e.size); if (need == null || need > MAX_HERMES_PREFIX) null else readRest(ins, head, need.toInt()) }
                    else null
                }
            } catch (_: Throwable) { null }
            if (bytes == null) { skipped++; continue }
            files++
            var inFile = 0
            if (HermesStrings.version(bytes) != null) {
                val hs = HermesStrings.read(bytes, if (e.size >= 0) e.size else bytes.size.toLong())
                if (hs == null) { skipped++; continue }
                hermes++
                for ((i, str) in hs.strings.withIndex()) {
                    if (!str.contains(q, ignoreCase = true)) continue
                    out.add("$name [Hermes string #$i]: " + str.take(200).replace('\n', ' '))
                    if (++inFile >= 5 || out.size >= max) break
                }
            } else {
                if (hasNul(bytes, 1024)) { skipped++; continue }
                val text = String(bytes, Charsets.UTF_8)
                var at = text.indexOf(q, 0, ignoreCase = true)
                var line = 1; var counted = 0                    // line number counted forward, no copy of the text
                while (at >= 0 && inFile < 5 && out.size < max) {
                    val a = maxOf(0, at - 80); val b = minOf(text.length, at + q.length + 80)
                    while (counted < at) { if (text[counted] == '\n') line++; counted++ }
                    out.add("$name:$line: " + (if (a > 0) "…" else "") + text.substring(a, b).replace('\n', ' ').replace('\r', ' ') + (if (b < text.length) "…" else ""))
                    inFile++
                    at = text.indexOf(q, at + q.length, ignoreCase = true)
                }
            }
            if (out.size >= max) break@loop
        }
        val head = "search_assets \"$q\": ${out.size} hit(s) in $files asset file(s) read" + (if (hermes > 0) " ($hermes Hermes string table(s))" else "") + (if (skipped > 0) ", $skipped skipped (binary, over the size cap, or an unreadable Hermes version)" else "") +
            (if (out.size >= max) ", stopped at $max" else "") + "."
        return if (out.isEmpty()) head + " Nothing under assets/ contains it (the Java / Kotlin code is searched with search_code)." else head + "\n" + out.joinToString("\n")
    }

    private fun cordovaConfig(path: String, xml: String): List<Finding> {
        val out = ArrayList<Finding>()
        if (Regex("<access[^>]*\\sorigin\\s*=\\s*\"\\*\"").containsMatchIn(xml))
            out.add(f(Severity.MEDIUM, "assets-cordova-access-wildcard", "Cordova: <access origin=\"*\"> lets the web view call any host",
                "$path allows the app's web view to make requests to every origin. With a content injection (an http page, a compromised CDN script) any site gets the Cordova plugin bridge the app exposes.",
                "List the hosts the app really needs (<access origin=\"https://api.example.com\" />) and drop the wildcard.", "CWE-346", path, "MEDIUM"))
        if (Regex("<allow-navigation[^>]*\\shref\\s*=\\s*\"\\*\"").containsMatchIn(xml))
            out.add(f(Severity.MEDIUM, "assets-cordova-navigation-wildcard", "Cordova: <allow-navigation href=\"*\"> lets the web view navigate anywhere",
                "$path allows the main web view to navigate to any URL, which then runs with the plugins of the app.",
                "Allow only your own https hosts; open external links in the system browser (<allow-intent>).", "CWE-346", path, "MEDIUM"))
        return out
    }
}
