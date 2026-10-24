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
    internal fun hermesVersion(head: ByteArray): Int? {   // the magic and the version; HermesStrings reads the table
        if (head.size < 12) return null
        val magic = byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F)
        for (i in 0 until 8) if (head[i] != magic[i]) return null
        return (head[8].toInt() and 255) or ((head[9].toInt() and 255) shl 8) or ((head[10].toInt() and 255) shl 16) or ((head[11].toInt() and 255) shl 24)
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
            if (e.size > cap) { skippedBig++; continue }
            val bytes = try { zip.getInputStream(e).use { it.readBytes() } } catch (_: Throwable) { RuleRegistry.noteError("assets-read"); continue }
            total += bytes.size
            val hv = hermesVersion(bytes)
            if (hv != null) {
                hybrid = true
                // 0.104.0: the string table of a version-96 file is read (no function is decoded) and goes through the same checks as a text bundle
                val hs = HermesStrings.read(bytes)
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
            if (bytes.take(1024).any { it.toInt() == 0 }) { binary++; continue }
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
