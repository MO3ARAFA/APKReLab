package dev.apkrelab

import org.json.JSONObject
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * 2.0.0 pillar 3: what a hybrid-framework payload SHIPS, read as strings and files (no code is executed, decoded or modified; no Dart snapshot object graph,
 * no JavaScript syntax, no deobfuscation; Hermes bundles go through the existing HermesStrings reader as it is).
 *  - Flutter (3a): libflutter.so + libapp.so + assets/flutter_assets/; the strings of ONE libapp.so (arm64-v8a first: a permanent rule, the same snapshot is
 *    compiled per ABI and reading all of them would triple the cost on a phone) and the text files of flutter_assets.
 *  - React Native (3b): libreactnativejni.so or libhermes.so + assets/index.android.bundle; a Hermes bundle's string table (HermesStrings), else the bundle read
 *    as plain text under the asset scan's cap.
 *  - Cordova / Capacitor (3b): assets/www/ or assets/public/ + config.xml (res/xml/config.xml, binary XML) or capacitor.config.json; the configuration values are
 *    listed verbatim (metadata, not findings) and the web root's text files are read.
 * For each: endpoint URLs and hosts (NativeScanner.noiseHost removed), config-named files, and strings in a SecretFormats format (counted and named by format;
 * a value is never kept, printed or stored). The result is a classification for the report's "Hybrid framework analysis" section, not a finding.
 * It is kept for the report in [current] for the scan in progress (set by the resource scan, cleared at the start of each scan).
 */
object HybridInspector {

    enum class HybridKind { NONE, FLUTTER, REACT_NATIVE, CORDOVA }

    /** What one framework payload ships. */
    class Section(
        val kind: HybridKind,
        /** Flutter: "libapp.so"; React Native: the bundle and how it was read; Cordova: the web root(s). */
        val source: String,
        val libAppCount: Int,
        val libAppRead: String?,
        val hosts: List<String>,
        val endpoints: List<String>,
        val configFiles: List<String>,
        val secretCount: Int,
        val secretFormats: List<String>,
        val secretWhere: List<String>,
        /** Cordova: the named <access origin> / <allow-navigation href> values of config.xml ("*" is left to the asset scan's own card). */
        val namedOrigins: List<String> = emptyList(),
        /** Cordova: whether config.xml has origin / href "*". */
        val wildcardOrigin: Boolean = false,
        /** Capacitor: server.hostname / androidScheme / cleartext / allowNavigation, verbatim as "key=value". */
        val settings: List<String> = emptyList()
    )

    class HybridResult(val sections: List<Section>) {
        val kinds: List<HybridKind> get() = sections.map { it.kind }
        /** The first detected framework (FLUTTER, REACT_NATIVE, CORDOVA order), or NONE. */
        val kind: HybridKind get() = sections.firstOrNull()?.kind ?: HybridKind.NONE
        val isHybrid get() = sections.isNotEmpty()
        private val first get() = sections.firstOrNull()
        // 3a accessors: the first section's values
        val libAppCount get() = first?.libAppCount ?: 0
        val libAppRead get() = first?.libAppRead
        val hosts get() = first?.hosts ?: emptyList()
        val endpoints get() = first?.endpoints ?: emptyList()
        val configFiles get() = first?.configFiles ?: emptyList()
        val secretCount get() = first?.secretCount ?: 0
        val secretFormats get() = first?.secretFormats ?: emptyList()
        val secretWhere get() = first?.secretWhere ?: emptyList()
        fun section(k: HybridKind) = sections.firstOrNull { it.kind == k }
    }

    val NONE = HybridResult(emptyList())

    @Volatile var current: HybridResult? = null
    fun clear() { current = null }

    private const val FLUTTER_ASSETS = "assets/flutter_assets/"
    private const val RN_BUNDLE = "assets/index.android.bundle"
    private val WEB_ROOTS = listOf("assets/www/", "assets/public/")
    private const val MAX_TEXT = 3_000_000L            // the asset scan's per-file cap
    private const val MAX_BUNDLE = 10_000_000L         // the asset scan's cap for a plain-text React Native bundle
    private const val MAX_HERMES = 48_000_000L         // the asset scan's cap for the part of a Hermes bundle read (up to the end of its string storage)
    private const val MAX_LIB = 64_000_000L            // NativeScanner's cap for one library
    private const val MAX_LIST = 400                   // endpoints / hosts kept (the report prints fewer)
    private const val WINDOW = 1800                    // SecretFormats.scan reads at most 2000 chars: a long minified line is read in overlapping windows
    private const val OVERLAP = 400                    // longer than any credential value of the format table
    private val urlRe = Regex("https?://([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)(?::\\d{1,5})?(/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)?")
    private val configName = Regex("(?i)^(?:\\.env(?:\\..+)?|.+\\.env|secrets\\..+|config\\..+|.+\\.ya?ml)$")
    private val textConfig = Regex("(?i)\\.(?:env|json|ya?ml|txt|properties)$|^\\.env")
    private val webText = Regex("(?i)\\.(?:js|mjs|html?|json|txt)$")
    private val originRe = Regex("<(access|allow-navigation)\\b[^>]*?\\b(origin|href)\\s*=\\s*\"([^\"]*)\"")

    /** Entry names of the archives (base first, then the splits) -> every framework they carry, in FLUTTER, REACT_NATIVE, CORDOVA order. */
    fun detectAll(names: Collection<String>): List<HybridKind> {
        val lib = names.filter { it.startsWith("lib/") }.map { it.substringAfterLast('/') }.toSet()
        val out = ArrayList<HybridKind>()
        if ("libflutter.so" in lib && "libapp.so" in lib && names.any { it.startsWith(FLUTTER_ASSETS) }) out.add(HybridKind.FLUTTER)
        if (("libreactnativejni.so" in lib || "libhermes.so" in lib) && RN_BUNDLE in names) out.add(HybridKind.REACT_NATIVE)
        if (names.any { n -> WEB_ROOTS.any { n.startsWith(it) } } && names.any { it == "assets/capacitor.config.json" || it.endsWith("/config.xml") || it == "config.xml" })
            out.add(HybridKind.CORDOVA)
        return out
    }

    /** 3a: the first framework, or NONE. */
    fun detect(names: Collection<String>): HybridKind = detectAll(names).firstOrNull() ?: HybridKind.NONE

    /** Collects endpoints, hosts and credential-format strings of one framework. */
    private class Acc {
        val endpoints = LinkedHashSet<String>(); val hosts = LinkedHashSet<String>()
        val secrets = LinkedHashSet<String>(); val formats = LinkedHashSet<String>(); val where = LinkedHashSet<String>()

        fun take(s: String, from: String) {
            if (s.length > 4000) return
            urls(s)
            if (s.length >= 12) secretsIn(s, from)
        }

        /** A text line of any length: URLs over the whole line, credential formats over overlapping windows (a value is at most a few hundred chars). */
        fun takeText(line: String, from: String) {
            if (line.length <= 2000) { take(line, from); return }
            urls(line)
            var i = 0
            while (i < line.length) {
                val end = minOf(line.length, i + WINDOW)
                // a value cut by the window's end is skipped here: the next window starts OVERLAP chars earlier and holds it whole
                secretsIn(line.substring(i, end), from, cutAtEnd = end < line.length)
                if (end == line.length) break
                i += WINDOW - OVERLAP
            }
        }

        private fun urls(s: String) {
            for (m in urlRe.findAll(s)) {
                val h = m.groupValues[1].lowercase()
                if (NativeScanner.noiseHost(h)) continue
                if (hosts.size < MAX_LIST) hosts.add(h)
                val url = m.value.trimEnd('/', '.', ',', ')', ';')                          // the path class has no '?': a query never enters the match
                if (endpoints.size < MAX_LIST) endpoints.add(url)
            }
        }

        private fun secretsIn(s: String, from: String, cutAtEnd: Boolean = false) {
            if (!SecretFormats.loaded()) return
            for (h in SecretFormats.scan(s)) {
                if (SecretFormats.looksLikePlaceholder(h.secret)) continue
                if (cutAtEnd && s.endsWith(h.secret)) continue
                if (secrets.add(h.ruleId + "\u0000" + h.secret)) { formats.add(h.ruleId); where.add(from) }
            }
        }
    }

    /** The first [n] bytes of [s] (fewer at its end); InputStream.readNBytes needs API 33. */
    private fun readUpTo(s: java.io.InputStream, n: Int): ByteArray {
        val b = ByteArray(n); var got = 0
        while (got < n) { val r = s.read(b, got, n - got); if (r < 0) break; got += r }
        return if (got == n) b else b.copyOf(got)
    }

    private fun bytesOf(a: ZipFile, e: ZipEntry, max: Long): ByteArray? =
        if (e.size !in 1..max) null else try { a.getInputStream(e).use { it.readBytes() } } catch (_: Throwable) { null }

    /** [zip] = the base APK; [splits] = split archives of the same app (NativeScanner.extraArchives). Never throws: a broken entry is skipped. */
    fun inspect(zip: ZipFile, splits: List<java.io.File> = NativeScanner.extraArchives): HybridResult {
        val opened = ArrayList<ZipFile>()
        try {
            val archives = ArrayList<ZipFile>(); archives.add(zip)
            for (f in splits) try { ZipFile(f).also { opened.add(it); archives.add(it) } } catch (_: Throwable) { }
            val entries = archives.flatMap { a -> a.entries().toList().filter { !it.isDirectory }.map { a to it } }
            val kinds = detectAll(entries.map { it.second.name })
            if (kinds.isEmpty()) return NONE
            return HybridResult(kinds.mapNotNull { k ->
                try {
                    when (k) {
                        HybridKind.FLUTTER -> flutter(entries)
                        HybridKind.REACT_NATIVE -> reactNative(entries)
                        HybridKind.CORDOVA -> cordova(entries)
                        HybridKind.NONE -> null
                    }
                } catch (_: Throwable) { null }
            })
        } catch (_: Throwable) {
            return NONE
        } finally {
            for (o in opened) try { o.close() } catch (_: Throwable) { }
        }
    }

    private fun flutter(entries: List<Pair<ZipFile, ZipEntry>>): Section {
        val acc = Acc()
        val libApps = entries.filter { it.second.name.startsWith("lib/") && it.second.name.endsWith("/libapp.so") }
        val pick = libApps.firstOrNull { it.second.name.contains("/arm64-v8a/") } ?: libApps.firstOrNull()
        if (pick != null) bytesOf(pick.first, pick.second, MAX_LIB)?.let { b -> ElfAnalyzer.forEachString(b, 8) { acc.take(it, pick.second.name) } }
        val configs = ArrayList<String>()
        for ((a, e) in entries) {
            if (!e.name.startsWith(FLUTTER_ASSETS)) continue
            val file = e.name.substringAfterLast('/')
            if (configName.matches(file)) configs.add(e.name)
            if (!textConfig.containsMatchIn(file)) continue
            val b = bytesOf(a, e, MAX_TEXT) ?: continue
            for (line in String(b, Charsets.UTF_8).lineSequence()) acc.takeText(line, e.name)
        }
        return Section(HybridKind.FLUTTER, "libapp.so", libApps.size, pick?.second?.name, acc.hosts.toList(), acc.endpoints.toList(), configs.distinct().sorted(),
            acc.secrets.size, acc.formats.toList(), acc.where.toList())
    }

    private fun reactNative(entries: List<Pair<ZipFile, ZipEntry>>): Section {
        val acc = Acc()
        var source = "index.android.bundle"
        val bundle = entries.firstOrNull { it.second.name == RN_BUNDLE }
        if (bundle != null) {
            val (a, e) = bundle
            val head = try { a.getInputStream(e).use { readUpTo(it, 128) } } catch (_: Throwable) { ByteArray(0) }
            val hermes = HermesStrings.version(head)
            if (hermes != null) {
                val need = HermesStrings.prefixNeeded(head, e.size)
                val b = if (need == null || need > MAX_HERMES) null else try { a.getInputStream(e).use { s -> readUpTo(s, need.toInt()) } } catch (_: Throwable) { null }
                val res = b?.let { HermesStrings.read(it, e.size) }
                if (res != null) {
                    for (s in res.strings) acc.take(s, RN_BUNDLE)
                    source = "index.android.bundle (Hermes bytecode v$hermes, ${res.strings.size} strings read)"
                } else source = "index.android.bundle (Hermes bytecode v$hermes, string table not read: version or size not supported)"
            } else {
                val b = bytesOf(a, e, MAX_BUNDLE)
                if (b != null) {
                    for (line in String(b, Charsets.UTF_8).lineSequence()) acc.takeText(line, RN_BUNDLE)
                    source = "index.android.bundle (plain JavaScript, read as text)"
                } else source = "index.android.bundle (plain JavaScript over the ${MAX_BUNDLE / 1_000_000} MB text cap, not read)"
            }
        }
        val configs = entries.map { it.second.name }.filter { n -> n.startsWith("assets/") && n.count { it == '/' } == 1 && configName.matches(n.substringAfterLast('/')) }
        return Section(HybridKind.REACT_NATIVE, source, 0, null, acc.hosts.toList(), acc.endpoints.toList(), configs.distinct().sorted(),
            acc.secrets.size, acc.formats.toList(), acc.where.toList())
    }

    private fun cordova(entries: List<Pair<ZipFile, ZipEntry>>): Section {
        val acc = Acc()
        val roots = WEB_ROOTS.filter { r -> entries.any { it.second.name.startsWith(r) } }
        for ((a, e) in entries) {
            if (WEB_ROOTS.none { e.name.startsWith(it) } || !webText.containsMatchIn(e.name)) continue
            val b = bytesOf(a, e, MAX_TEXT) ?: continue
            for (line in String(b, Charsets.UTF_8).lineSequence()) acc.takeText(line, e.name)
        }
        // config.xml: res/xml/config.xml is compiled (binary XML) in an APK; a plain-text copy is read as it is
        val named = LinkedHashSet<String>(); var wildcard = false
        for ((a, e) in entries.filter { it.second.name.endsWith("/config.xml") || it.second.name == "config.xml" }) {
            val b = bytesOf(a, e, MAX_TEXT) ?: continue
            val xml = (if (b.isNotEmpty() && b[0] == '<'.code.toByte()) String(b, Charsets.UTF_8) else Axml.decode(b)) ?: continue
            if (!xml.contains("<widget")) continue                                    // not Cordova's config.xml
            for (m in originRe.findAll(xml)) { val v = m.groupValues[3]; if (v == "*") wildcard = true else if (v.isNotBlank()) named.add(v) }
        }
        val settings = ArrayList<String>()
        entries.firstOrNull { it.second.name == "assets/capacitor.config.json" }?.let { (a, e) ->
            val text = bytesOf(a, e, MAX_TEXT)?.let { String(it, Charsets.UTF_8) }
            val server = try { text?.let { JSONObject(it).optJSONObject("server") } } catch (_: Throwable) { null }
            if (server != null) {
                for (k in listOf("hostname", "androidScheme", "cleartext")) if (server.has(k)) settings.add("server.$k=" + server.opt(k))
                server.optJSONArray("allowNavigation")?.let { arr -> for (i in 0 until arr.length()) settings.add("server.allowNavigation=" + arr.opt(i)) }
            }
        }
        return Section(HybridKind.CORDOVA, roots.joinToString(", ") { it.trimEnd('/') }, 0, null, acc.hosts.toList(), acc.endpoints.toList(), emptyList(),
            acc.secrets.size, acc.formats.toList(), acc.where.toList(), named.toList(), wildcard, settings)
    }

    private fun title(k: HybridKind) = when (k) {
        HybridKind.FLUTTER -> "Flutter"; HybridKind.REACT_NATIVE -> "React Native"; HybridKind.CORDOVA -> "Cordova / Capacitor"; HybridKind.NONE -> ""
    }
    private fun intro(r: HybridResult): String {
        val dart = HybridKind.FLUTTER in r.kinds; val js = r.kinds.any { it == HybridKind.REACT_NATIVE || it == HybridKind.CORDOVA }
        val lang = if (dart && js) "Dart and JavaScript" else if (dart) "Dart" else "JavaScript"
        return "What the framework payload ships, read as strings and files. The $lang code itself is not analysed: a string here is not proof that the code uses it."
    }

    /** Markdown for the report ("" when the app ships no hybrid payload). */
    fun markdown(r: HybridResult?): String {
        if (r == null || !r.isHybrid) return ""
        val sb = StringBuilder("## Hybrid framework analysis\n\n").append(intro(r)).append("\n\n")
        for (s in r.sections) {
            sb.append("### ").append(title(s.kind)).append("\n\n")
            when (s.kind) {
                HybridKind.FLUTTER -> sb.append("- libapp.so: ").append(s.libAppCount).append(" file(s)").append(s.libAppRead?.let { " (strings read from `$it`)" } ?: "").append('\n')
                HybridKind.REACT_NATIVE -> sb.append("- Bundle: ").append(s.source).append('\n')
                HybridKind.CORDOVA -> {
                    sb.append("- Web root: ").append(s.source).append('\n')
                    sb.append("- Named origins (config.xml): ").append(if (s.namedOrigins.isEmpty()) "none" else s.namedOrigins.joinToString(", ") { "`$it`" })
                        .append(if (s.wildcardOrigin) "; origin \"*\" is present (see the asset scan's card)" else "").append('\n')
                    if (s.settings.isNotEmpty()) sb.append("- Capacitor server configuration: ").append(s.settings.joinToString(", ") { "`$it`" }).append('\n')
                }
                HybridKind.NONE -> {}
            }
            sb.append("- Endpoints: ").append(s.endpoints.size).append(" URL(s) on ").append(s.hosts.size).append(" host(s)")
            if (s.hosts.isNotEmpty()) sb.append(": ").append(s.hosts.take(20).joinToString(", ")).append(if (s.hosts.size > 20) ", … (${s.hosts.size - 20} more in the HTML report)" else "")
            sb.append('\n')
            if (s.kind != HybridKind.CORDOVA)
                sb.append("- Configuration files: ").append(if (s.configFiles.isEmpty()) "none" else s.configFiles.joinToString(", ") { "`$it`" }).append('\n')
            sb.append("- Strings in a known credential format: ").append(s.secretCount)
            if (s.secretCount > 0) sb.append(" (formats: ").append(s.secretFormats.joinToString(", ")).append("; in ").append(s.secretWhere.joinToString(", ") { "`$it`" }).append("; values are not printed)")
            sb.append("\n\n")
        }
        return sb.toString()
    }

    /** HTML for the report: the same lines, every host and endpoint in a collapsible block. */
    fun html(r: HybridResult?): String {
        if (r == null || !r.isHybrid) return ""
        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        val sb = StringBuilder("<h2>Hybrid framework analysis</h2><div class=\"card\"><p>").append(esc(intro(r))).append("</p>")
        for (s in r.sections) {
            sb.append("<h3>").append(esc(title(s.kind))).append("</h3>")
            when (s.kind) {
                HybridKind.FLUTTER -> sb.append("<p>libapp.so: ").append(s.libAppCount).append(" file(s)").append(s.libAppRead?.let { " (strings read from " + esc(it) + ")" } ?: "").append("</p>")
                HybridKind.REACT_NATIVE -> sb.append("<p>Bundle: ").append(esc(s.source)).append("</p>")
                HybridKind.CORDOVA -> {
                    sb.append("<p>Web root: ").append(esc(s.source)).append("</p><p>Named origins (config.xml): ").append(if (s.namedOrigins.isEmpty()) "none" else esc(s.namedOrigins.joinToString(", "))).append("</p>")
                    if (s.settings.isNotEmpty()) sb.append("<p>Capacitor server configuration: ").append(esc(s.settings.joinToString(", "))).append("</p>")
                }
                HybridKind.NONE -> {}
            }
            sb.append("<p>Endpoints: ").append(s.endpoints.size).append(" URL(s) on ").append(s.hosts.size).append(" host(s)</p>")
            if (s.endpoints.isNotEmpty()) sb.append("<details><summary>Every host and endpoint</summary><p>").append(s.hosts.joinToString(", ") { esc(it) }).append("</p><ul>")
                .append(s.endpoints.joinToString("") { "<li>" + esc(it) + "</li>" }).append("</ul></details>")
            if (s.kind != HybridKind.CORDOVA) sb.append("<p>Configuration files: ").append(if (s.configFiles.isEmpty()) "none" else s.configFiles.joinToString(", ") { esc(it) }).append("</p>")
            sb.append("<p>Strings in a known credential format: ").append(s.secretCount)
            if (s.secretCount > 0) sb.append(" (formats: ").append(esc(s.secretFormats.joinToString(", "))).append("; values are not printed)")
            sb.append("</p>")
        }
        return sb.append("</div>").toString()
    }

    private fun n(count: Int, one: String, many: String = one + "s") = "$count " + if (count == 1) one else many

    /** audit_brief / UI: one line per detected framework ("" for a native app). */
    fun briefLines(r: HybridResult?): List<String> = r?.sections?.map { s ->
        when (s.kind) {
            HybridKind.FLUTTER -> "Flutter: libapp.so, ${n(s.endpoints.size, "endpoint")}, ${n(s.secretCount, "secret")}, ${n(s.configFiles.size, "config file")}"
            HybridKind.REACT_NATIVE -> "React Native: index.android.bundle, ${n(s.endpoints.size, "endpoint")}, ${n(s.secretCount, "secret")}"
            HybridKind.CORDOVA -> "Cordova: ${s.source}, ${n(s.namedOrigins.size, "named origin")}, ${n(s.secretCount, "secret")}"
            HybridKind.NONE -> ""
        }
    }?.filter { it.isNotEmpty() } ?: emptyList()

    /** One line for the UI's scan summary ("" for a native app). */
    fun summaryLine(r: HybridResult?): String = briefLines(r).joinToString("; ")

    /** The Verdict's NOT SEEN entries for the detected frameworks (empty for a native app). */
    fun notSeen(kinds: List<HybridKind>): List<String> = kinds.mapNotNull {
        when (it) {
            HybridKind.FLUTTER -> "Dart code (Flutter libapp.so): strings read, code not analysed"
            HybridKind.REACT_NATIVE -> "JavaScript (React Native bundle): strings read, code not analysed"
            HybridKind.CORDOVA -> "JavaScript (Cordova / Capacitor www): strings read, code not analysed"
            HybridKind.NONE -> null
        }
    }
}
