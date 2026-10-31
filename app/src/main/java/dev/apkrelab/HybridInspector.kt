package dev.apkrelab

import java.util.zip.ZipFile

/**
 * 2.0.0 pillar 3a: what a hybrid-framework payload SHIPS, read as strings and files (no code is executed, decoded or modified; the Dart snapshot's object graph is
 * NOT parsed: reading the printable strings of its data sections is the whole deliverable). Flutter only for now: detection (libflutter.so + libapp.so +
 * assets/flutter_assets/), the HTTPS / HTTP endpoints named in libapp.so and in the bundled config files, the config files themselves (by path), and the strings
 * that match a known credential format (counted and named by format; a value is never kept, printed or stored).
 *
 * The result is a classification of the payload for the report's "Hybrid framework analysis" section; it is not a finding. It is kept for the report in
 * [current] for the scan in progress (set by the resource scan, cleared at the start of each scan, like NativeScanner.extraArchives).
 */
object HybridInspector {

    enum class HybridKind { NONE, FLUTTER }

    class HybridResult(
        val kind: HybridKind,
        /** every lib/<abi>/libapp.so across the base and the splits (the same snapshot per ABI); the strings are read from one of them (arm64-v8a first). */
        val libAppCount: Int,
        val libAppRead: String?,
        /** distinct hosts of the endpoints, package / documentation hosts removed (NativeScanner.noiseHost). */
        val hosts: List<String>,
        /** distinct endpoint URLs (scheme, host, path; no query), same filter. */
        val endpoints: List<String>,
        /** flutter_assets files with a configuration name (.env, .env.*, secrets.*, config.*, *.yaml / *.yml). */
        val configFiles: List<String>,
        /** strings that match a credential format of SecretFormats (distinct by format + value); only the count and the format names are kept. */
        val secretCount: Int,
        val secretFormats: List<String>,
        val secretWhere: List<String>
    ) {
        val isHybrid get() = kind != HybridKind.NONE
    }

    val NONE = HybridResult(HybridKind.NONE, 0, null, emptyList(), emptyList(), emptyList(), 0, emptyList(), emptyList())

    @Volatile var current: HybridResult? = null
    fun clear() { current = null }

    private const val FLUTTER_ASSETS = "assets/flutter_assets/"
    private const val MAX_TEXT = 3_000_000L            // the asset scan's per-file cap
    private const val MAX_LIB = 64_000_000L            // NativeScanner's cap for one library
    private const val MAX_LIST = 400                   // endpoints / hosts kept (the report prints fewer)
    private val urlRe = Regex("https?://([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)(?::\\d{1,5})?(/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)?")
    private val configName = Regex("(?i)^(?:\\.env(?:\\..+)?|.+\\.env|secrets\\..+|config\\..+|.+\\.ya?ml)$")
    private val textConfig = Regex("(?i)\\.(?:env|json|ya?ml|txt|properties)$|^\\.env")

    /** Entry names of the archives (base first, then the splits) -> the framework. A Flutter app ships libflutter.so, libapp.so and the flutter_assets folder. */
    fun detect(names: Collection<String>): HybridKind {
        val lib = names.filter { it.startsWith("lib/") }.map { it.substringAfterLast('/') }.toSet()
        val assets = names.any { it.startsWith(FLUTTER_ASSETS) }
        return if ("libflutter.so" in lib && "libapp.so" in lib && assets) HybridKind.FLUTTER else HybridKind.NONE
    }

    /** [zip] = the base APK; [splits] = split archives of the same app (NativeScanner.extraArchives). Never throws: a broken entry is skipped. */
    fun inspect(zip: ZipFile, splits: List<java.io.File> = NativeScanner.extraArchives): HybridResult {
        val opened = ArrayList<ZipFile>()
        try {
            val archives = ArrayList<ZipFile>(); archives.add(zip)
            for (f in splits) try { ZipFile(f).also { opened.add(it); archives.add(it) } } catch (_: Throwable) { }
            val names = archives.flatMap { a -> a.entries().toList().map { it.name } }
            val kind = detect(names)
            if (kind == HybridKind.NONE) return NONE
            val endpoints = LinkedHashSet<String>(); val hosts = LinkedHashSet<String>()
            val secrets = LinkedHashSet<String>(); val formats = LinkedHashSet<String>(); val where = LinkedHashSet<String>()
            fun take(s: String, from: String) {
                if (s.length > 4000) return
                for (m in urlRe.findAll(s)) {
                    val h = m.groupValues[1].lowercase()
                    if (NativeScanner.noiseHost(h)) continue
                    if (hosts.size < MAX_LIST) hosts.add(h)
                    val url = m.value.trimEnd('/', '.', ',', ')', ';')                          // the path class has no '?': a query never enters the match
                    if (endpoints.size < MAX_LIST) endpoints.add(url)
                }
                if (s.length < 12 || !SecretFormats.loaded()) return
                for (h in SecretFormats.scan(s)) {
                    if (SecretFormats.looksLikePlaceholder(h.secret)) continue
                    if (secrets.add(h.ruleId + "\u0000" + h.secret)) { formats.add(h.ruleId); where.add(from) }
                }
            }
            // libapp.so: one ABI (the same snapshot per ABI), arm64-v8a first
            val libApps = archives.flatMap { a -> a.entries().toList().filter { it.name.startsWith("lib/") && it.name.endsWith("/libapp.so") }.map { a to it } }
            val pick = libApps.firstOrNull { it.second.name.contains("/arm64-v8a/") } ?: libApps.firstOrNull()
            if (pick != null && pick.second.size in 1..MAX_LIB) {
                val bytes = try { pick.first.getInputStream(pick.second).use { it.readBytes() } } catch (_: Throwable) { null }
                if (bytes != null) ElfAnalyzer.forEachString(bytes, 8) { take(it, pick.second.name) }
            }
            // flutter_assets: configuration files by name, and the text ones read (under the asset scan's cap)
            val configs = ArrayList<String>()
            for (a in archives) for (e in a.entries()) {
                if (e.isDirectory || !e.name.startsWith(FLUTTER_ASSETS)) continue
                val file = e.name.substringAfterLast('/')
                if (configName.matches(file)) configs.add(e.name)
                if (!textConfig.containsMatchIn(file) || e.size !in 1..MAX_TEXT) continue
                val text = try { a.getInputStream(e).use { String(it.readBytes(), Charsets.UTF_8) } } catch (_: Throwable) { continue }
                for (line in text.lineSequence()) take(line, e.name)
            }
            return HybridResult(kind, libApps.size, pick?.second?.name, hosts.toList(), endpoints.toList(), configs.distinct().sorted(), secrets.size, formats.toList(), where.toList())
        } catch (_: Throwable) {
            return NONE
        } finally {
            for (o in opened) try { o.close() } catch (_: Throwable) { }
        }
    }

    /** Markdown for the report ("" when the app ships no hybrid payload). */
    fun markdown(r: HybridResult?): String {
        if (r == null || !r.isHybrid) return ""
        val sb = StringBuilder("## Hybrid framework analysis\n\n")
        sb.append("What the framework payload ships, read as strings and files. The Dart code itself is not analysed: a string here is not proof that the code uses it.\n\n")
        sb.append("### Flutter\n\n")
        sb.append("- libapp.so: ").append(r.libAppCount).append(" file(s)").append(r.libAppRead?.let { " (strings read from `$it`)" } ?: "").append('\n')
        sb.append("- Endpoints: ").append(r.endpoints.size).append(" URL(s) on ").append(r.hosts.size).append(" host(s)")
        if (r.hosts.isNotEmpty()) sb.append(": ").append(r.hosts.take(20).joinToString(", ")).append(if (r.hosts.size > 20) ", … (${r.hosts.size - 20} more in the HTML report)" else "")
        sb.append('\n')
        sb.append("- Configuration files in flutter_assets: ").append(if (r.configFiles.isEmpty()) "none" else r.configFiles.joinToString(", ") { "`$it`" }).append('\n')
        sb.append("- Strings in a known credential format: ").append(r.secretCount)
        if (r.secretCount > 0) sb.append(" (formats: ").append(r.secretFormats.joinToString(", ")).append("; in ").append(r.secretWhere.joinToString(", ") { "`$it`" }).append("; values are not printed)")
        sb.append("\n\n")
        return sb.toString()
    }

    /** HTML for the report: the same lines, every host and endpoint in a collapsible block. */
    fun html(r: HybridResult?): String {
        if (r == null || !r.isHybrid) return ""
        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        val sb = StringBuilder("<h2>Hybrid framework analysis</h2><div class=\"card\"><p>What the framework payload ships, read as strings and files. The Dart code itself is not analysed: a string here is not proof that the code uses it.</p>")
        sb.append("<h3>Flutter</h3><p>libapp.so: ").append(r.libAppCount).append(" file(s)").append(r.libAppRead?.let { " (strings read from " + esc(it) + ")" } ?: "").append("</p>")
        sb.append("<p>Endpoints: ").append(r.endpoints.size).append(" URL(s) on ").append(r.hosts.size).append(" host(s)</p>")
        if (r.endpoints.isNotEmpty()) sb.append("<details><summary>Every host and endpoint</summary><p>").append(r.hosts.joinToString(", ") { esc(it) }).append("</p><ul>")
            .append(r.endpoints.joinToString("") { "<li>" + esc(it) + "</li>" }).append("</ul></details>")
        sb.append("<p>Configuration files in flutter_assets: ").append(if (r.configFiles.isEmpty()) "none" else r.configFiles.joinToString(", ") { esc(it) }).append("</p>")
        sb.append("<p>Strings in a known credential format: ").append(r.secretCount)
        if (r.secretCount > 0) sb.append(" (formats: ").append(esc(r.secretFormats.joinToString(", "))).append("; values are not printed)")
        return sb.append("</p></div>").toString()
    }

    /** One line for the UI's scan summary ("" for a native app). */
    fun summaryLine(r: HybridResult?): String =
        if (r == null || !r.isHybrid) "" else "Flutter payload: ${r.libAppCount} libapp.so, ${r.endpoints.size} endpoint(s) on ${r.hosts.size} host(s), ${r.configFiles.size} config file(s), ${r.secretCount} credential-format string(s)"
}
