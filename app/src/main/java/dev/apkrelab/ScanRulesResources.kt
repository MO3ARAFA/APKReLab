package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.zip.ZipFile

/**
 * 0.43.0: resources and network security scanner, as plugin rules (third kind of rule, after code rules and manifest rules).
 *
 * Input of a resource rule is a [ResourceContext]: ONE file at a time (a decoded res/xml file, a plain values file, or the
 * string pool of resources.arsc). The context is light on purpose:
 *  - it holds the text it was given and nothing else; every derived fact is lazy (a rule pays only for what it reads);
 *  - network_security_config.xml is parsed by a tiny tokenizer into [NscModel] (a few dozen nodes, capped), never a DOM library;
 *  - resources.arsc is NOT turned into a list of all its strings: [ArscPool] reads the global string pool in place and keeps only
 *    the strings that can be a key or a token (20+ chars, no spaces), so a 10 MB arsc costs a few thousand small strings;
 *  - [ResourceScanner.scanApk] decodes one file, runs the rules, drops it, then goes to the next one.
 *
 * Where the strings come from: in a built APK there is NO res/values/strings.xml. aapt compiles every values resource into
 * resources.arsc, so the strings are read from its global string pool (values only: the resource NAME of a string is not
 * available there, so name-based checks run only on plain values files, which exist in unpacked projects).
 *
 * To add a rule: write the object, add `registerResource(MyRule)` in RuleRegistry init, one line in Capabilities.SCANNER, and a
 * VulnKnowledge entry if the CWE is new (RuleRegistry.audit() must stay empty).
 */

// ---------------------------------------------------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------------------------------------------------

/** One string resource. [name] is empty when the source has no names (resources.arsc string pool). */
class ResString(val name: String, val value: String)

class ResourceContext(
    val path: String,
    val xml: String = "",
    private val stringSource: (() -> List<ResString>)? = null,
    /** 0.46.0: explicit "names available" flag (the arsc named-strings parse provides names; the plain pool fallback does not). */
    namesAvailable: Boolean? = null,
    /** 0.75.0: APK-wide facts (code mitigations seen in the dex, minSdk) for rules that cross-check a layout with the code. */
    val apk: ApkFacts = ApkFacts.NONE
) {
    /** Decoded res/xml file that is a network security config. */
    val isNsc: Boolean by lazy { xml.contains("<network-security-config") }

    val nsc: NscModel? by lazy { if (isNsc) NscModel.parse(xml) else null }

    /** True for the arsc string pool and for plain res/values*.xml files. */
    val isStringsFile: Boolean = stringSource != null || PlainStrings.isValuesPath(path)

    /** Plain values files and a successfully name-mapped resources.arsc carry resource names; the raw arsc pool does not. */
    val hasNames: Boolean = namesAvailable ?: (stringSource == null)

    val strings: List<ResString> by lazy {
        try {
            stringSource?.invoke() ?: PlainStrings.parse(xml)
        } catch (_: Throwable) {
            RuleRegistry.noteError("res-parse")
            emptyList()
        }
    }

    /** Same shape as every other resource finding ("  [path]" suffix, `file` = path, so the list shows the location). */
    fun finding(sev: Severity, title: String, detail: String, rec: String, cwe: String): Finding =
        Finding(sev, title, detail + "  [" + path + "]", rec, null, -1, -1, cwe, path)
}

interface ResourceRule {
    val id: String
    val title: String
    /** Weaknesses this rule can report; every one must have an entry in VulnKnowledge (see RuleRegistry.audit). */
    val cwes: List<String> get() = emptyList()
    /** HIGH = exact structural setting or exact key format, MEDIUM = inferred / heuristic, LOW = informational. */
    val confidence: String get() = "HIGH"
    fun appliesTo(ctx: ResourceContext): Boolean
    fun scan(ctx: ResourceContext): List<Finding>
}

// ---------------------------------------------------------------------------------------------------------------------
// network security config model (tiny tokenizer, no DOM)
// ---------------------------------------------------------------------------------------------------------------------

class NscNode(val name: String, val attrs: Map<String, String>, val parent: NscNode?) {
    val children = ArrayList<NscNode>(4)
    val text = StringBuilder()

    fun child(n: String): NscNode? = children.firstOrNull { it.name == n }
    fun all(n: String): List<NscNode> = children.filter { it.name == n }
    fun walk(out: MutableList<NscNode>) {
        out.add(this)
        for (c in children) c.walk(out)
    }
    fun insideOf(n: String): Boolean {
        var cur: NscNode? = parent
        while (cur != null) {
            if (cur.name == n) return true
            cur = cur.parent
        }
        return false
    }
}

class NscDomain(val host: String, val subdomains: Boolean) {
    fun label(): String = host + (if (subdomains) " (+subdomains)" else "")
}

class NscModel(val root: NscNode) {
    val nodes: List<NscNode> by lazy { val l = ArrayList<NscNode>(); root.walk(l); l }
    val base: NscNode? get() = root.child("base-config")
    val debug: NscNode? get() = root.child("debug-overrides")
    val domainConfigs: List<NscNode> by lazy { nodes.filter { it.name == "domain-config" } }
    val pinSets: List<NscNode> by lazy { nodes.filter { it.name == "pin-set" } }

    fun boolAttr(n: NscNode, attr: String): Boolean? = parseBool(n.attrs[attr])

    /** A nested domain-config inherits the setting of its parents and of base-config unless it overrides it. */
    fun inheritedBool(n: NscNode, attr: String): Boolean? {
        var cur: NscNode? = n
        while (cur != null) {
            if (cur.name == "domain-config" || cur.name == "base-config") {
                val v = parseBool(cur.attrs[attr])
                if (v != null) return v
            }
            cur = cur.parent
        }
        return null
    }

    fun domains(dc: NscNode): List<NscDomain> = dc.all("domain").map { d ->
        NscDomain(d.text.toString().ifEmpty { "(domain not decoded)" }, parseBool(d.attrs["includeSubdomains"]) == true)
    }

    fun userCertNodes(n: NscNode): List<NscNode> =
        n.all("trust-anchors").flatMap { it.all("certificates") }.filter { it.attrs["src"] == "user" }

    companion object {
        private const val MAX_NODES = 3000
        private const val MAX_DEPTH = 40

        // groups: 1 = "/" of a closing tag, 2 = tag name, 3 = attributes, 4 = "/" of a self-closing tag, 5 = text
        private val tokenRe = rx("<!--[\\s\\S]*?-->|<\\?[\\s\\S]*?\\?>|<(/?)([A-Za-z_][\\w.:-]*)((?:\\s+[\\w.:-]+\\s*=\\s*\"[^\"]*\")*)\\s*(/?)>|([^<]+)")
        private val attrRe = rx("([\\w.:-]+)\\s*=\\s*\"([^\"]*)\"")

        fun parseBool(v: String?): Boolean? = when (v?.trim()?.lowercase()) {
            "true", "0xffffffff", "-1", "1" -> true
            "false", "0x0", "0" -> false
            else -> null
        }

        private fun unesc(s: String): String = s.replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")

        /** Works on the output of Axml.decode (one tag per line, text lines) and on plain XML. null = no usable root element. */
        fun parse(xml: String): NscModel? {
            val doc = NscNode("#doc", emptyMap(), null)
            val stack = ArrayList<NscNode>()
            stack.add(doc)
            var count = 0
            for (m in tokenRe.findAll(xml)) {
                val name = m.groups[2]?.value
                if (name != null) {
                    if (m.groupValues[1] == "/") {
                        val idx = stack.indexOfLast { it.name == name }
                        if (idx > 0) while (stack.size > idx) stack.removeAt(stack.size - 1)
                    } else {
                        if (++count > MAX_NODES) break
                        val attrs = LinkedHashMap<String, String>()
                        for (a in attrRe.findAll(m.groupValues[3])) attrs[a.groupValues[1]] = unesc(a.groupValues[2])
                        val node = NscNode(name, attrs, stack[stack.size - 1])
                        stack[stack.size - 1].children.add(node)
                        if (m.groupValues[4] != "/" && stack.size < MAX_DEPTH) stack.add(node)
                    }
                } else {
                    val t = m.groups[5]?.value
                    if (t != null && t.isNotBlank()) stack[stack.size - 1].text.append(unesc(t.trim()))
                }
            }
            val r = doc.child("network-security-config") ?: return null
            return NscModel(r)
        }
    }
}

private fun isLocalHost(h: String): Boolean {
    val x = h.lowercase()
    return x == "localhost" || x.endsWith(".localhost") || x.endsWith(".local") || x.endsWith(".test") || x.endsWith(".internal") ||
        rx("^(127|10)\\.\\d+\\.\\d+\\.\\d+$").containsMatchIn(x) || rx("^192\\.168\\.\\d+\\.\\d+$").containsMatchIn(x) ||
        rx("^172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+$").containsMatchIn(x)
}

// ---------------------------------------------------------------------------------------------------------------------
// network security config rules (res-nsc-*)
// ---------------------------------------------------------------------------------------------------------------------

/** cleartextTrafficPermitted="true" on base-config: every domain may use plain HTTP. (Moved from AndroGoatChecks.scanResourceXml, same title.) */
object NscCleartextRule : ResourceRule {
    override val id = "res-nsc-cleartext"
    override val title = "Network Security Config: cleartext permitted"
    override val cwes = listOf("CWE-319")
    override val confidence = "HIGH"

    override fun appliesTo(ctx: ResourceContext) = ctx.nsc != null

    override fun scan(ctx: ResourceContext): List<Finding> {
        val m = ctx.nsc ?: return emptyList()
        val base = m.base ?: return emptyList()
        if (m.boolAttr(base, "cleartextTrafficPermitted") != true) return emptyList()
        return listOf(ctx.finding(Severity.MEDIUM, title,   // 0.81.0: MEDIUM unless the code uses plain HTTP (FindingPolish.applyNetworkEvidence)
            "network_security_config.xml allows plain HTTP (cleartextTrafficPermitted=true) in base-config, i.e. for every domain the app talks to. Traffic can be read and modified on the network (MASVS-NETWORK).",
            "Set cleartextTrafficPermitted=\"false\" in base-config and use HTTPS everywhere. If one legacy host really needs HTTP, allow it in a domain-config for that host only.",
            "CWE-319"))
    }
}

/** cleartextTrafficPermitted="true" on specific domain-config entries (base-config stays safe). */
object NscCleartextDomainsRule : ResourceRule {
    override val id = "res-nsc-cleartext-domains"
    override val title = "Network Security Config: cleartext permitted for specific domains"
    override val cwes = listOf("CWE-319")
    override val confidence = "HIGH"

    override fun appliesTo(ctx: ResourceContext) = ctx.nsc != null

    override fun scan(ctx: ResourceContext): List<Finding> {
        val m = ctx.nsc ?: return emptyList()
        val base = m.base
        if (base != null && m.boolAttr(base, "cleartextTrafficPermitted") == true) return emptyList()   // already reported for every domain
        val hosts = ArrayList<NscDomain>()
        var anyUnknown = false
        for (dc in m.domainConfigs) {
            if (m.inheritedBool(dc, "cleartextTrafficPermitted") != true) continue
            val d = m.domains(dc)
            if (d.isEmpty()) anyUnknown = true
            hosts.addAll(d)
        }
        if (hosts.isEmpty() && !anyUnknown) return emptyList()
        val devOnly = hosts.isNotEmpty() && !anyUnknown && hosts.all { isLocalHost(it.host) }
        val shown = if (hosts.isEmpty()) "a domain-config" else hosts.take(5).joinToString(", ") { it.label() } + (if (hosts.size > 5) " and " + (hosts.size - 5) + " more" else "")
        return listOf(ctx.finding(if (devOnly) Severity.LOW else Severity.MEDIUM, title,
            "Plain HTTP is allowed for: " + shown + (if (devOnly) " (local / test hosts only: fine for development, make sure it is not shipped)." else ". Traffic to these hosts can be read and modified on the network."),
            "Move the backend to HTTPS and remove cleartextTrafficPermitted=\"true\". If a legacy host cannot be fixed yet, keep the exception scoped to that exact domain and track its removal.",
            "CWE-319"))
    }
}

/** <certificates src="user"/> : the app trusts CAs that the user (or malware) installed. Debug-only use is LOW. */
object NscUserCaRule : ResourceRule {
    override val id = "res-nsc-user-ca"
    override val title = "Network Security Config: trusts user-installed CAs"
    override val cwes = listOf("CWE-295")
    override val confidence = "HIGH"

    override fun appliesTo(ctx: ResourceContext) = ctx.nsc != null

    override fun scan(ctx: ResourceContext): List<Finding> {
        val m = ctx.nsc ?: return emptyList()
        val where = ArrayList<String>()
        var everyDomain = false
        val base = m.base
        if (base != null && m.userCertNodes(base).isNotEmpty()) {
            where.add("base-config (every domain)")
            everyDomain = true
        }
        for (dc in m.domainConfigs) {
            if (m.userCertNodes(dc).isEmpty()) continue
            where.add("domain-config " + m.domains(dc).take(3).joinToString(", ") { it.host })
        }
        val dbg = m.debug
        val inDebug = dbg != null && m.userCertNodes(dbg).isNotEmpty()
        if (where.isEmpty() && !inDebug) return emptyList()
        if (where.isEmpty()) {
            return listOf(ctx.finding(Severity.LOW, title,
                "The config trusts certificates the user installed (only inside debug-overrides, which Android applies only when the app is debuggable). A proxy such as Burp/mitmproxy can decrypt this app's HTTPS traffic in debug builds.",
                "Keep user CAs inside <debug-overrides> only, and make sure the shipped build is not debuggable.",
                "CWE-295"))
        }
        // 0.81.0: MEDIUM: trusting user CAs needs a CA the user (or a device admin / malware with that power) installed; it is the
        // standard set-up for self-hosted servers. Still listed so a reviewer sees it.
        return listOf(ctx.finding(if (everyDomain) Severity.MEDIUM else Severity.LOW, title,
            "The config trusts certificates the user installed in: " + where.joinToString("; ") +
                ". A proxy such as Burp/mitmproxy (or malware that installs a CA) can then decrypt this app's HTTPS traffic (MASVS-NETWORK).",
            "Trust only the system CAs (src=\"system\") in release builds; keep user CAs inside <debug-overrides> only.",
            "CWE-295"))
    }
}

/** <certificates overridePins="true"> outside debug-overrides: that CA is exempt from pin-set checks. */
object NscOverridePinsRule : ResourceRule {
    override val id = "res-nsc-override-pins"
    override val title = "Network Security Config: overridePins bypasses certificate pinning"
    override val cwes = listOf("CWE-295")
    override val confidence = "HIGH"

    override fun appliesTo(ctx: ResourceContext) = ctx.nsc != null

    override fun scan(ctx: ResourceContext): List<Finding> {
        val m = ctx.nsc ?: return emptyList()
        val hit = m.nodes.filter { it.name == "certificates" && NscModel.parseBool(it.attrs["overridePins"]) == true && !it.insideOf("debug-overrides") }
        if (hit.isEmpty()) return emptyList()
        val srcs = hit.map { it.attrs["src"] ?: "?" }.distinct().joinToString(", ")
        return listOf(ctx.finding(Severity.MEDIUM, title,
            "overridePins=true on certificate source(s): " + srcs + ". Certificates from that source are accepted even when they do not match the pin-set, so pinning does not protect against them.",
            "Remove overridePins=\"true\" from release configs. It is meant for <debug-overrides> (debugging proxy), not for shipped builds.",
            "CWE-295"))
    }
}

/** No <pin-set> anywhere in the config. Informational: pinning in code (OkHttp CertificatePinner) is checked by the code rules. */
object NscNoPinningRule : ResourceRule {
    override val id = "res-nsc-no-pinning"
    override val title = "Network Security Config: no certificate pinning (pin-set)"
    override val cwes = listOf("CWE-295")
    override val confidence = "LOW"

    override fun appliesTo(ctx: ResourceContext) = ctx.nsc != null

    override fun scan(ctx: ResourceContext): List<Finding> {
        val m = ctx.nsc ?: return emptyList()
        PostureScanner.nscPins = m.pinSets.isNotEmpty()   // 0.91.0: the posture table says whether a pin-set exists
        if (m.pinSets.isNotEmpty()) return emptyList()
        return listOf(ctx.finding(Severity.INFO, title,
            "The config has no <pin-set>, so any certificate signed by a trusted CA is accepted for these domains. (Pinning done in code with OkHttp CertificatePinner is not visible in this file.)",
            "For your own backend domains add a <pin-set> with a backup pin and an expiration date.",
            "CWE-295"))
    }
}

/** Pin lifecycle: expired pin-set (pinning silently stops), expires soon, single pin without a backup, empty pin-set. */
object NscPinLifecycleRule : ResourceRule {
    override val id = "res-nsc-pin-lifecycle"
    override val title = "Network Security Config: pin-set lifecycle"
    override val cwes = listOf("CWE-324", "CWE-295")
    override val confidence = "HIGH"

    private const val SOON_DAYS = 60L

    override fun appliesTo(ctx: ResourceContext) = ctx.nsc != null

    override fun scan(ctx: ResourceContext): List<Finding> {
        val m = ctx.nsc ?: return emptyList()
        if (m.pinSets.isEmpty()) return emptyList()
        val out = ArrayList<Finding>()
        val today = LocalDate.now()
        val expired = ArrayList<String>()
        val soon = ArrayList<String>()
        val noBackup = ArrayList<String>()
        for (ps in m.pinSets) {
            val hosts = ps.parent?.let { p -> m.domains(p).take(2).joinToString(", ") { it.host } }.orEmpty().ifEmpty { "(domain not decoded)" }
            val exp = ps.attrs["expiration"]?.trim()
            val date = try { if (exp != null) LocalDate.parse(exp) else null } catch (_: Throwable) { null }
            if (date != null) {
                val days = ChronoUnit.DAYS.between(today, date)
                if (days < 0) expired.add(hosts + " (expired " + exp + ")")
                else if (days <= SOON_DAYS) soon.add(hosts + " (" + exp + ", in " + days + " days)")
            }
            val pins = ps.all("pin").size
            if (pins <= 1) noBackup.add(hosts + (if (pins == 0) " (no <pin> element)" else ""))
        }
        if (expired.isNotEmpty()) {
            out.add(ctx.finding(Severity.MEDIUM, "Network Security Config: pin-set expired",
                "The pin-set of " + expired.joinToString("; ") + " is past its expiration date. Android stops enforcing an expired pin-set, so the app silently falls back to normal CA validation and certificate pinning no longer protects it.",
                "Ship an app update with fresh pins and a new expiration date. Plan the update well before the date and keep a backup pin so a certificate rotation never locks users out.",
                "CWE-324"))
        }
        if (soon.isNotEmpty()) {
            out.add(ctx.finding(Severity.LOW, "Network Security Config: pin-set expires soon",
                "The pin-set of " + soon.joinToString("; ") + " expires within " + SOON_DAYS + " days. After that date pinning stops being enforced for old installs.",
                "Release an update with the new pins and a later expiration before this date.",
                "CWE-324"))
        }
        if (noBackup.isNotEmpty()) {
            out.add(ctx.finding(Severity.LOW, "Network Security Config: pin-set has no backup pin",
                "The pin-set of " + noBackup.joinToString("; ") + " contains fewer than two pins. If that key is rotated or lost, the app cannot connect until every user updates it.",
                "Add a backup pin (the hash of a second key you generated in advance and keep offline) next to the current one.",
                "CWE-295"))
        }
        return out
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// strings: sources and filters
// ---------------------------------------------------------------------------------------------------------------------

/** Plain res/values (and values-xx) XML files (not present in a built APK, normal in an unpacked project): <string name=..> and <string-array>. */
internal object PlainStrings {
    private val pathRe = rx("(?:^|/)res/values[^/]*/[^/]+\\.xml$")
    private val stringRe = rx("<string(?![\\w-])((?:\"[^\"]*\"|[^>\"/]|/(?!>))*)>([\\s\\S]*?)</string>")
    private val arrayRe = rx("<(string-array|array)(?![\\w-])((?:\"[^\"]*\"|[^>\"/]|/(?!>))*)>([\\s\\S]*?)</\\1>")
    private val itemRe = rx("<item(?![\\w-])[^>]*>([\\s\\S]*?)</item>")
    private val nameRe = rx("name\\s*=\\s*\"([^\"]*)\"")
    private val cdataRe = rx("<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>")
    private const val MAX_STRINGS = 20000

    fun isValuesPath(p: String): Boolean = pathRe.containsMatchIn(p)

    fun parse(xml: String): List<ResString> {
        val out = ArrayList<ResString>()
        for (m in stringRe.findAll(xml)) {
            if (out.size >= MAX_STRINGS) break
            val name = nameRe.find(m.groupValues[1])?.groupValues?.get(1) ?: ""
            out.add(ResString(name, clean(m.groupValues[2])))
        }
        for (a in arrayRe.findAll(xml)) {
            val name = nameRe.find(a.groupValues[2])?.groupValues?.get(1) ?: ""
            for (i in itemRe.findAll(a.groupValues[3])) {
                if (out.size >= MAX_STRINGS) break
                out.add(ResString(name, clean(i.groupValues[1])))
            }
        }
        return out
    }

    private fun clean(raw: String): String {
        var v = raw.trim()
        val c = cdataRe.find(v)
        if (c != null) v = c.groupValues[1]
        v = v.replace("\\'", "'").replace("\\\"", "\"").replace("\\n", " ")
            .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'")
        if (v.length >= 2 && v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length - 1)
        return v.trim()
    }
}

/**
 * Reads the GLOBAL string pool of resources.arsc in place and returns only the candidate strings: 20..4096 chars and no
 * whitespace (or a PEM header). UI text has spaces, so it never gets here; no key, token or URL we look for is shorter than 20.
 * Strings that fail the length test are skipped BEFORE they are decoded, so nothing big is allocated. null = not a table.
 *
 * 0.46.0: the pool is now a small random-access reader ([StrPool]) and [namedStrings] also walks the table packages and their
 * RES_TABLE_TYPE chunks of type "string", so every candidate value carries its ORIGINAL RESOURCE NAME (the entry name from the
 * key pool: api_key, stripe_secret, auth_token ...). That is what lets the name-based secret rule run on a built APK; the value
 * strings alone never carried names. Name extraction stops at the first (default-config) TYPE chunk per type id.
 */
internal object ArscPool {
    private const val MIN_LEN = 20
    private const val MAX_LEN = 4096
    private const val MAX_OUT = 60000
    private const val MAX_NAMED = 40000

    /** Random-access reader over one string-pool chunk (UTF-8 or UTF-16, length-prefixed entries). */
    internal class StrPool(private val b: ByteArray, private val bb: ByteBuffer, private val pos: Int) {
        private val count = bb.getInt(pos + 8)
        private val flags = bb.getInt(pos + 16)
        private val start = bb.getInt(pos + 20)
        private val hdr = bb.getShort(pos + 2).toInt() and 0xFFFF
        private val utf8 = (flags and 0x100) != 0

        val size: Int get() = count

        /** Decoded string at pool index [i]; null when the entry is out of range or malformed. Never throws. */
        fun get(i: Int): String? {
            if (i < 0 || i >= count) return null
            try {
                var p = pos + start + bb.getInt(pos + hdr + i * 4)
                if (utf8) {
                    var l = bb.get(p).toInt() and 0xFF
                    p++
                    if ((l and 0x80) != 0) { l = ((l and 0x7F) shl 8) or (bb.get(p).toInt() and 0xFF); p++ }
                    var bl = bb.get(p).toInt() and 0xFF
                    p++
                    if ((bl and 0x80) != 0) { bl = ((bl and 0x7F) shl 8) or (bb.get(p).toInt() and 0xFF); p++ }
                    if (l < 0 || l > MAX_LEN || bl < 0 || p + bl > b.size) return null
                    return String(b, p, bl, Charsets.UTF_8)
                }
                var l = bb.getShort(p).toInt() and 0xFFFF
                p += 2
                if ((l and 0x8000) != 0) { l = ((l and 0x7FFF) shl 16) or (bb.getShort(p).toInt() and 0xFFFF); p += 2 }
                if (l < 0 || l > MAX_LEN || p + l * 2 > b.size) return null
                return String(b, p, l * 2, Charsets.UTF_16LE)
            } catch (_: Throwable) {
                return null
            }
        }
    }

    private fun u16(bb: ByteBuffer, p: Int) = bb.getShort(p).toInt() and 0xFFFF

    /** The global string pool of the table; null = not a resource table. */
    private fun globalPool(b: ByteArray): StrPool? {
        if (b.size < 16) return null
        val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
        if (u16(bb, 0) != 0x0002) return null
        var pos = u16(bb, 2)
        val total = minOf(bb.getInt(4), b.size)
        while (pos + 8 <= total) {
            val type = u16(bb, pos)
            val size = bb.getInt(pos + 4)
            if (size < 8 || pos + size > b.size) return null
            if (type == 0x0001) return StrPool(b, bb, pos)
            pos += size
        }
        return null
    }

    fun candidates(b: ByteArray): List<ResString>? {
        try {
            val pool = globalPool(b) ?: return null
            val out = ArrayList<ResString>()
            if (pool.size <= 0 || pool.size > 3_000_000) return out
            for (i in 0 until pool.size) {
                if (out.size >= MAX_OUT) break
                val s = pool.get(i) ?: continue
                if (s.length >= MIN_LEN && isCandidate(s)) out.add(ResString("", s))
            }
            return out
        } catch (_: Throwable) {
            return null
        }
    }

    /**
     * 0.46.0: candidate strings WITH their resource names. Walks every package chunk, reads its type-name and key-name pools,
     * and for each RES_TABLE_TYPE chunk named "string" (first / default config only) maps entry name -> value string through
     * the global pool. null = table unreadable (the caller falls back to [candidates], then to the byte scan).
     */
    fun namedStrings(b: ByteArray): List<ResString>? {
        try {
            val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            val pool = globalPool(b) ?: return null
            val out = LinkedHashMap<String, ResString>()
            var pos = u16(bb, 2)
            val total = minOf(bb.getInt(4), b.size)
            while (pos + 8 <= total) {
                val type = u16(bb, pos)
                val hdr = u16(bb, pos + 2)
                val size = bb.getInt(pos + 4)
                if (size < 8 || pos + size > b.size) return null
                if (type == 0x0200) readPackage(b, bb, pos, hdr, size, pool, out)   // RES_TABLE_PACKAGE_TYPE (0.46.3: was wrongly 0x0000)
                pos += size
            }
            return out.values.toList()
        } catch (_: Throwable) {
            return null
        }
    }

    private fun readPackage(b: ByteArray, bb: ByteBuffer, pos: Int, hdr: Int, size: Int, pool: StrPool, out: LinkedHashMap<String, ResString>) {
        if (hdr < 284 || pos + hdr > b.size) return
        // ResTable_package: id(4) @+8, name char16[128] @+12, typeStrings off @+268, lastPublicType @+272, keyStrings off @+276
        val typeStringsOff = bb.getInt(pos + 268)
        val keyStringsOff = bb.getInt(pos + 276)
        if (typeStringsOff <= 0 || keyStringsOff <= 0 || typeStringsOff >= size || keyStringsOff >= size) return
        if (u16(bb, pos + typeStringsOff) != 0x0001 || u16(bb, pos + keyStringsOff) != 0x0001) return
        val typePool = StrPool(b, bb, pos + typeStringsOff)
        val keyPool = StrPool(b, bb, pos + keyStringsOff)
        val seenTypeIds = HashSet<Int>()
        var p = pos + hdr
        val end = pos + size
        while (p + 8 <= end) {
            val st = u16(bb, p)
            val shdr = u16(bb, p + 2)
            val ssize = bb.getInt(p + 4)
            if (ssize < 8 || p + ssize > b.size) return
            if (st == 0x0201) {   // RES_TABLE_TYPE
                val typeId = bb.get(p + 8).toInt() and 0xFF
                if (seenTypeIds.add(typeId) && typeId >= 1) {
                    val typeName = typePool.get(typeId - 1)
                    if (typeName == "string") readStringEntries(b, bb, p, shdr, ssize, pool, keyPool, out)
                }
            }
            p += ssize
        }
    }

    private fun readStringEntries(b: ByteArray, bb: ByteBuffer, tp: Int, hdr: Int, size: Int, pool: StrPool, keyPool: StrPool, out: LinkedHashMap<String, ResString>) {
        // ResTable_type after the chunk header: id(1) res0(1) res1(2) entryCount(4)@+12 entriesStart(4)@+16 config@+20
        val entryCount = bb.getInt(tp + 12)
        val entriesStart = bb.getInt(tp + 16)
        if (entryCount <= 0 || entryCount > 200_000) return
        if (entriesStart < hdr || entriesStart >= size) return
        // 0.46.2: type flags byte at +9: FLAG_SPARSE 0x01 (entries array = pairs idx(2) + offset/4(2)), FLAG_OFFSET16 0x02 (u16 offset/4,
        // 0xFFFF = none); otherwise u32 offsets, -1 = none.
        val tflags = bb.get(tp + 9).toInt() and 0xFF
        val sparse = (tflags and 0x01) != 0
        val off16 = !sparse && (tflags and 0x02) != 0
        val stride = if (off16) 2 else 4
        for (j in 0 until entryCount) {
            if (out.size >= MAX_NAMED) return
            val offPos = tp + hdr + j * stride
            if (offPos + stride > tp + size) return
            val off: Long
            if (sparse) {
                off = u16(bb, offPos + 2).toLong() * 4L
            } else if (off16) {
                val v = u16(bb, offPos)
                if (v == 0xFFFF) continue
                off = v.toLong() * 4L
            } else {
                val v = bb.getInt(offPos)
                if (v == -1) continue
                off = v.toLong() and 0xFFFFFFFFL
            }
            if (off < 0L || off >= size.toLong()) continue
            val e = tp + entriesStart + off.toInt()
            if (e + 16 > tp + size) continue
            val flags = u16(bb, e + 2)
            if ((flags and 0x0008) != 0) continue                    // compact entry: different layout, skipped
            if ((flags and 0x0001) != 0) continue                    // complex (map) entry: bags, styles, arrays
            val keyIdx = bb.getInt(e + 4)
            val dataType = bb.get(e + 11).toInt() and 0xFF           // Res_value: size(2) res0(1) dataType(1) data(4)
            if (dataType != 0x03) continue                           // TYPE_STRING only
            val valueIdx = bb.getInt(e + 12)
            val value = pool.get(valueIdx) ?: continue
            if (value.length < MIN_LEN || !isCandidate(value)) continue
            val name = keyPool.get(keyIdx) ?: ""
            if (name.isEmpty()) continue
            if (!out.containsKey(name)) out[name] = ResString(name, value)
        }
    }

    private fun isCandidate(s: String): Boolean {
        if (s.startsWith("-----BEGIN")) return true
        for (ch in s) if (ch.isWhitespace()) return false
        return true
    }
}

/** False-positive filters shared by the strings rules. */
internal object SecretFilters {
    private val placeholderWords = listOf(
        "example", "your_", "your-", "yourkey", "your key", "xxxx", "dummy", "sample", "placeholder", "changeme", "change_me",
        "insert", "replace", "todo", "fake", "<", ">", "{{", "\${", "%s", "%1\$s", "*****", "....", "redacted"
    )

    fun entropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in s) counts[c] = (counts[c] ?: 0) + 1
        var h = 0.0
        for (n in counts.values) {
            val p = n.toDouble() / s.length
            h -= p * (Math.log(p) / Math.log(2.0))
        }
        return h
    }

    fun distinct(s: String): Int = s.toSet().size

    /** upper / lower / digit / symbol present. */
    fun classes(s: String): Int {
        var c = 0
        if (s.any { it.isUpperCase() }) c++
        if (s.any { it.isLowerCase() }) c++
        if (s.any { it.isDigit() }) c++
        if (s.any { !it.isLetterOrDigit() }) c++
        return c
    }

    fun isPlaceholder(s: String): Boolean {
        val l = s.lowercase()
        if (placeholderWords.any { l.contains(it) }) return true
        return s.length >= 16 && distinct(s) < 6
    }

    /** A random-looking token body: enough different characters and entropy, not a placeholder. */
    fun randomLooking(body: String, minEntropy: Double, minDistinct: Int): Boolean =
        !isPlaceholder(body) && distinct(body) >= minDistinct && entropy(body) >= minEntropy

    fun mask(s: String): String = s.take(6) + "..." + " (" + s.length + " chars)"

    /** For a value stored under a credential-like NAME: no word, no sentence, no reference, no format string, no plain URL. */
    fun looksLikeSecretValue(v: String): Boolean {
        if (v.length < 12 || v.length > 512) return false
        if (v.any { it.isWhitespace() }) return false
        if (v.startsWith("@") || v.startsWith("?") || v.contains("%s") || v.contains("%1\$s") || v.contains("{")) return false
        if (v.startsWith("http://") || v.startsWith("https://")) return false
        if (isPlaceholder(v)) return false
        if (v.all { it.isLetter() } || v.all { it.isDigit() }) return false
        if (rx("^[A-Za-z]+([._-][A-Za-z]+)+$").containsMatchIn(v)) return false    // identifiers: com.example.app, some_resource_name
        return entropy(v) >= 3.2 && classes(v) >= 2
    }
}

/** Patterns shared by several rules (so the name-based rule can skip what a format rule already reports). */
internal object ResPatterns {
    val google = rx("(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")
    val firebaseAppId = rx("^\\d+:\\d{6,}:android:[0-9a-f]{12,}$")
    val firebaseUrl = rx("https?://([a-z0-9][a-z0-9-]{2,62})(?:\\.[a-z0-9-]+)?\\.(?:firebaseio\\.com|firebasedatabase\\.app)(?![a-z0-9.-])")
    val aws = rx("(?<![0-9A-Za-z])(AKIA|ASIA)([0-9A-Z]{16})(?![0-9A-Za-z])")
    val jwt = rx("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\\.eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])")

    fun isKnownFormat(v: String): Boolean =
        google.containsMatchIn(v) || aws.containsMatchIn(v) || jwt.containsMatchIn(v) || ResKnownTokensRule.matchesAny(v)
}

// ---------------------------------------------------------------------------------------------------------------------
// strings rules (res-strings-*)
// ---------------------------------------------------------------------------------------------------------------------

private const val REC_KEY = "Remove the secret from the APK, rotate it (it must be treated as leaked), and keep it on a server you control; the app should call your backend instead."

/** AIza... Google API key. LOW when the APK also carries the Firebase app id (the standard client key), MEDIUM otherwise. */
object ResGoogleApiKeyRule : ResourceRule {
    override val id = "res-strings-google-api-key"
    override val title = "Google API key in resources"
    override val cwes = listOf("CWE-798")
    override val confidence = "MEDIUM"

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile

    override fun scan(ctx: ResourceContext): List<Finding> {
        val keys = LinkedHashSet<String>()
        var firebaseApp = false
        for (s in ctx.strings) {
            val v = s.value
            if (!firebaseApp && ResPatterns.firebaseAppId.containsMatchIn(v)) firebaseApp = true
            for (m in ResPatterns.google.findAll(v)) {
                val body = m.value.substring(4)
                if (SecretFilters.randomLooking(body, 3.2, 12)) keys.add(m.value)
            }
        }
        if (keys.isEmpty()) return emptyList()
        val first = SecretFilters.mask(keys.first()) + (if (keys.size > 1) " and " + (keys.size - 1) + " more" else "")
        return listOf(ctx.finding(if (firebaseApp) Severity.LOW else Severity.MEDIUM, title,
            "A Google API key (" + first + ") is stored in the app resources. " +
                (if (firebaseApp) "The APK also has a Firebase app id, so this is the standard client key of google-services: it is meant to ship in the app, but it is only safe when it is restricted. "
                else "Anyone who unpacks the APK can read it and use your quota. ") +
                "Check it in the Google Cloud console (Credentials).",
            "Restrict the key to this app (package name + SHA-1) and to the APIs you use, set a quota alert, and rotate it if it was ever unrestricted.",
            "CWE-798"))
    }
}

/** Firebase Realtime Database URL. A lead, not proof: the question is whether the database rules are open. */
object ResFirebaseUrlRule : ResourceRule {
    override val id = "res-strings-firebase-url"
    override val title = "Firebase Realtime Database URL"
    override val cwes = listOf("CWE-284")
    override val confidence = "MEDIUM"

    private val fakeIds = setOf("project-id", "your-project", "my-project", "myproject", "example", "demo", "test")

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile

    override fun scan(ctx: ResourceContext): List<Finding> {
        val urls = LinkedHashSet<String>()
        for (s in ctx.strings) {
            for (m in ResPatterns.firebaseUrl.findAll(s.value)) {
                val pid = m.groupValues[1]
                if (pid.startsWith("s-") && pid.contains("-nss-")) continue          // Firebase SDK wire hosts, not an app database
                if (pid in fakeIds || pid.contains("your") || pid.contains("example") || pid.contains("xxxx")) continue
                urls.add(m.value)
            }
        }
        if (urls.isEmpty()) return emptyList()
        return listOf(ctx.finding(Severity.MEDIUM, title,
            "The app resources contain a Firebase Realtime Database URL (" + urls.first().take(60) + (if (urls.size > 1) " and " + (urls.size - 1) + " more" else "") +
                "). The URL alone is not a flaw, but if the database rules allow public reads or writes, anyone can dump or change the data. This cannot be checked statically.",
            "Open this URL + \"/.json\" from a test device you own: if it returns data, the database rules allow public reads. Lock the rules down (auth != null) and require authentication.",
            "CWE-284"))
    }
}

/** AWS access key id (AKIA long-term, ASIA temporary). CRITICAL when a 40-char secret-looking string sits next to it. */
object ResAwsKeysRule : ResourceRule {
    override val id = "res-strings-aws-keys"
    override val title = "AWS access key ID embedded"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    private val secretRe = rx("^[A-Za-z0-9/+]{40}$")

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile

    override fun scan(ctx: ResourceContext): List<Finding> {
        val ids = LinkedHashSet<String>()
        var longTerm = false
        var secret = false
        for (s in ctx.strings) {
            val v = s.value
            for (m in ResPatterns.aws.findAll(v)) {
                val body = m.groupValues[2]
                if (body.endsWith("EXAMPLE") || !body.any { it.isDigit() } || !SecretFilters.randomLooking(body, 3.0, 8)) continue
                ids.add(m.value)
                if (m.groupValues[1] == "AKIA") longTerm = true
            }
            if (!secret && secretRe.containsMatchIn(v) && SecretFilters.classes(v) >= 3 && v.any { it.isUpperCase() } && SecretFilters.entropy(v) >= 4.2 &&
                !SecretFilters.isPlaceholder(v)) secret = true
        }
        if (ids.isEmpty()) return emptyList()
        val first = SecretFilters.mask(ids.first())
        if (secret) {
            return listOf(ctx.finding(Severity.CRITICAL, "AWS access key pair embedded",
                "An AWS access key id (" + first + ") and a 40-character secret-looking string are both stored in the resources. If this is the matching secret key, whoever unpacks the APK can call AWS as this identity.",
                REC_KEY + " Deactivate the key in IAM now and use Cognito or a backend that issues short-lived credentials.",
                "CWE-798"))
        }
        return listOf(ctx.finding(if (longTerm) Severity.HIGH else Severity.MEDIUM, title,
            "An AWS access key id (" + first + ", " + (if (longTerm) "long-term AKIA key" else "temporary ASIA session key") + ") is stored in the resources. On its own it only identifies the key, but its secret is usually next to it in the code or the assets.",
            REC_KEY + " Check the key in IAM and deactivate it if it is still active.",
            "CWE-798"))
    }
}

/** eyJ... JSON Web Tokens: decoded and judged by their claims (role, exp), so public anon keys and expired tokens do not look like leaks. */
object ResJwtRule : ResourceRule {
    override val id = "res-strings-jwt"
    override val title = "JWT embedded in resources"
    override val cwes = listOf("CWE-798")
    override val confidence = "MEDIUM"

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile

    private fun json(seg: String): JSONObject? = try {
        JSONObject(String(Base64.getUrlDecoder().decode(seg), Charsets.UTF_8))
    } catch (_: Throwable) {
        null
    }

    override fun scan(ctx: ResourceContext): List<Finding> {
        val out = ArrayList<Finding>()
        val seenTitles = HashSet<String>()
        for (s in ctx.strings) {
            for (m in ResPatterns.jwt.findAll(s.value)) {
                val parts = m.value.split('.')
                if (parts.size != 3) continue
                val header = json(parts[0]) ?: continue
                val payload = json(parts[1]) ?: continue
                if (!header.has("alg")) continue                       // not a JWT: random base64 that starts with eyJ
                val alg = header.optString("alg")
                val role = payload.optString("role")
                val exp = payload.optLong("exp", 0L)
                val now = System.currentTimeMillis() / 1000L
                val claims = payload.keys().asSequence().take(8).joinToString(", ")
                val shown = SecretFilters.mask(m.value) + ", alg " + alg + ", claims: " + claims
                val sev: Severity
                val t: String
                val d: String
                when {
                    role == "service_role" -> {
                        sev = Severity.CRITICAL; t = "JWT with a privileged role embedded"
                        d = "A token with role service_role (" + shown + ") is stored in the resources. Tokens of this kind bypass row-level security and give full access to the project's data."
                    }
                    role == "anon" -> {
                        sev = Severity.LOW; t = "Public (anon) JWT in resources"
                        d = "An anonymous-role token (" + shown + ") is stored in the resources. These keys are public by design, so what protects the data is the backend access policy (row-level security / rules), not the secrecy of the token."
                    }
                    exp > 0L && exp < now -> {
                        sev = Severity.LOW; t = "Expired JWT embedded in resources"
                        d = "A token (" + shown + ") that has already expired is stored in the resources. It cannot be used any more, but it still shows who issued it and what its claims are, and it suggests that tokens are pasted into the code."
                    }
                    else -> {
                        sev = Severity.HIGH; t = title
                        d = "A signed token (" + shown + (if (exp > 0L) ", still valid" else ", no expiry") + ") is stored in the resources. Anyone who unpacks the APK can replay it as a bearer token" +
                            (if (alg.equals("none", ignoreCase = true)) ". The algorithm is none, so the token is not even signed." else ".")
                    }
                }
                if (!seenTitles.add(t)) continue
                out.add(ctx.finding(sev, t, d,
                    "Do not ship tokens in the app. Issue them after login from your backend with a short lifetime, and revoke this one.",
                    "CWE-798"))
            }
        }
        return out
    }
}

/** Other well-known key formats (strict prefix + entropy + placeholder filter). One finding per format. */
object ResKnownTokensRule : ResourceRule {
    override val id = "res-strings-known-tokens"
    override val title = "Known secret formats in resources"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    private class Fmt(val title: String, val re: Regex, val sev: Severity, val minEntropy: Double, val rec: String)

    private val formats = listOf(
        Fmt("Anthropic API key embedded", rx("(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}"), Severity.HIGH, 3.5, REC_KEY),
        Fmt("OpenAI API key embedded", rx("(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"), Severity.HIGH, 4.0, REC_KEY),
        Fmt("Hugging Face token embedded", rx("(?<![A-Za-z0-9_-])hf_[A-Za-z0-9]{30,}"), Severity.HIGH, 3.8, REC_KEY),
        Fmt("GitHub token embedded", rx("(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}"), Severity.HIGH, 3.8, REC_KEY),
        Fmt("Slack token embedded", rx("(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,}"), Severity.HIGH, 3.0, REC_KEY),
        Fmt("Stripe live secret key embedded", rx("(?<![A-Za-z0-9_])sk_live_[A-Za-z0-9]{16,}"), Severity.CRITICAL, 3.3, REC_KEY),
        Fmt("SendGrid API key embedded", rx("(?<![A-Za-z0-9_-])SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"), Severity.HIGH, 3.8, REC_KEY),
        Fmt("Google OAuth client secret embedded", rx("(?<![A-Za-z0-9_-])GOCSPX-[A-Za-z0-9_-]{28}"), Severity.HIGH, 3.5, REC_KEY),
        Fmt("FCM legacy server key embedded", rx("(?<![A-Za-z0-9_-])AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}"), Severity.CRITICAL, 4.0, REC_KEY),
        Fmt("Telegram bot token embedded", rx("(?<![0-9A-Za-z_-])\\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])"), Severity.HIGH, 3.8, REC_KEY),
        Fmt("GitLab access token embedded", rx("(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20}(?![A-Za-z0-9_-])"), Severity.HIGH, 3.5, REC_KEY),
        Fmt("npm access token embedded", rx("(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), Severity.HIGH, 3.8, REC_KEY),
        Fmt("Shopify access token embedded", rx("(?<![A-Za-z0-9_])shp(?:at|ca|pa|ss)_[0-9a-f]{32}(?![0-9a-f])"), Severity.HIGH, 3.0, REC_KEY),
        Fmt("Square access token embedded", rx("(?<![A-Za-z0-9_-])sq0(?:atp|csp)-[A-Za-z0-9_-]{22,}"), Severity.HIGH, 3.5, REC_KEY),
        Fmt("Azure storage account key embedded", rx("AccountKey=[A-Za-z0-9+/=]{40,}"), Severity.HIGH, 4.0, REC_KEY),
        Fmt("Private key embedded", rx("-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\\\\[rn]|\\s)*[A-Za-z0-9+/]{40,}"), Severity.CRITICAL, 0.0, REC_KEY),
        Fmt("Discord webhook URL embedded", rx("discord(?:app)?\\.com/api/webhooks/\\d{15,}/[A-Za-z0-9_-]{30,}"), Severity.MEDIUM, 3.5,
            "Anyone with this URL can post to your channel. Delete the webhook and send messages from your server instead."),
        Fmt("Slack webhook URL embedded", rx("hooks\\.slack\\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"), Severity.MEDIUM, 3.5,
            "Anyone with this URL can post to your workspace. Revoke the webhook and send messages from your server instead."),
        Fmt("Cloud storage bucket URL (S3/GCS)", rx("[a-z0-9.-]+\\.s3[.-][a-z0-9.-]*amazonaws\\.com|storage\\.googleapis\\.com/[a-z0-9._-]+"), Severity.LOW, 0.0,
            "Check the bucket's ACL/policy: it must not allow public listing or writes. Use pre-signed URLs from your backend.")
    )

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile

    /** Used by the name-based rule to skip values that a format rule already reports. */
    fun matchesAny(v: String): Boolean = formats.any { it.re.containsMatchIn(v) }

    override fun scan(ctx: ResourceContext): List<Finding> {
        val hits = LinkedHashMap<Fmt, MutableSet<String>>()
        for (s in ctx.strings) {
            val v = s.value
            for (f in formats) {
                for (m in f.re.findAll(v)) {
                    val tok = m.value
                    if (f.minEntropy > 0.0 && !SecretFilters.randomLooking(tok, f.minEntropy, 10)) continue
                    hits.getOrPut(f) { LinkedHashSet() }.add(tok)
                }
            }
        }
        val out = ArrayList<Finding>()
        for ((f, toks) in hits) {
            val what = if (f.title.startsWith("Private key")) "A PEM private key header" else SecretFilters.mask(toks.first())
            out.add(ctx.finding(f.sev, f.title,
                "Found in the app resources (" + what + (if (toks.size > 1) ", " + toks.size + " distinct values" else "") + "). App resources are readable by anyone who unpacks the APK.",
                f.rec, "CWE-798"))
        }
        return out
    }
}

/** scheme://user:password@host with a real-looking password. */
object ResUrlCredentialsRule : ResourceRule {
    override val id = "res-strings-url-credentials"
    override val title = "Hardcoded credentials in a URL"
    override val cwes = listOf("CWE-798")
    override val confidence = "MEDIUM"

    private val re = rx("[a-zA-Z][a-zA-Z0-9+.-]{1,10}://([^\\s/:@\"']{1,64}):([^\\s/@\"']{3,128})@([A-Za-z0-9.-]{3,})")
    private val fakePass = setOf("password", "pass", "passwd", "pwd", "secret", "user", "username", "xxx", "xxxx", "token")

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile

    override fun scan(ctx: ResourceContext): List<Finding> {
        for (s in ctx.strings) {
            for (m in re.findAll(s.value)) {
                val pass = m.groupValues[2]
                val host = m.groupValues[3].lowercase()
                if (pass.lowercase() in fakePass || SecretFilters.isPlaceholder(pass) || pass.contains("%") || pass.contains('$')) continue
                if (host.endsWith("example.com") || host.endsWith("example.org")) continue
                return listOf(ctx.finding(Severity.HIGH, title,
                    "A URL with an embedded user name and password (user " + m.groupValues[1].take(3) + "..., host " + host + ") is stored in the resources.",
                    "Remove the credentials from the URL and rotate that password. Authenticate with a per-user token obtained after login.",
                    "CWE-798"))
            }
        }
        return emptyList()
    }
}

/** Credential-like NAME + credential-like VALUE (api_key, stripe_secret, auth_token ...). 0.46.0: also runs on resources.arsc when the entry names were mapped from the key pool, so it works on the built APK, not only on unpacked values files. */
object ResSecretNamesRule : ResourceRule {
    override val id = "res-strings-secret-names"
    override val title = "Credential-like value in string resources"
    override val cwes = listOf("CWE-798")
    override val confidence = "MEDIUM"

    private val nameRe = rx("(?i)(^|[_.-])(api[_-]?key|apikey|secret|client[_-]?secret|passw(?:or)?d|passwd|pwd|private[_-]?key|access[_-]?(?:key|token)|auth[_-]?(?:key|token)|token|bearer|signing[_-]?key|encryption[_-]?key)($|[_.-])")
    private val uiRe = rx("(?i)(label|title|hint|text|desc|description|message|msg|error|summary|prompt|button|btn|dialog|header|placeholder|toast|info|cd|format|name|type|expired|invalid|required|empty|wrong|forgot|reset|show|hide|enter|confirm|change|login|sign_?in|sign_?up)$")

    private val uiPrefixRe = rx("(?i)^(forgot|reset|enter|confirm|change|show|hide|invalid|wrong|empty|login|sign_?in|sign_?up)[_.-]")

    override fun appliesTo(ctx: ResourceContext) = ctx.isStringsFile && ctx.hasNames

    override fun scan(ctx: ResourceContext): List<Finding> {
        val hits = ArrayList<String>()
        for (s in ctx.strings) {
            if (s.name.isEmpty() || !nameRe.containsMatchIn(s.name) || uiRe.containsMatchIn(s.name) || uiPrefixRe.containsMatchIn(s.name)) continue
            if (!SecretFilters.looksLikeSecretValue(s.value)) continue
            if (ResPatterns.isKnownFormat(s.value)) continue          // the format rules already report it
            hits.add(s.name + " = " + SecretFilters.mask(s.value))
        }
        if (hits.isEmpty()) return emptyList()
        return listOf(ctx.finding(Severity.MEDIUM, title,
            "String resources with a credential-like name and a random-looking value: " + hits.take(4).joinToString("; ") + (if (hits.size > 4) " and " + (hits.size - 4) + " more" else "") +
                ". The value is not a word, a reference or a placeholder.",
            REC_KEY, "CWE-798"))
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// pipeline: one file at a time
// ---------------------------------------------------------------------------------------------------------------------

class ResourceScanResult(val findings: List<Finding>, val stats: String)

/**
 * 0.82.0: one LOW card per APK about native code, because a reader must know a part of the app was NOT looked at:
 * (1) the dex loads native libraries (System.loadLibrary / System.load) but this APK has no lib/ *.so: they ship in an ABI split
 * (manifest requiredSplitTypes) that was not given to the scanner; (2) the APK has .so files: they are not analysed.
 */
internal fun nativeCoverageFinding(zip: java.util.zip.ZipFile, manifest: String?): Finding? {
    val sos = ArrayList<String>()
    for (e in zip.entries()) if (e.name.startsWith("lib/") && e.name.endsWith(".so")) sos.add(e.name.substringAfterLast('/'))
    val loads = ApkFacts.dexMentions(zip, listOf("loadLibrary")).isNotEmpty()
    val abiSplit = manifest != null && Regex("requiredSplitTypes\\s*=\\s*\"[^\"]*abi").containsMatchIn(manifest)
    val (title, detail) = when {
        sos.isEmpty() && (loads || abiSplit) -> "Native code not in this APK (not analysed)" to
            ("The app's code loads native libraries" + (if (abiSplit) " and the manifest declares an ABI split (requiredSplitTypes)" else "") +
                ", but this APK contains no lib/*.so: the native code ships in a separate split APK that was not scanned. Install-time splits " +
                "(base__abi) must be extracted from the device or the store bundle to look at them.")
        sos.isNotEmpty() -> "Native libraries not analysed (${sos.distinct().size} .so)" to
            ("This APK contains native libraries (" + sos.distinct().take(8).joinToString(", ") + (if (sos.distinct().size > 8) ", ..." else "") +
                "). APKReLab analyses Java / Kotlin (dex) code only: data handed to native methods is not followed.")
        else -> return null
    }
    return Finding(Severity.LOW, title, detail,
        "Review the native code separately (e.g. strings / imports of the .so, a disassembler) and check what the app passes to its JNI methods.",
        null, -1, -1, "", "lib/").also { it.ruleId = "native-coverage"; it.confidence = "HIGH" }
}

object ResourceScanner {
    private const val MAX_XML = 100_000
    private const val MAX_VALUES_XML = 1_500_000
    private const val MAX_FILES = 2500
    private const val MAX_ARSC = 40_000_000

    /** Resource rules on one decoded (or plain) XML file, plus the two layout checks that still live in AndroGoatChecks (keyboard cache, FileProvider paths). */
    fun scanXml(path: String, xml: String, apk: ApkFacts = ApkFacts.NONE): List<Finding> {
        val out = ArrayList<Finding>()
        try { out.addAll(RuleRegistry.runResource(ResourceContext(path, xml, apk = apk))) } catch (_: Throwable) { RuleRegistry.noteError("res-engine") }
        try { out.addAll(AndroGoatChecks.scanResourceXml(path, xml)) } catch (_: Throwable) { RuleRegistry.noteError("androgoat-res-xml") }
        return FindingPolish.applyResource(out)
    }

    /** Strings of resources.arsc through the rules. If the table cannot be read, the old byte scan runs instead (it never returns nothing silently). */
    fun scanArsc(raw: ByteArray): List<Finding> {
        // 0.46.0: named strings first (entry names from the key pool -> name-based secret rules work on the built APK),
        // then the nameless pool, then the byte scan. Each step is a full fallback, never a silent miss.
        val named = try { ArscPool.namedStrings(raw) } catch (_: Throwable) { null }
        if (named != null && named.isNotEmpty()) {
            arscCandidates = named.size
            arscNamed = true
            val ctx = ResourceContext("resources.arsc", "", stringSource = { named }, namesAvailable = true)
            return FindingPolish.applyResource(RuleRegistry.runResource(ctx))
        }
        arscNamed = false
        val cands = ArscPool.candidates(raw)
        if (cands == null) {
            RuleRegistry.noteError("res-arsc-pool")
            return AndroGoatChecks.scanArsc(raw)
        }
        arscCandidates = cands.size
        val ctx = ResourceContext("resources.arsc", "", stringSource = { cands })
        return FindingPolish.applyResource(RuleRegistry.runResource(ctx))
    }

    /**
     * 0.75.2: per-layout findings with the same verdict on every screen (tapjacking, keyboard cache) become ONE card per title: the worst
     * severity, the first file as location, the other files listed, count = number of layouts. Device reports had 5-8 identical cards.
     */
    private val GROUPED_TITLES = setOf("Password screen not protected against tapjacking", "Keyboard cache: sensitive input field")

    internal fun groupLayoutFindings(list: List<Finding>): List<Finding> {
        val out = ArrayList<Finding>()
        val groups = LinkedHashMap<String, MutableList<Finding>>()
        for (f in list) if (f.title in GROUPED_TITLES && f.file.isNotEmpty()) groups.getOrPut(f.title) { ArrayList() }.add(f) else out.add(f)
        for ((_, g) in groups) {
            if (g.size == 1) { out.add(g[0]); continue }
            val first = g.minByOrNull { it.severity.rank }!!
            val others = g.filter { it !== first }.map { it.file }.distinct()
            first.detail = first.detail + "  The same applies to " + others.size + " more layout(s): " + others.take(12).joinToString(", ") +
                (if (others.size > 12) ", ..." else "") + "."
            first.count = g.size
            out.add(first)
        }
        return out
    }

    @Volatile private var arscCandidates = 0
    @Volatile private var arscNamed = false

    /**
     * 0.66.4: path (res/xml/NAME.xml) of the network security config the manifest references, or null when it cannot be told
     * (no attribute, the decoder printed a numeric id instead of @xml/NAME, or that file is not in the zip: shrunk / renamed paths).
     * null = old behaviour (every NSC file is checked), so nothing is lost when the reference cannot be resolved.
     */
    private fun referencedNscPath(zip: ZipFile): String? {
        return try {
            val me = zip.getEntry("AndroidManifest.xml") ?: return null
            val xml = Axml.decode(zip.getInputStream(me).use { it.readBytes() }) ?: return null
            val name = Regex("networkSecurityConfig\\s*=\\s*\"@xml/([A-Za-z0-9_.]+)\"").find(xml)?.groupValues?.get(1) ?: return null
            val path = "res/xml/$name.xml"
            if (zip.getEntry(path) != null) path else null
        } catch (_: Throwable) { null }
    }

    /** Whole APK: one zip entry at a time, decode, run the rules, drop. Called from a background thread. */
    fun scanApk(apk: File): ResourceScanResult {
        val found = ArrayList<Finding>()
        var seen = 0; var bin = 0; var ok = 0; var fail = 0
        var nsc = 0; var edit = 0; var paths = 0; var vals = 0
        var firstErr = ""
        var arscInfo = "no resources.arsc"
        var assetInfo = ""
        arscCandidates = 0
        try {
            ZipFile(apk).use { zip ->
                val nscRef = referencedNscPath(zip)   // 0.66.4: the file the manifest really points to (null = could not resolve)
                // 0.75.0: one streaming pass over the dex files (tapjacking mitigations) + minSdk, for the layout cross-check
                var manText: String? = null
                val apkFacts = try {
                    val man = zip.getEntry("AndroidManifest.xml")?.let { me -> Axml.decode(zip.getInputStream(me).use { it.readBytes() }) }
                    manText = man
                    ApkFacts(ApkFacts.minSdkOf(man), ApkFacts.dexMentions(zip, ApkFacts.MITIGATION_NAMES))
                } catch (_: Throwable) { RuleRegistry.noteError("res-apk-facts"); ApkFacts.NONE }
                // 0.82.0 (JustMarkets: split APK, 6 dex, NO .so in the base APK): say plainly that native code was not analysed
                // 0.90.0: native libraries are READ (ELF headers, dynamic symbols, data strings); the old "not analysed" card stays only for an APK whose native code is in a split
                try {
                    val nat = NativeScanner.scan(zip, manText)
                    if (nat.isNotEmpty()) found.addAll(nat) else nativeCoverageFinding(zip, manText)?.let { found.add(it) }
                } catch (_: Throwable) { RuleRegistry.noteError("res-native") }
                for (e in zip.entries()) {
                    val name = e.name
                    if (name == "resources.arsc" && e.size < MAX_ARSC) {
                        val raw = zip.getInputStream(e).use { it.readBytes() }
                        arscInfo = "resources.arsc " + raw.size + " bytes"
                        try { found.addAll(scanArsc(raw)) } catch (_: Throwable) { RuleRegistry.noteError("res-arsc") }
                        continue
                    }
                    if (!name.startsWith("res/") || !name.endsWith(".xml")) continue
                    val isValues = PlainStrings.isValuesPath(name)
                    if (e.size > (if (isValues) MAX_VALUES_XML else MAX_XML)) continue
                    if (++seen > MAX_FILES) break
                    val bytes = zip.getInputStream(e).use { it.readBytes() }
                    val binary = bytes.size > 8 && bytes[0].toInt() == 0x03 && bytes[1].toInt() == 0x00
                    if (!binary) {
                        if (isValues) {          // plain values file: rare in a built APK, normal in an unpacked project
                            vals++
                            try { found.addAll(scanXml(name, String(bytes, Charsets.UTF_8))) } catch (_: Throwable) { RuleRegistry.noteError("res-values") }
                        }
                        continue
                    }
                    bin++
                    val xml = Axml.decode(bytes)
                    if (xml == null) {
                        fail++
                        if (firstErr.isEmpty()) firstErr = "Axml.decode returned null for " + name
                        continue
                    }
                    ok++
                    val hasNsc = xml.contains("<network-security-config")
                    val hasEdit = xml.contains("EditText")
                    val hasPaths = xml.contains("<paths")     // 0.43.0: FileProvider path files were skipped by the old filter
                    if (hasNsc) nsc++
                    if (hasEdit) edit++
                    if (hasPaths) paths++
                    if (!hasNsc && !hasEdit && !hasPaths) continue
                    if (hasNsc && nscRef != null && name != nscRef) {
                        // 0.66.4: Exness: manifest -> @xml/network_security_config_union, but res/xml/network_security_config.xml was
                        // scanned too and gave a HIGH "trusts user CAs". Android only applies the referenced file.
                        found.add(Finding(Severity.INFO, "Network Security Config file not referenced by the manifest",
                            "This file contains a <network-security-config> but the manifest points to " + nscRef + ", so Android does not apply this one (probably a library or leftover file). It was not checked.  [" + name + "]",
                            "Open " + nscRef + " (the file in use) and check that one.", null, -1, -1, "", name).also { it.ruleId = "res-nsc-unreferenced"; it.confidence = "HIGH" })
                        if (!hasEdit && !hasPaths) continue
                    }
                    try { found.addAll(scanXml(name, xml, apkFacts)) } catch (_: Throwable) { RuleRegistry.noteError("res-xml") }
                }
                // 0.103.0: the assets/ folder (JS bundles, web apps, configs): see AssetScanner
                try { val a = AssetScanner.scan(zip); found.addAll(a.findings); assetInfo = a.stats } catch (_: Throwable) { RuleRegistry.noteError("res-assets") }
            }
        } catch (t: Throwable) {
            firstErr = t.javaClass.simpleName + ": " + t.message
        }
        // 0.95.0 (a wallet app whose posture table said "no config file read" although its manifest declares one): when the manifest points to a network security config and no such
        // file was found / decoded, say so: its cleartext, user-CA and pinning rules were NOT evaluated (renamed resources, or a file the scanner could not read).
        try {
            val declared = java.util.zip.ZipFile(apk).use { zf -> zf.getEntry("AndroidManifest.xml")?.let { e -> Axml.decode(zf.getInputStream(e).use { it.readBytes() })?.contains("android:networkSecurityConfig") == true } == true }
            PostureScanner.nscDeclared = declared
            if (declared && nsc == 0) found.add(Finding(Severity.INFO, "Network Security Config declared but not found in the APK",
                "The manifest declares android:networkSecurityConfig, but no <network-security-config> file could be located or decoded in the package (resource names may be obfuscated, or the file was not readable). Its cleartext, user-CA and pinning settings were NOT evaluated: this is not a pass. (Resource scan: decoded $ok of $bin binary XML files, $fail failed.)",
                "Open the file the manifest points to in your project and check cleartextTrafficPermitted, trust-anchors (user CAs) and pin-set by hand.", null, -1, -1, "", "AndroidManifest.xml").also { it.ruleId = "res-nsc-not-found"; it.confidence = "HIGH" })
        } catch (_: Throwable) { }
        // the same secret can live in several values files (translations): report it once
        val keys = HashSet<String>()
        val uniq0 = found.filter { !it.ruleId.startsWith("res-strings") || keys.add(it.title + "|" + it.detail.substringBefore("  [")) }
        val uniq = groupLayoutFindings(uniq0)
        val errors = RuleRegistry.errorReport()
        val stats = "decoded $ok/$bin, failed $fail, NSC files $nsc, EditText layouts $edit, FileProvider path files $paths, values files $vals, $arscInfo" +
            (if (arscCandidates > 0) ", arsc strings checked $arscCandidates" + (if (arscNamed) " (with entry names)" else "") else "") +
            (if (assetInfo.isNotEmpty()) ", $assetInfo" else "") + ", resource rules " + RuleRegistry.resourceCount() +
            (if (firstErr.isNotEmpty()) "; first error: $firstErr" else "") +
            (if (errors.isNotEmpty()) "; rule errors: " + errors.replace("\n", ", ") else "")
        return ResourceScanResult(uniq, stats)
    }
}
