package dev.apkrelab

/**
 * 1.1.0: the app's deep-link entry points, one row per <intent-filter> (not per activity): the links it accepts, the activity that receives them and its launch mode,
 * whether a web link is a verified App Link (android:autoVerify="true" on THAT filter), and which link / Intent parameters the receiving activity reads.
 *
 * Why per filter: Android verifies App Links filter by filter. An activity with two verified https filters and a third one without autoVerify (Axis Pay 3.0.1: axis.airbridge.io and
 * axis.abr.ge verified, axisapp.dre.agconnect.link not) accepts the third host as an ordinary link: any installed app that declares the same host can be offered for it. The 0.x rule
 * looked for "autoVerify" anywhere in the activity and called all three verified.
 *
 * Pure functions on the manifest XML (as decoded by Axml) and on smali class text.
 */
object DeepLinks {

    class Link(
        val activity: String, val launchMode: String, val schemes: List<String>, val hosts: List<String>, val paths: List<String>,
        val browsable: Boolean, val autoVerify: Boolean
    ) {
        val web: Boolean get() = schemes.any { it == "http" || it == "https" }
        /** A browsable http(s) filter that Android does not verify: another app can declare the same host and be offered for it. */
        val unverifiedWeb: Boolean get() = browsable && web && !autoVerify
        /** scheme://host/path for every combination the filter accepts (Android combines the <data> attributes of one filter). */
        val uris: List<String> get() {
            val s = schemes.ifEmpty { listOf("") }; val h = hosts.ifEmpty { listOf("") }; val p = paths.ifEmpty { listOf("") }
            val out = ArrayList<String>()
            for (a in s) for (b in h) for (c in p) out.add((if (a.isEmpty()) "" else "$a://") + b + c)
            return out.distinct()
        }
    }

    private val compRe = Regex("<(activity|activity-alias)\\b([^>]*?)(/>|>(.*?)</\\1>)", RegexOption.DOT_MATCHES_ALL)
    private val filterRe = Regex("<intent-filter\\b([^>]*)>(.*?)</intent-filter>", RegexOption.DOT_MATCHES_ALL)
    private val dataRe = Regex("<data\\b([^>]*)/?>")
    private fun attr(s: String, n: String) = Regex("android:$n\\s*=\\s*\"([^\"]*)\"").find(s)?.groupValues?.get(1)

    /** android:launchMode as text; the binary manifest gives the enum's number. */
    fun launchMode(v: String?): String = when (v) {
        null, "", "0", "standard" -> "standard"
        "1", "singleTop" -> "singleTop"
        "2", "singleTask" -> "singleTask"
        "3", "singleInstance" -> "singleInstance"
        "4", "singleInstancePerTask" -> "singleInstancePerTask"
        else -> v
    }

    /** Every filter that a link can open: BROWSABLE, or a custom (non-web) scheme. [pkg] completes relative class names. */
    fun parse(xml: String, pkg: String): List<Link> {
        val out = ArrayList<Link>()
        for (m in compRe.findAll(xml)) {
            val tag = m.groupValues[1]; val header = m.groupValues[2]; val body = m.groupValues[4]
            if (body.isEmpty()) continue
            var name = (if (tag == "activity-alias") attr(header, "targetActivity") else attr(header, "name")) ?: continue
            name = when { name.startsWith(".") -> pkg + name; name.contains('.') -> name; else -> "$pkg.$name" }
            val mode = launchMode(attr(header, "launchMode"))
            for (f in filterRe.findAll(body)) {
                val fb = f.groupValues[2]
                val datas = dataRe.findAll(fb).map { it.groupValues[1] }.toList()
                if (datas.isEmpty()) continue
                val schemes = datas.mapNotNull { attr(it, "scheme") }.distinct()
                val browsable = fb.contains("android.intent.category.BROWSABLE")
                val custom = schemes.any { it.isNotEmpty() && it != "http" && it != "https" }
                if (!browsable && !custom) continue
                val hosts = datas.mapNotNull { attr(it, "host") }.distinct()
                val paths = datas.flatMap { d -> listOfNotNull(attr(d, "path"), attr(d, "pathPrefix")?.let { "$it*" }, attr(d, "pathPattern"), attr(d, "pathAdvancedPattern")) }.distinct()
                val verify = attr(f.groupValues[1], "autoVerify").let { it == "true" || it == "1" || it == "-1" }
                out.add(Link(name, mode, schemes, hosts, paths, browsable, verify))
            }
        }
        return out
    }

    /** Hosts of the browsable http(s) filters in one component body that carry no android:autoVerify (each filter judged on its own); empty when every web filter is verified. */
    fun unverifiedWebHosts(body: String): List<String> {
        val out = ArrayList<String>()
        for (f in filterRe.findAll(body)) {
            val fb = f.groupValues[2]
            if (!fb.contains("android.intent.category.BROWSABLE")) continue
            val datas = dataRe.findAll(fb).map { it.groupValues[1] }.toList()
            if (datas.none { attr(it, "scheme").let { s -> s == "http" || s == "https" } }) continue
            val verify = attr(f.groupValues[1], "autoVerify").let { it == "true" || it == "1" || it == "-1" }
            if (!verify) out.addAll(datas.mapNotNull { attr(it, "host") }.ifEmpty { listOf("(any host)") })
        }
        return out.distinct()
    }

    private val paramApis = listOf(
        "Landroid/net/Uri;->getQueryParameter(" to "query", "Landroid/net/Uri;->getQueryParameters(" to "query", "Landroid/net/Uri;->getBooleanQueryParameter(" to "query",
        "Landroid/content/Intent;->get" to "extra", "Landroid/os/Bundle;->get" to "extra", "Landroid/os/BaseBundle;->get" to "extra")
    private val constRe = Regex("^\\s*const-string(?:/jumbo)?\\s+([vp]\\d+),\\s*\"([^\"]*)\"")

    /**
     * The constant names of link query parameters and Intent extras that a class reads: `const-string vK, "name"` as the key argument (the first one after the receiver) of
     * Uri.getQueryParameter / Intent.get*Extra / Bundle.get*, with no other write of vK in between (searched back to the method start or a label). A computed key is not listed.
     */
    fun paramsRead(text: String): Map<String, Set<String>> {
        val out = HashMap<String, MutableSet<String>>()
        val lines = text.lines()
        for ((i, l) in lines.withIndex()) {
            val t = l.trim()
            if (!t.startsWith("invoke-")) continue
            val kind = paramApis.firstOrNull { t.contains(it.first) }?.second ?: continue
            if (kind == "extra" && !(t.contains("Extra(") || t.contains("Landroid/os/Bundle;->get") || t.contains("Landroid/os/BaseBundle;->get"))) continue
            val regs = Regex("\\{([^}]*)\\}").find(t)?.groupValues?.get(1)?.split(',')?.map { it.trim() } ?: continue
            val key = regs.getOrNull(1) ?: continue
            for (b in i - 1 downTo maxOf(0, i - 40)) {
                val p = lines[b].trim()
                if (p.startsWith(".method") || p.startsWith(":")) break
                val c = constRe.find(p)
                if (c != null && c.groupValues[1] == key) { out.getOrPut(kind) { HashSet() }.add(c.groupValues[2]); break }
                if (Regex("^[a-z][a-z0-9/-]*\\s+" + Regex.escape(key) + "\\s*(,|$)").containsMatchIn(p)) break
            }
        }
        return out
    }

    /** Markdown section for the report; [params] = activity class name -> what it reads ("" when nothing could be read). */
    fun section(links: List<Link>, params: (String) -> Map<String, Set<String>>): String {
        if (links.isEmpty()) return ""
        val sb = StringBuilder("## Deep links\n\n")
        val unverified = links.filter { it.unverifiedWeb }
        sb.append(links.size).append(" link filter(s) in ").append(links.map { it.activity }.distinct().size).append(" activit(y/ies); ")
            .append(unverified.size).append(" web filter(s) without android:autoVerify.\n\n")
        sb.append("| Links accepted | Activity | Launch mode | Verified App Link | Parameters the activity reads |\n|---|---|---|---|---|\n")
        val cache = HashMap<String, Map<String, Set<String>>>()
        for (l in links) {
            val p = cache.getOrPut(l.activity) { try { params(l.activity) } catch (_: Throwable) { emptyMap() } }
            val ps = listOfNotNull(p["query"]?.sorted()?.takeIf { it.isNotEmpty() }?.let { "query: " + it.take(12).joinToString(", ") },
                p["extra"]?.sorted()?.takeIf { it.isNotEmpty() }?.let { "extras: " + it.take(12).joinToString(", ") }).joinToString("; ").ifEmpty { "none read as constants in this class" }
            sb.append("| ").append(l.uris.take(6).joinToString(", ") { "`$it`" }).append(if (l.uris.size > 6) " (+" + (l.uris.size - 6) + ")" else "").append(" | `").append(l.activity).append("` | ")
                .append(l.launchMode).append(" | ").append(if (!l.web) "n/a (custom scheme: any app can declare it)" else if (l.autoVerify) "yes" else "**NO**: not verified, another app can be offered for this host")
                .append(" | ").append(ps).append(" |\n")
        }
        sb.append("\nParameters are the constant names read in the receiving activity's own class (and its inner classes); a link handled in a framework layer (Flutter / React Native routes, a WebView) is read there and is not listed. ")
            .append("Every value in a link is chosen by whoever sends it.\n\n")
        return sb.toString()
    }

    /** Short lines for the agent's audit_brief. */
    fun brief(links: List<Link>): String {
        if (links.isEmpty()) return ""
        val sb = StringBuilder("\nDEEP LINKS (").append(links.size).append(" filters):\n")
        for (l in links.filter { it.unverifiedWeb }) sb.append("  UNVERIFIED web link ").append(l.uris.take(3).joinToString(", ")).append(" -> ").append(l.activity).append(" (no android:autoVerify on this filter)\n")
        val custom = links.filter { !it.web }.flatMap { it.uris }.distinct()
        if (custom.isNotEmpty()) sb.append("  custom-scheme links (any app can declare the scheme): ").append(custom.take(12).joinToString(", ")).append(if (custom.size > 12) " ..." else "").append('\n')
        val verified = links.count { it.web && it.autoVerify }
        if (verified > 0) sb.append("  verified App Link filters: ").append(verified).append('\n')
        return sb.toString()
    }
}
