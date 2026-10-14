package dev.apkrelab

/**
 * 0.40.0: turns findings into educational output.
 * Every finding card follows one order: name -> severity -> where -> why flagged -> risk scenario -> fix -> references.
 * The vulnerable / secure code samples are printed once per weakness (CWE) in the "Remediation guide" so the report stays short.
 * Output formats: Markdown ([securitySection]), HTML ([html]) and a short block for the finding dialog ([dialogExtra]).
 * Pure functions over the Finding list: no Android classes, so they cannot fail on a device-specific API.
 */
object ReportBuilder {

    private val sevOrder = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    /** Findings that belong in a report: app / unknown code, rank <= LOW (the same rule the old report used). */
    fun reportable(all: List<SecurityScanner.Finding>): List<SecurityScanner.Finding> =
        all.filter { it.scope != SecurityScanner.Scope.LIB && it.severity.rank <= 3 }

    private fun countBySeverity(list: List<SecurityScanner.Finding>): Map<String, Int> {
        val m = LinkedHashMap<String, Int>()
        for (s in sevOrder) m[s] = 0
        for (f in list) m[f.severity.label] = (m[f.severity.label] ?: 0) + 1
        return m
    }

    private fun countByOwasp(list: List<SecurityScanner.Finding>): List<Pair<String, Int>> {
        val m = LinkedHashMap<String, Int>()
        for (f in list) {
            val e = VulnKnowledge.forFinding(f)
            val key = e?.owasp ?: "Not mapped"
            m[key] = (m[key] ?: 0) + 1
        }
        return m.entries.sortedByDescending { it.value }.map { it.key to it.value }
    }

    private fun meta(f: SecurityScanner.Finding): String {
        val e = VulnKnowledge.forFinding(f)
        val parts = ArrayList<String>()
        if (f.cwe.isNotEmpty()) parts.add("CWE: " + f.cwe)
        if (e != null) { parts.add("OWASP: " + e.owasp); parts.add("MASVS: " + e.masvs) }
        parts.add("Confidence: " + FindingPolish.confidenceOf(f))
        if (f.ruleId.isNotEmpty()) parts.add("Rule: " + f.ruleId)
        if (f.scope != SecurityScanner.Scope.OTHER) parts.add("Scope: " + f.scope.tag)
        if (f.reach == "YES") parts.add("Reachable from an exported component")
        else if (f.reach == "YES~") parts.add("Probably reachable from an exported component (approximate class-level path)")
        return parts.joinToString(" | ")
    }

    private fun verdictText(f: SecurityScanner.Finding): String = when (f.verdict) {
        "TP" -> "TRUE POSITIVE"
        "FP" -> "FALSE POSITIVE"
        "REVIEW" -> "NEEDS REVIEW"
        else -> ""
    }

    // ---------- 0.46.0: attack surface summary ----------

    private val compRe = Regex("<(activity-alias|activity|service|receiver|provider)(?![\\w-])([^>]*?)(?:/>|>([\\s\\S]*?)</\\1>)")
    private val nameAttrRe = Regex("android:name\\s*=\\s*\"([^\"]+)\"")
    private val actionRe = Regex("<action\\s+android:name\\s*=\\s*\"([^\"]+)\"")
    private val permRe = Regex("<uses-permission[^>]*android:name\\s*=\\s*\"([^\"]+)\"")

    private class Surface(val kind: String, val name: String, val exported: Boolean, val actions: List<String>) {
        var n: Int = 1   // 0.49.1: identical entries (e.g. 19 launcher-icon activity-aliases of one activity) are merged and counted
        val label: String get() = if (n > 1) "$name (x$n)" else name
    }

    /** Exported components (with their intent-filter actions) and the requested permissions, straight from the manifest. */
    private fun surface(xml: String, pkg: String): Pair<List<Surface>, List<String>> {
        val comps = ArrayList<Surface>()
        for (m in compRe.findAll(xml)) {
            val tag = m.groupValues[1]
            val header = m.groupValues[2]
            val body = m.groupValues[3]
            var name = nameAttrRe.find(header)?.groupValues?.get(1) ?: continue
            if (tag == "activity-alias") name = Regex("android:targetActivity\\s*=\\s*\"([^\"]+)\"").find(header)?.groupValues?.get(1) ?: continue
            val full = when {
                name.startsWith(".") -> pkg + name
                name.contains('.') -> name
                else -> "$pkg.$name"
            }
            val expM = Regex("android:exported\\s*=\\s*\"(true|false)\"").find(header)
            val exported = if (expM != null) expM.groupValues[1] == "true" else body.contains("<intent-filter")
            if (!exported) continue
            val s = Surface(tag, full, true, actionRe.findAll(body).map { it.groupValues[1].substringAfterLast('.') }.distinct().take(6).toList())
            val same = comps.firstOrNull { it.kind == s.kind && it.name == s.name && it.actions == s.actions }
            if (same != null) same.n++ else comps.add(s)
        }
        val perms = permRe.findAll(xml).map { it.groupValues[1].removePrefix("android.permission.") }.distinct().sorted().toList()
        return comps to perms
    }

    /** Markdown table for the report: every exported component + its actions, and the full permission list. */
    fun attackSurface(xml: String, pkg: String): String {
        if (xml.isBlank()) return ""
        val (comps, perms) = surface(xml, pkg)
        val sb = StringBuilder()
        sb.append("## Attack surface\n\n")
        sb.append("Exported components (reachable by other apps): **").append(comps.sumOf { it.n }).append("** - requested permissions: **").append(perms.size).append("**\n\n")
        if (comps.isNotEmpty()) {
            sb.append("| Component | Kind | Intent-filter actions |\n|---|---|---|\n")
            for (c in comps) sb.append("| `").append(c.label).append("` | ").append(c.kind).append(" | ")
                .append(if (c.actions.isEmpty()) "-" else c.actions.joinToString(", ")).append(" |\n")
            sb.append("\n")
        }
        if (perms.isNotEmpty()) sb.append("**Permissions:** ").append(perms.joinToString(", ")).append("\n")
        sb.append("\n")
        return sb.toString()
    }

    /** Same summary as HTML (used by the .html report export). */
    fun attackSurfaceHtml(xml: String, pkg: String): String {
        if (xml.isBlank()) return ""
        val (comps, perms) = surface(xml, pkg)
        val sb = StringBuilder()
        sb.append("<h2>Attack surface</h2><p>").append(comps.sumOf { it.n }).append(" exported component(s), ")
            .append(perms.size).append(" requested permission(s).</p>")
        if (comps.isNotEmpty()) {
            sb.append("<table><tr><th>Component</th><th>Kind</th><th>Intent-filter actions</th></tr>")
            for (c in comps) sb.append("<tr><td>").append(esc(c.label)).append("</td><td>").append(c.kind).append("</td><td>")
                .append(esc(if (c.actions.isEmpty()) "-" else c.actions.joinToString(", "))).append("</td></tr>")
            sb.append("</table>")
        }
        if (perms.isNotEmpty()) sb.append("<p class=\"mut\"><b>Permissions:</b> ").append(esc(perms.joinToString(", "))).append("</p>")
        return sb.toString()
    }

    // ---------- 0.47.0: third-party libraries & SCA ----------

    /** One row of the SCA table: library, version, source, and its matching vulnerabilities (empty = clean/unknown). */
    private class ScaRow(val lib: DetectedLib, val vulns: List<LibVuln>) {
        val worst: SecurityScanner.Severity get() = vulns.minByOrNull { it.severity.rank }?.severity ?: SecurityScanner.Severity.INFO
    }

    private fun scaRows(libs: List<DetectedLib>): List<ScaRow> {
        val rows = ArrayList<ScaRow>(libs.size)
        for (l in libs) {
            val ms = try { if (l.version == "?") emptyList() else LibraryScanner.matches(l) } catch (_: Throwable) { emptyList() }
            rows.add(ScaRow(l, ms))
        }
        // vulnerable first (worst severity first), then the rest alphabetically
        return rows.sortedWith(compareBy({ if (it.vulns.isEmpty()) 1 else 0 }, { it.worst.rank }, { if (ScaScanner.isLowSignal(it.lib)) 1 else 0 }, { it.lib.label }))
    }

    /**
     * "Third-Party Libraries & SCA" for the Markdown report. Lists EVERY detected library (transparency),
     * highlights the vulnerable / outdated ones with their CVE and the fixed version to upgrade to.
     * Empty string when no library was detected at all.
     */
    fun scaSection(libs: List<DetectedLib>): String {
        if (libs.isEmpty()) return ""
        val rows = scaRows(libs)
        val vulnCount = rows.count { it.vulns.isNotEmpty() }
        val sb = StringBuilder()
        sb.append("## Third-Party Libraries & SCA\n\n")
        sb.append(libs.size).append(" component(s) detected in the APK (META-INF version files, pom.properties, native .so strings, dex strings, package-path heuristics). ")
        val unknown = rows.count { it.lib.version == "?" }
        sb.append("**").append(vulnCount).append(" vulnerable / outdated")
        if (unknown > 0) sb.append(", ").append(unknown).append(" with unknown version (NOT checked against CVEs)")
        sb.append(".** ")
        sb.append("Libraries detected only by package path have version `?`: presence is proven, the version is not - they cannot be matched against version-specific CVEs, so this is a lower bound, not proof that nothing else is bundled.\n\n")
        sb.append("| Component | Version | Status | Known vulnerabilities | Fix | Source |\n|---|---|---|---|---|---|\n")
        for (r in rows.take(300)) {
            if (r.vulns.isEmpty()) {
                val w = try { LibraryScanner.watchFor(r.lib) } catch (_: Throwable) { emptyList() }
                if (w.isEmpty()) sb.append("| ").append(r.lib.label).append(" | ").append(r.lib.version).append(" | ").append(if (r.lib.version == "?") "UNKNOWN VERSION" else "OK").append(" | - | - | ").append(r.lib.source).append(" |\n")
                else sb.append("| ").append(r.lib.label).append(" | ? | UNKNOWN VERSION (CVEs exist for older releases) | ").append(w.map { it.id }.distinct().joinToString("<br>")).append(" | check version, fixed in ").append(w.map { it.fixed }.distinct().joinToString(" / ")).append(" | ").append(r.lib.source).append(" |\n")
            } else {
                val ids = r.vulns.map { it.id }.distinct().joinToString("<br>")
                val fixed = r.vulns.map { it.fixed }.distinct().joinToString(" / ")
                sb.append("| **").append(r.lib.label).append("** | ").append(r.lib.version).append(" | **")
                    .append(r.worst.label).append("** | ").append(ids).append(" | ").append(fixed).append(" | ").append(r.lib.source).append(" |\n")
            }
        }
        if (rows.size > 300) sb.append("\n(").append(rows.size - 300).append(" more rows omitted.)\n")
        val bom = try { LibraryScanner.cycloneDx() } catch (_: Throwable) { "" }
        if (bom.isNotEmpty()) sb.append("\nCycloneDX 1.5 (JSON):\n\n```json\n").append(bom).append("\n```\n")
        sb.append('\n')
        return sb.toString()
    }

    /** Same section as HTML for the .html report export (vulnerable rows get a red status badge). */
    fun scaSectionHtml(libs: List<DetectedLib>): String {
        if (libs.isEmpty()) return ""
        val rows = scaRows(libs)
        val vulnCount = rows.count { it.vulns.isNotEmpty() }
        val sb = StringBuilder()
        sb.append("<h2>Third-Party Libraries &amp; SCA</h2><p>").append(libs.size)
            .append(" component(s) detected, <b>").append(vulnCount).append(" vulnerable / outdated</b>")
            .append(rows.count { it.lib.version == "?" }.let { if (it > 0) ", $it with unknown version (not checked against CVEs)" else "" }).append(". ")
            .append("Version <code>?</code> = found by package path only (presence proven, version unknown; cannot be matched to version-specific CVEs). This list is a lower bound.</p>")
        sb.append("<table><tr><th>Component</th><th>Version</th><th>Status</th><th>Known vulnerabilities</th><th>Fix</th><th>Source</th></tr>")
        for (r in rows.take(300)) {
            if (r.vulns.isEmpty()) {
                sb.append("<tr><td>").append(esc(r.lib.label)).append("</td><td>").append(esc(r.lib.version))
                    .append("</td><td>").append(if (r.lib.version == "?") "UNKNOWN VERSION" else "OK").append("</td><td>-</td><td>-</td><td>").append(esc(r.lib.source)).append("</td></tr>")
            } else {
                val sums = r.vulns.joinToString("<br>") { esc(it.id + ": " + it.summary) }
                val fixed = r.vulns.map { it.fixed }.distinct().joinToString(" / ")
                sb.append("<tr><td><b>").append(esc(r.lib.label)).append("</b></td><td>").append(esc(r.lib.version))
                    .append("</td><td><span class=\"badge\" style=\"background:").append(sevColor(r.worst.label)).append("\">")
                    .append(r.worst.label).append("</span></td><td>").append(sums).append("</td><td>").append(esc(fixed))
                    .append("</td><td>").append(esc(r.lib.source)).append("</td></tr>")
            }
        }
        sb.append("</table>")
        return sb.toString()
    }

    // ---------- Markdown ----------

    fun securitySection(all: List<SecurityScanner.Finding>, maxItems: Int = 400): String {
        val sb = StringBuilder()
        val list = reportable(all).take(maxItems)
        sb.append("Heuristic static scan - ").append(all.size).append(" finding(s) in total; ").append(list.size)
            .append(" listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.\n\n")
        // 0.82.0: what a static scan of the APK cannot see, said once at the top
        sb.append("Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.\n\n")
        if (list.isEmpty()) return sb.toString()

        sb.append("### Summary\n\n| Severity | Count |\n|---|---|\n")
        for ((k, v) in countBySeverity(list)) if (v > 0) sb.append("| ").append(k).append(" | ").append(v).append(" |\n")
        sb.append("\n**OWASP Mobile Top 10 (2024) coverage**\n\n")
        for ((k, v) in countByOwasp(list)) sb.append("- ").append(k).append(": ").append(v).append("\n")
        sb.append("\n### Findings\n\n")

        var n = 0
        for (f in list) {
            n++
            val e = VulnKnowledge.forFinding(f)
            sb.append("#### ").append(n).append(". [").append(f.severity.label).append("] ").append(f.title)
            if (f.count > 1) sb.append(" (x").append(f.count).append(")")
            sb.append("\n\n")
            sb.append("- Location: `").append(f.location).append("`\n")
            sb.append("- ").append(meta(f)).append("\n")
            sb.append("- Priority: ").append(FindingScore.of(f).short).append("\n")      // 0.69.3
            if (f.adjusted.isNotEmpty()) sb.append("- Note: ").append(f.adjusted).append("\n")
            // 0.51.1: the call-graph path itself, so an approximate (YES~) result can be checked by hand
            if (f.reach.startsWith("YES") && f.chain.isNotEmpty()) sb.append("- Call path: ").append(f.chain.replace("\n", " | ")).append("\n")
            if (f.verdict.isNotEmpty()) {
                sb.append("- AI triage: ").append(verdictText(f)).append(" - ").append(f.verdictNote.replace("\n", " ")).append("\n")
            }
            sb.append("- Why flagged: ").append(f.detail).append("\n")
            if (e != null) sb.append("- Risk scenario: ").append(e.scenario).append("\n")
            sb.append("- Fix: ").append(f.recommendation).append("\n\n")
        }

        // remediation guide: one block per weakness that appears in the list
        val seen = LinkedHashSet<String>()
        for (f in list) if (f.cwe.isNotEmpty()) seen.add(f.cwe.uppercase())
        if (seen.isNotEmpty()) {
            sb.append("### Remediation guide\n\nOne entry per weakness type found above.\n\n")
            for (cwe in seen) {
                val e = VulnKnowledge.forCwe(cwe)
                sb.append("#### ").append(cwe)
                if (e != null) sb.append(" - ").append(e.name)
                sb.append("\n\n")
                if (e != null) {
                    sb.append("OWASP: ").append(e.owasp).append(" | MASVS: ").append(e.masvs).append("\n\n")
                    sb.append("Risk: ").append(e.scenario).append("\n\n")
                    if (e.bad.isNotEmpty()) sb.append("Vulnerable:\n\n```kotlin\n").append(e.bad).append("\n```\n\n")
                    if (e.good.isNotEmpty()) sb.append("Secure:\n\n```kotlin\n").append(e.good).append("\n```\n\n")
                }
                sb.append("References: ")
                sb.append(VulnKnowledge.references(cwe).joinToString(" | ") { "[" + it.first + "](" + it.second + ")" })
                sb.append("\n\n")
            }
        }
        return sb.toString()
    }

    /** Extra text for the finding dialog (rendered by the app's markdown renderer: plain ``` fences, no language tag). */
    fun dialogExtra(f: SecurityScanner.Finding): String {
        val e = VulnKnowledge.forFinding(f)
        val sb = StringBuilder()
        sb.append("\n\n**Confidence:** ").append(FindingPolish.confidenceOf(f))
        if (f.adjusted.isNotEmpty()) sb.append("  (").append(f.adjusted).append(")")
        FindingScore.of(f).let { sb.append("\n**Priority:** ").append(it.short).append("  (").append(it.why).append(")") }      // 0.69.3
        if (e == null) return sb.toString()
        sb.append("\n**OWASP:** ").append(e.owasp).append("\n**MASVS:** ").append(e.masvs)
        sb.append("\n\n**Risk scenario:** ").append(e.scenario)
        if (e.bad.isNotEmpty()) sb.append("\n\n**Vulnerable:**\n```\n").append(e.bad).append("\n```")
        if (e.good.isNotEmpty()) sb.append("\n\n**Secure:**\n```\n").append(e.good).append("\n```")
        val refs = VulnKnowledge.references(f.cwe).take(3)
        if (refs.isNotEmpty()) sb.append("\n\n**References:**\n").append(refs.joinToString("\n") { it.first + ": " + it.second })
        return sb.toString()
    }

    // ---------- HTML ----------

    private fun esc(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun sevColor(label: String): String = when (label) {
        "CRITICAL" -> "#b00020"
        "HIGH" -> "#d9480f"
        "MEDIUM" -> "#c98a00"
        "LOW" -> "#2b7bb9"
        else -> "#6b7280"
    }

    fun html(pkg: String, appInfo: String, all: List<SecurityScanner.Finding>, notes: List<Pair<String, String>>, maxItems: Int = 400, manifestXml: String = "", scaLibs: List<DetectedLib> = emptyList()): String {
        val list = reportable(all).take(maxItems)
        val sb = StringBuilder()
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
        sb.append("<title>APK ReLab report: ").append(esc(pkg)).append("</title><style>")
        sb.append(":root{--bg:#ffffff;--fg:#1c1b2e;--card:#f4f3fb;--mut:#5b5a70;--line:#dcdaf0}")
        sb.append("@media (prefers-color-scheme:dark){:root{--bg:#0e0c24;--fg:#ececf6;--card:#1a1838;--mut:#a3a1bd;--line:#2c2a52}}")
        sb.append("body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:900px;margin-inline:auto}")
        sb.append("h1{font-size:22px}h2{font-size:18px;margin-top:28px}h3{font-size:16px;margin:0}")
        sb.append(".card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 14px;margin:10px 0}")
        sb.append(".badge{display:inline-block;color:#fff;border-radius:999px;padding:1px 10px;font-size:12px;font-weight:700;margin-right:6px}")
        sb.append(".mut{color:var(--mut);font-size:13px}pre{background:rgba(127,127,127,.14);padding:10px;border-radius:10px;overflow-x:auto;font-size:12.5px}")
        sb.append("table{border-collapse:collapse}td,th{border:1px solid var(--line);padding:4px 12px;text-align:left}a{color:#6d5bd0}")
        sb.append("</style></head><body>")
        sb.append("<h1>APK ReLab report: ").append(esc(pkg)).append("</h1>")
        sb.append("<p class=\"mut\">Educational static analysis. Use only on apps you own or are allowed to analyze. Findings are heuristic leads: verify manually.</p>")
        if (appInfo.isNotBlank()) sb.append("<h2>App info</h2><pre>").append(esc(appInfo.take(4000))).append("</pre>")
        if (manifestXml.isNotBlank()) sb.append(attackSurfaceHtml(manifestXml, pkg))
        if (scaLibs.isNotEmpty()) sb.append(scaSectionHtml(scaLibs))   // 0.47.0: third-party libraries & SCA

        sb.append("<h2>Security scan</h2>")
        if (all.isEmpty()) {
            sb.append("<p>Not run yet.</p>")
        } else {
            sb.append("<p>").append(all.size).append(" finding(s) in total; ").append(list.size).append(" listed (app/unknown code, INFO and library findings left out).</p>")
            sb.append("<table><tr><th>Severity</th><th>Count</th></tr>")
            for ((k, v) in countBySeverity(list)) if (v > 0) sb.append("<tr><td>").append(k).append("</td><td>").append(v).append("</td></tr>")
            sb.append("</table><h3 style=\"margin-top:14px\">OWASP Mobile Top 10 (2024)</h3><ul>")
            for ((k, v) in countByOwasp(list)) sb.append("<li>").append(esc(k)).append(": ").append(v).append("</li>")
            sb.append("</ul>")
            var n = 0
            for (f in list) {
                n++
                val e = VulnKnowledge.forFinding(f)
                sb.append("<div class=\"card\"><h3><span class=\"badge\" style=\"background:").append(sevColor(f.severity.label)).append("\">")
                    .append(f.severity.label).append("</span>").append(n).append(". ").append(esc(f.title))
                if (f.count > 1) sb.append(" (x").append(f.count).append(")")
                sb.append("</h3><p class=\"mut\">").append(esc(f.location)).append("<br>").append(esc(meta(f))).append("<br>Priority: ").append(FindingScore.of(f).short).append("</p>")
                if (f.adjusted.isNotEmpty()) sb.append("<p class=\"mut\">").append(esc(f.adjusted)).append("</p>")
                if (f.verdict.isNotEmpty()) sb.append("<p><b>AI triage: ").append(verdictText(f)).append("</b> - ").append(esc(f.verdictNote.replace("\n", " "))).append("</p>")
                sb.append("<p><b>Why flagged:</b> ").append(esc(f.detail)).append("</p>")
                if (e != null) sb.append("<p><b>Risk scenario:</b> ").append(esc(e.scenario)).append("</p>")
                sb.append("<p><b>Fix:</b> ").append(esc(f.recommendation)).append("</p></div>")
            }
            val seen = LinkedHashSet<String>()
            for (f in list) if (f.cwe.isNotEmpty()) seen.add(f.cwe.uppercase())
            if (seen.isNotEmpty()) {
                sb.append("<h2>Remediation guide</h2>")
                for (cwe in seen) {
                    val e = VulnKnowledge.forCwe(cwe)
                    sb.append("<div class=\"card\"><h3>").append(esc(cwe)).append(if (e != null) " - " + esc(e.name) else "").append("</h3>")
                    if (e != null) {
                        sb.append("<p class=\"mut\">").append(esc(e.owasp)).append(" | ").append(esc(e.masvs)).append("</p>")
                        sb.append("<p>").append(esc(e.scenario)).append("</p>")
                        if (e.bad.isNotEmpty()) sb.append("<b>Vulnerable</b><pre>").append(esc(e.bad)).append("</pre>")
                        if (e.good.isNotEmpty()) sb.append("<b>Secure</b><pre>").append(esc(e.good)).append("</pre>")
                    }
                    sb.append("<p class=\"mut\">")
                    sb.append(VulnKnowledge.references(cwe).joinToString(" | ") { "<a href=\"" + esc(it.second) + "\">" + esc(it.first) + "</a>" })
                    sb.append("</p></div>")
                }
            }
        }
        if (notes.isNotEmpty()) {
            sb.append("<h2>AI notes (this session)</h2>")
            for ((t, body) in notes) sb.append("<div class=\"card\"><h3>").append(esc(t)).append("</h3><pre style=\"white-space:pre-wrap\">").append(esc(body)).append("</pre></div>")
        }
        sb.append("</body></html>")
        return sb.toString()
    }
}
