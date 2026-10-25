package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Scope

/**
 * 1.0.0: the `audit_brief` agent tool: one page about the last scan, built from the findings and the posture table only (no AI, no clock, no randomness: the same scan gives
 * the same page). It tells the agent and the user where to start and what the scan could not see; it judges nothing.
 *
 * [findings] must be in the order `get_findings` / `flow_path` number them (sorted, AI false positives left out), so "#N" here is the number those tools accept.
 */
object AuditBrief {
    const val MAX_FIRST = 10

    fun build(pkg: String, findings: List<Finding>, posture: List<PostureScanner.Row>, scanNote: String): String {
        if (findings.isEmpty()) return "No scan results yet for $pkg: run scan_security (mode smart or deep) first."
        val sb = StringBuilder("AUDIT BRIEF ").append(pkg).append('\n')
        if (scanNote.isNotEmpty()) sb.append("Last scan: ").append(scanNote).append('\n')
        val shown = findings.filter { it.severity != SecurityScanner.Severity.INFO }
        sb.append("Findings (LOW and above): ").append(shown.size)
        for (s in SecurityScanner.Severity.values()) {
            if (s == SecurityScanner.Severity.INFO) continue
            val n = shown.count { it.severity == s }
            if (n > 0) sb.append(", ").append(s.label).append(' ').append(n)
        }
        sb.append(".\nBy origin: app ").append(shown.count { it.scope == Scope.APP }).append(", renamed of unknown origin ").append(shown.count { it.scope == Scope.OBF })
            .append(", libraries ").append(shown.count { it.scope == Scope.LIB }).append(", other ").append(shown.count { it.scope == Scope.OTHER }).append(".\n")
        val code = findings.count { it.clsIndex >= 0 }
        if (code == 0) sb.append("Only the manifest / resources were scanned: run a deep scan for the code.\n")

        // what to verify first: not library code, MEDIUM or worse, reachable ones first
        fun reachRank(f: Finding) = when (f.reach) { "YES" -> 0; "YES~" -> 1; "" -> 2; else -> 3 }
        val first = findings.withIndex()
            .filter { (_, f) -> f.scope != Scope.LIB && f.severity.rank <= SecurityScanner.Severity.MEDIUM.rank }
            .sortedWith(compareBy({ reachRank(it.value) }, { it.value.severity.rank }, { it.index }))
            .take(MAX_FIRST)
        sb.append("\nVERIFY FIRST (flow_path #N, then get_class at the source and the sink):\n")
        if (first.isEmpty()) sb.append("  none at MEDIUM or above outside libraries.\n")
        for ((i, f) in first) {
            sb.append("  #").append(i + 1).append(" [").append(f.severity.label).append(if (f.scope == Scope.OTHER) "" else "/" + f.scope.tag)
                .append(if (f.reach.isEmpty()) "" else ", reach " + f.reach).append(if (f.verdict.isEmpty()) "" else ", AI " + f.verdict).append("] ")
                .append(f.title).append(" - ").append(f.location).append('\n')
        }
        val merged = findings.withIndex().filter { (_, f) -> f.detail.contains("R8 may have merged") || f.detail.contains("R8 merged several original classes") || f.detail.contains("from a class R8 merged") }
        if (merged.isNotEmpty()) {
            sb.append("\nTHROUGH R8-MERGED CODE (a lead until the smali shows writer and reader are the same original class; classify_class tells):\n")
            for ((i, f) in merged.take(MAX_FIRST)) sb.append("  #").append(i + 1).append(' ').append(f.title).append(" - ").append(f.location).append('\n')
        }

        // posture: controls present only in libraries, and the MASVS controls seen only through presence signals
        val libOnly = posture.filter { it.app.isEmpty() && it.obf.isEmpty() && it.lib.isNotEmpty() }.map { it.sig.control.substringBefore(':') }.distinct()
        if (libOnly.isNotEmpty()) sb.append("\nPosture only inside libraries (not the app's own protection): ").append(libOnly.joinToString("; ")).append(".\n")
        val cov = Masvs.coverage(findings)
        val signalsOnly = cov.filter { it.signalsOnly }.map { it.control.removePrefix("MASVS-") }
        sb.append("\nNOT SEEN BY STATIC ANALYSIS: ")
        sb.append("server-side checks, the app's behaviour at run time, logic flaws")
        if (signalsOnly.isNotEmpty()) sb.append("; MASVS ").append(signalsOnly.joinToString(", ")).append(" are only known by what the code uses (posture table), not by whether it is used correctly")
        sb.append(". \"No finding\" is never a pass.\n")
        return sb.toString()
    }
}
