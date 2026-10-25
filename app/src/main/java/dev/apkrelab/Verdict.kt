package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 1.2.0: the five lines at the top of every report (MD, HTML, SARIF run properties): what was found, what matters, what to fix first, how sure the scan is, and what it
 * could not see. Deterministic, no AI, built only from the cards, the attack scenarios and the coverage values the scan already produces. It changes no card.
 *
 * Card numbers are positions in the report's own list ([ReportBuilder.reportable] order), the numbers the report and the AI Hub use.
 */
object Verdict {

    /** What the scan covered, read from values the app already holds (status line, native scan, strings overlay, split import). */
    class Coverage(
        val deepScan: Boolean, val classesScanned: Int,
        val groups: Int = 0, val groupsCapped: Int = 0, val timeUp: Boolean = false,
        val nativeMethods: Int = 0, val nativeLibs: Int = 0,
        val decryptorCalls: Int = 0, val decrypted: Int? = null,
        val splits: Int = 0
    )

    class Lines(val failed: Boolean, val verdict: String, val criticalPath: List<String>, val mustFix: List<String>, val confidence: String, val notSeen: String) {
        fun asList(): List<Pair<String, String>> = listOf("VERDICT" to verdict, "CRITICAL PATH" to criticalPath.joinToString("\n"), "MUST FIX" to mustFix.joinToString("\n"),
            "CONFIDENCE" to confidence, "NOT SEEN" to notSeen)
    }

    const val MAX_MUST_FIX = 3

    /** "finished, 18093 / 18093 classes; ... (25 groups of up to 3000 classes ..." -> classes read, groups. */
    fun parseStatus(note: String): Pair<Int, Int> {
        val read = Regex("(?:finished, |stopped at )(\\d+) / \\d+").find(note)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val groups = Regex("(\\d+) groups of up to").find(note)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        return read to groups
    }

    private fun label(i: Int) = "#" + (i + 1)
    private fun where(f: Finding) = f.location.substringAfterLast('/').substringAfterLast('.').ifEmpty { f.location }

    /** [all] = every finding of the scan, INFO included (the native and asset scans say there what they could not read); the cards are the reported subset. */
    fun build(cards: List<Finding>, scenarios: List<AttackScenarios.Scenario>, cov: Coverage, pkg: String = "", all: List<Finding> = cards): Lines {
        if (cov.deepScan && cov.classesScanned == 0)
            return Lines(true, "SCAN FAILED: the deep scan read 0 classes, so nothing in this report is a verdict on the code (re-import the APK and run the Deep scan again).",
                emptyList(), emptyList(), "not rated (no classes read)", notSeen(cards, cov, all))
        val crit = cards.count { it.severity == Severity.CRITICAL }
        val high = cards.count { it.severity == Severity.HIGH }
        val rest = cards.size - crit - high
        val verdict = "$crit critical / $high high-priority / $rest informational (MEDIUM and below) of ${cards.size} reported card(s)" +
            (if (crit + high == 0) "; no HIGH or CRITICAL finding" else "") + (if (!cov.deepScan) "; manifest and resources only, no code scan was run" else "")

        // CRITICAL PATH: the scenario whose chain holds the highest-priority reported card and names an entry
        val pos = HashMap<Finding, Int>(); for ((i, f) in cards.withIndex()) pos[f] = i
        val best = scenarios.filter { s -> s.entry.isNotBlank() && s.chain.any { it in pos } }
            .maxByOrNull { s -> s.chain.filter { it in pos }.maxOf { FindingScore.of(it).value } }
        val path = if (best == null) listOf("none: no attack scenario links a reported card to an entry point") else {
            val chain = best.chain.filter { it in pos }
            val top = chain.maxByOrNull { FindingScore.of(it).value }!!
            listOf("card ${label(pos[top]!!)}: ${best.title}",
                "entry: ${best.entry} -> path: " + chain.joinToString(" -> ") { label(pos[it]!!) + " " + it.title.take(60) + " in " + where(it) } +
                    (FixTemplates.sinkOf(top)?.let { " -> sink: $it" } ?: ""),
                "impact: ${best.impact}")
        }

        // MUST FIX: HIGH / CRITICAL, reachable from an exported component, highest priority first; never more than three
        val must = cards.withIndex().filter { (_, f) -> f.severity.rank <= Severity.HIGH.rank && (f.reach == "YES" || f.reach == "YES~") }
            .sortedWith(compareByDescending<IndexedValue<Finding>> { FindingScore.of(it.value).value }.thenBy { it.index }).take(MAX_MUST_FIX)
            .map { (i, f) -> label(i) + " [" + f.severity.label + "] " + f.title + " in " + where(f) + " (" + FindingScore.of(f).short + "): " +
                (FixTemplates.match(f, pkg)?.sentence ?: f.recommendation.substringBefore(". ").trimEnd('.') + ".") }
            .ifEmpty { listOf("no HIGH/CRITICAL finding is reachable from an exported component") }

        // CONFIDENCE: a ratio, not an adjective
        val highPlus = cards.filter { it.severity.rank <= Severity.HIGH.rank }
        val sure = highPlus.count { FindingPolish.confidenceOf(it) == "HIGH" }
        val confidence = if (highPlus.isEmpty()) "weak (no HIGH or CRITICAL card to rate)" else {
            val pct = 100 * sure / highPlus.size
            (if (pct >= 80) "strong" else if (pct >= 50) "moderate" else "weak") + " ($pct% of HIGH+ cards have HIGH confidence: $sure of ${highPlus.size})"
        }
        return Lines(false, verdict, path, must, confidence, notSeen(cards, cov, all))
    }

    private fun notSeen(cards: List<Finding>, cov: Coverage, all: List<Finding>): String {
        val parts = ArrayList<String>()
        // QA 1.2.0 (a Flutter and a React Native app): the app's own code in Dart / JavaScript was not named, although the native and asset scans say so in INFO cards
        if (all.any { it.ruleId == "native-flutter" }) parts.add("Dart code (libapp.so): strings scanned, the code itself not analysed")
        all.firstOrNull { it.ruleId == "assets-coverage" }?.let { f -> parts.add(f.title.substringAfter("scanned as text: ").ifEmpty { "hybrid layer" } + ": scanned as text only, the code itself not analysed") }
        parts.add(if (!cov.deepScan) "code: not scanned (no Deep scan)" else "native: " + (if (cov.nativeMethods == 0) "no native method declared" else
            "${cov.nativeMethods} native methods, flows into .so not followed, " + (if (cov.nativeLibs > 0) "${cov.nativeLibs} libraries read" else "libraries not available (import the ABI split)")))
        val refl = cards.count { it.title.contains("class or method by name") }
        parts.add("reflection: Method.invoke / Class.forName targets are not followed" + (if (refl > 0) " ($refl card(s) with a reflection sink)" else ""))
        parts.add("strings: " + (if (cov.decryptorCalls == 0) "no string decryptor seen" else "${cov.decrypted ?: 0} / ${cov.decryptorCalls} decryptor call sites decrypted" +
            (if (cov.decrypted == null) " (no strings overlay imported)" else "")))
        parts.add("splits: " + (if (cov.splits == 0) "base only" else "base + ${cov.splits} split(s)"))
        parts.add("groups: " + when {
            !cov.deepScan -> "not run"
            cov.groups == 0 -> "whole app in one run"
            cov.groupsCapped > 0 || cov.timeUp -> "${cov.groupsCapped} of ${cov.groups} groups capped" + (if (cov.timeUp) ", time limit reached" else "")
            else -> "${cov.groups}/${cov.groups} groups"
        })
        return parts.joinToString("; ")
    }

    fun markdown(l: Lines): String {
        val sb = StringBuilder("## Verdict\n\n")
        if (l.failed) return sb.append("**VERDICT: ").append(l.verdict).append("**\n\n- **NOT SEEN:** ").append(l.notSeen).append("\n\n").toString()
        for ((k, v) in l.asList()) {
            val ls = v.split('\n')
            if (ls.size == 1) sb.append("- **").append(k).append(":** ").append(ls[0]).append('\n')
            else { sb.append("- **").append(k).append(":**\n"); for (x in ls) sb.append("  - ").append(x).append('\n') }
        }
        return sb.append("\nDeterministic summary of the cards below (no AI): card numbers are this report's; nothing here changes a card.\n\n").toString()
    }

    fun html(l: Lines): String {
        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        val sb = StringBuilder("<h2>Verdict</h2><div class=\"card\">")
        if (l.failed) return sb.append("<p><b>VERDICT: ").append(esc(l.verdict)).append("</b></p><p><b>NOT SEEN:</b> ").append(esc(l.notSeen)).append("</p></div>").toString()
        for ((k, v) in l.asList()) sb.append("<p><b>").append(k).append(":</b> ").append(v.split('\n').joinToString("<br>") { esc(it) }).append("</p>")
        return sb.append("</div>").toString()
    }

    /** The same five fields for SARIF run.properties. */
    fun properties(l: Lines): Map<String, String> = linkedMapOf("verdict" to (if (l.failed) "SCAN FAILED: " else "") + l.verdict, "criticalPath" to l.criticalPath.joinToString(" | "),
        "mustFix" to l.mustFix.joinToString(" | "), "confidence" to l.confidence, "notSeen" to l.notSeen)
}
