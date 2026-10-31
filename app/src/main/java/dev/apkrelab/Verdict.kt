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
        val splits: Int = 0,
        /** 2.0.0 pillar 3b: the hybrid frameworks HybridInspector detected (empty = a native app). */
        val hybridKinds: List<HybridInspector.HybridKind> = emptyList()
    )

    class Lines(val failed: Boolean, val verdict: String, val criticalPath: List<String>, val mustFix: List<String>, val confidence: String, val notSeen: String) {
        fun asList(): List<Pair<String, String>> = listOf("VERDICT" to verdict, "CRITICAL PATH" to criticalPath.joinToString("\n"), "MUST FIX" to mustFix.joinToString("\n"),
            "CONFIDENCE" to confidence, "NOT SEEN" to notSeen)
    }

    const val MAX_MUST_FIX = 3
    /** 1.2.1: a MUST FIX card whose evidence is below this is marked "CHECK FIRST:" (no traced source + path). */
    const val CHECK_FIRST_BELOW = 0.9
    /** 1.2.1: switches for the mutation checks of the verify lines and the sanitizer families. */
    internal var VERIFY = true
    internal var SANITIZER_FAMILIES = true

    private val methodRe = Regex("in method ([A-Za-z0-9_$.<>]+)\\(")
    private val lineRe = Regex("\\(around line (\\d+)\\)")
    // the families of TaintEngine.validationRe / SsaBridge.VALIDATION, by the sink they protect
    private val noStandardSanitizer = listOf("Runtime.exec", "ProcessBuilder.", "WebView.addJavascriptInterface", "Class.forName", "Method.invoke", "DexClassLoader.", "PathClassLoader.",
        "System.load", "ObjectInputStream.")
    private fun family(sink: String): String? = when {
        sink.startsWith("WebView.") -> "a host allow-list (Uri.parse + getHost / getScheme compared with equals / startsWith / an allow-list contains)"
        sink.startsWith("File") || sink.startsWith("RandomAccessFile") || sink.startsWith("ParcelFileDescriptor.open") || sink.startsWith("Files.") || sink.startsWith("ZipFile") ->
            "a canonical-path check (getCanonicalPath / getCanonicalFile / normalize, then startsWith of the base directory) or a \"..\" check"
        sink.startsWith("SQLiteDatabase.") || sink.startsWith("SupportSQLiteDatabase.") -> "selection arguments (? placeholders) or DatabaseUtils.sqlEscapeString"
        sink.startsWith("ContentResolver.open") -> "a scheme / authority allow-list (Uri.getScheme / getAuthority)"
        else -> null
    }
    private val COMPONENT_CARD = Regex("(?i)exported|permission|provider|receiver|service|activity")
    private fun fmtEv(e: Double) = if (e == 1.0) "1.0" else String.format(java.util.Locale.US, "%.1f", e)
    private fun evidenceKind(e: Double) = when { e >= 1.0 -> "real SSA source+path"; e >= 0.8 -> "source only: a flow inside one class"; e >= 0.6 -> "rule-only"; else -> "validation-like calls on the path" }

    /** 1.2.1: what the reader opens to confirm a card before acting on it, from the card's own fields. */
    fun verifyOf(f: Finding): String {
        val sink = FixTemplates.sinkOf(f)
        val method = methodRe.find(f.detail)?.groupValues?.get(1)?.substringAfterLast('.')?.let { "$it()" }
        val cls = f.classType?.removePrefix("L")?.removeSuffix(";")?.replace('/', '.')
        val ssa = f.detail.contains("Found by the SSA data-flow engine")
        val deepLink = f.detail.contains("Data from Intent.getData()") || f.detail.contains("Data from a deep link") || f.ruleId == "manifest-deep-links"
        return when {
            sink != null && noStandardSanitizer.any { sink.startsWith(it) } ->
                (if (ssa) "SSA flow verified; " else "") + "no sanitizer is standard for $sink: confirm the value really comes from outside in ${method ?: cls}"
            sink != null && sink.startsWith("WebView.") -> "check the host allow-list / Uri.parse before loadUrl in ${method ?: cls}" + (if (ssa) " or its direct callees" else "") + ". If present, this is a false positive."
            deepLink && sink != null -> "check the host / path validation in ${method ?: cls} before the sink ($sink). If present, this is a false positive."
            SANITIZER_FAMILIES && sink != null && family(sink) != null -> "check for ${family(sink)} in ${method ?: cls} or its direct callees. If present, this is a false positive."
            // 1.2.1 QA (VulnLab #54: an SSA card whose sink has no sanitizer family was described as a rule-only match)
            sink != null && (ssa || f.ruleId.startsWith("taint")) -> (if (ssa) "SSA flow verified; " else "") + "the scanner knows no standard sanitizer for $sink: read ${method ?: cls} between the source and $sink and confirm nothing restricts the value."
            // 1.2.1 QA (Gu3ssWeak: debuggable / allowBackup got the exported-component caller-check sentence)
            f.classType == null && !COMPONENT_CARD.containsMatchIn(f.title) -> "open ${f.location} and confirm \"" + f.title + "\" in the manifest of the build you ship (the rule read the manifest only)."
            f.classType == null -> "open ${f.location} (" + f.title.substringAfter(": ", f.title) + "): check the permission and the component's own caller checks (getCallingPackage / Binder.getCallingUid / a signature check); the rule read the manifest only."
            else -> "open $cls" + (lineRe.find(f.detail)?.groupValues?.get(1)?.let { " at smali line $it" } ?: "") + " (offset ${f.at}): the rule matched a pattern there and traced no data flow; confirm the code does what the title says."
        }
    }

    /** "finished, 18093 / 18093 classes; ... (25 groups of up to 3000 classes ..." -> classes read, groups. */
    fun parseStatus(note: String): Pair<Int, Int> {
        val read = Regex("(?:finished, |stopped at )(\\d+) / \\d+").find(note)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val groups = Regex("(\\d+) groups of up to").find(note)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        return read to groups
    }

    private fun label(i: Int) = "#" + (i + 1)
    private fun where(f: Finding) = f.location.substringAfterLast('/').substringAfterLast('.').ifEmpty { f.location }

    /** [all] = every finding of the scan, INFO included (the native and asset scans say there what they could not read); the cards are the reported subset. */
    /** [guard] = the manifest's permission guards for the MUST FIX gate (phase 2); null = the reach pass's own seed filter is trusted. */
    fun build(cards: List<Finding>, scenarios: List<AttackScenarios.Scenario>, cov: Coverage, pkg: String = "", all: List<Finding> = cards, guard: PermissionGuard? = null): Lines {
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
                "impact: ${best.impact}") + chain.take(MAX_MUST_FIX).map { "→ to verify (" + label(pos[it]!!) + "): " + verifyOf(it) }      // 1.2.1
        }

        // MUST FIX: HIGH / CRITICAL cards that pass the four-condition gate (phase 2: MustFixGate), highest priority first; never more than three
        val must = cards.withIndex().filter { (_, f) -> f.severity.rank <= Severity.HIGH.rank && MustFixGate.check(f, guard).passes }
            .sortedWith(compareByDescending<IndexedValue<Finding>> { FindingScore.of(it.value).value }.thenBy { it.index }).take(MAX_MUST_FIX)
            .map { (i, f) ->
                val ev = FindingScore.confidence(f).evidence
                (if (VERIFY && ev < CHECK_FIRST_BELOW) "CHECK FIRST: " else "") + label(i) + " [" + f.severity.label + "] " + f.title + " in " + where(f) + " (" + FindingScore.of(f).short + "): " +
                    (FixTemplates.match(f, pkg)?.sentence ?: f.recommendation.substringBefore(". ").trimEnd('.') + ".") +
                    (if (VERIFY) "\n→ to verify: " + verifyOf(f) + "\nEvidence: " + fmtEv(ev) + " (" + evidenceKind(ev) + ")" else "")      // 1.2.1
            }
            .ifEmpty { listOf("no HIGH/CRITICAL finding passes the MUST FIX gate (high-impact sink, exported entry without a signature-level guard, no validation seen, traced proof)") }

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
        // 2.0.0 pillar 3b: from the frameworks HybridInspector detected; a native app gets no hybrid clause. When it detected none but the asset / native scans
        // still saw a hybrid layer (its libraries in a split that was not imported), their 1.2.0 card-based lines stay so NOT SEEN keeps saying so.
        if (cov.hybridKinds.isNotEmpty()) parts.addAll(HybridInspector.notSeen(cov.hybridKinds))
        else {
            if (all.any { it.ruleId == "native-flutter" }) parts.add("Dart code (libapp.so): strings scanned, the code itself not analysed")
            all.firstOrNull { it.ruleId == "assets-coverage" }?.let { f -> parts.add(f.title.substringAfter("scanned as text: ").ifEmpty { "hybrid layer" } + ": scanned as text only, the code itself not analysed") }
        }
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
