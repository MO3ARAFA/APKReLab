package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Scope
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.69.3: one 1..100 priority number per finding, so a long list can be worked top-down.
 *
 * It is an ESTIMATE for ordering, not CVSS (CVSS needs attack vector / complexity / impact that a static scan cannot know) and not a
 * probability. Same inputs always give the same number; nothing here changes what is detected or the severity.
 *
 *   score = base(severity) x confidence x reachability x scope        (rounded, 1..100)
 *   base:        CRITICAL 90, HIGH 70, MEDIUM 45, LOW 20, INFO 5
 *   confidence:  HIGH 1.0, MEDIUM 0.85, LOW 0.6                       (FindingPolish.confidenceOf; it is always LOW for INFO, so INFO scores 3)
 *   reachability: from an exported component 1.0, approximate class-level path 0.9, no path found 0.7, not traced / manifest 1.0
 *   scope:       app code 1.0, obfuscated 0.85, library 0.5
 *   band:        P1 >= 70 (fix first), P2 >= 45, P3 >= 25, P4 below
 *
 * The AI triage verdict is NOT used: it is not stable between runs (see HANDOFF), so it would make the number move for no reason.
 */
object FindingScore {

    class Score(val value: Int, val band: String, val why: String) {
        /** "62/100 (P2)" */
        val short: String get() = "$value/100 ($band)"
    }

    fun of(f: Finding): Score {
        val base = when (f.severity) {
            Severity.CRITICAL -> 90
            Severity.HIGH -> 70
            Severity.MEDIUM -> 45
            Severity.LOW -> 20
            Severity.INFO -> 5
        }
        val conf = FindingPolish.confidenceOf(f)
        val cf = when (conf) {
            "HIGH" -> 1.0
            "MEDIUM" -> 0.85
            else -> 0.6
        }
        val (rf, rText) = when (f.reach) {
            "YES" -> 1.0 to "reachable from an exported component"
            "YES~" -> 0.9 to "probably reachable (approximate path)"
            "NO" -> 0.7 to "no path from an exported component found"
            else -> 1.0 to "reachability not traced"
        }
        val sf = when (f.scope) {
            Scope.LIB -> 0.5
            Scope.OBF -> 0.85
            else -> 1.0
        }
        val v = Math.round(base * cf * rf * sf).toInt().coerceIn(1, 100)
        val band = when {
            v >= 70 -> "P1"
            v >= 45 -> "P2"
            v >= 25 -> "P3"
            else -> "P4"
        }
        val scopeText = when (f.scope) {
            Scope.LIB -> "library code"
            Scope.OBF -> "obfuscated code"
            else -> "app code"
        }
        return Score(v, band, "${f.severity.label} $base x confidence $conf $cf x $rText $rf x $scopeText $sf")
    }

    /**
     * 1.2.0: the card's confidence as a number with its factors shown (the report prints them under the card). Same severity base as [of];
     *   reach     YES 1.0, YES~ 0.9, NO 0.7, not traced 1.0
     *   source    Intent / JavaScript bridge 1.0, ContentProvider parameter 0.9, SharedPreferences 0.7, library code 0.5, no source named 1.0 (neutral)
     *   evidence  SSA flow with its path 1.0, a data-flow rule inside one class 0.8, a rule's text match 0.6; 0.3 when the engine saw validation-like calls on the path
     *             (the sentence SsaBridge / the class-level taint rule add from their validation pattern)
     */
    class Confidence(val value: Int, val severity: Int, val reach: Double, val source: Double, val evidence: Double, val why: String) {
        val factors: String get() = "severity $severity x reach ${fmt(reach)} x source ${fmt(source)} x evidence ${fmt(evidence)}"
        private fun fmt(d: Double) = if (d == 1.0) "1.0" else String.format(java.util.Locale.US, "%.2f", d).trimEnd('0').let { if (it.endsWith(".")) it + "0" else it }
    }

    /** 1.2.0: switch for the mutation check of the source factor. */
    internal var SOURCE_QUALITY = true

    private val validationSeen = Regex("(chain|method) also contains validation-like calls")

    fun confidence(f: Finding): Confidence {
        val base = when (f.severity) { Severity.CRITICAL -> 90; Severity.HIGH -> 70; Severity.MEDIUM -> 45; Severity.LOW -> 20; Severity.INFO -> 5 }
        val reach = when (f.reach) { "YES" -> 1.0; "YES~" -> 0.9; "NO" -> 0.7; else -> 1.0 }
        val d = f.detail
        val (source, srcText) = when {
            !SOURCE_QUALITY -> 1.0 to ""
            f.scope == Scope.LIB -> 0.5 to "source in library code"
            d.contains("Data from Intent.") || d.contains("Data from a deep link") || d.contains("JavaScript-bridge parameter") || d.contains("JavascriptInterface") -> 1.0 to "source is " + (if (d.contains("Data from Intent.") || d.contains("Data from a deep link")) d.substringAfter("Data from ").substringBefore(" reaches").substringBefore(" (through") else "a JavaScript-bridge parameter")
            d.contains("ContentProvider method parameter") -> 0.9 to "source is a ContentProvider parameter"
            d.contains("Data from SharedPreferences") -> 0.7 to "source is SharedPreferences (needs root or a tampered backup to change)"
            else -> 1.0 to ""
        }
        val ssa = d.contains("Found by the SSA data-flow engine")
        val validated = validationSeen.containsMatchIn(d)
        val evidence = when { validated -> 0.3; ssa -> 1.0; f.ruleId.startsWith("taint") -> 0.8; else -> 0.6 }
        val v = Math.round(base * reach * source * evidence).toInt().coerceIn(0, 100)
        val why = ArrayList<String>()
        when (f.reach) {
            "YES" -> why.add("reachable from exported " + (Correlation.entryOf(f) ?: "component"))
            "YES~" -> why.add("probably reachable (class-level path)")
            "NO" -> why.add("no path from an exported component found")
        }
        if (srcText.isNotEmpty()) why.add(srcText)
        FixTemplates.sinkOf(f)?.let { why.add("sink is $it") }
        why.add(when { validated -> "validation-like calls seen on the path (check them)"; ssa || f.ruleId.startsWith("taint") -> "no validation seen"; else -> "a rule's pattern match, no data flow traced" })
        return Confidence(v, base, reach, source, evidence, why.joinToString(", "))
    }
}
