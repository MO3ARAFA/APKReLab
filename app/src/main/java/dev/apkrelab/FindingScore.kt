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
}
