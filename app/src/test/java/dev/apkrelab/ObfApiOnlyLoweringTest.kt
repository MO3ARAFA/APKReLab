package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.0.1: API-presence rules (deserialization, weak hash, weak random) are lowered one level in R8-obfuscated code, nothing else is. */
class ObfApiOnlyLoweringTest {
    private fun card(rule: String, scope: SecurityScanner.Scope, sev: SecurityScanner.Severity = SecurityScanner.Severity.MEDIUM): SecurityScanner.Finding =
        SecurityScanner.Finding(sev, "t", "d", "r", "Lq/z;", 3, 10, "CWE-502").also { it.ruleId = rule; it.scope = scope; it.confidence = "HIGH" }

    private fun run(f: SecurityScanner.Finding): SecurityScanner.Finding { FindingPolish.apply(listOf(f), "Lq/z;"); return f }

    @Test fun theThreeApiRulesInObfuscatedCodeGoDownOneLevel() {
        for (r in listOf("deserialization", "crypto-weak-hash", "weak-random")) {
            val f = run(card(r, SecurityScanner.Scope.OBF))
            assertEquals(r, SecurityScanner.Severity.LOW, f.severity)
            assertTrue(f.adjusted, f.adjusted.startsWith("Lowered one level: obfuscated"))
        }
    }

    // twins
    @Test fun theSameRulesInTheAppsOwnCodeStayMedium() {
        for (r in listOf("deserialization", "crypto-weak-hash", "weak-random")) assertEquals(r, SecurityScanner.Severity.MEDIUM, run(card(r, SecurityScanner.Scope.APP)).severity)
    }

    @Test fun anotherExactRuleInObfuscatedCodeIsNotLowered() {
        assertEquals(SecurityScanner.Severity.HIGH, run(card("crypto-cipher", SecurityScanner.Scope.OBF, SecurityScanner.Severity.HIGH)).severity)
    }

    @Test fun mutantSwitchOffKeepsMedium() {
        val was = FindingPolish.LOWER_OBF_API_ONLY
        FindingPolish.LOWER_OBF_API_ONLY = false
        try { assertEquals(SecurityScanner.Severity.MEDIUM, run(card("deserialization", SecurityScanner.Scope.OBF)).severity) } finally { FindingPolish.LOWER_OBF_API_ONLY = was }
    }
}
