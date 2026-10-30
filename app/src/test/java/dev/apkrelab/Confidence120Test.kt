package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.2.0: per-card confidence with visible factors. */
class Confidence120Test {
    private val ssa = " reaches FileOutputStream.<init>() in method A.b(). Found by the SSA data-flow engine, which follows values."
    private fun f(detail: String, sev: Severity = Severity.HIGH, reach: String = "", rule: String = "taint-flow", scope: SecurityScanner.Scope = SecurityScanner.Scope.APP) =
        Finding(sev, "Untrusted input is used as a file path", detail, "fix", "Lcom/x/A;", 1, 0, "CWE-22").also { it.ruleId = rule; it.reach = reach; it.scope = scope }

    private val intentFlow = "Data from Intent.getStringExtra()$ssa"

    @Test fun allFactorsAtTheTop() {
        val c = FindingScore.confidence(f(intentFlow, Severity.CRITICAL, "YES").also { it.chain = "Entry: com.x.MainActivity.onCreate\nPath: a" })
        assertEquals(90, c.value)
        assertEquals("severity 90 x reach 1.0 x source 1.0 x evidence 1.0", c.factors)
        assertEquals("reachable from exported com.x.MainActivity.onCreate, source is Intent.getStringExtra(), sink is FileOutputStream.<init>, no validation seen", c.why)
    }

    @Test fun reachMovesTheScore() {
        assertEquals(70, FindingScore.confidence(f(intentFlow, reach = "YES")).value)
        assertEquals(63, FindingScore.confidence(f(intentFlow, reach = "YES~")).value)
        assertEquals(49, FindingScore.confidence(f(intentFlow, reach = "NO")).value)
        assertEquals(70, FindingScore.confidence(f(intentFlow, reach = "")).value)          // not traced: neutral
    }

    @Test fun sourceQualityMovesTheScore() {
        assertEquals(63, FindingScore.confidence(f("Data from a ContentProvider method parameter$ssa")).value)
        assertEquals(49, FindingScore.confidence(f("Data from SharedPreferences.getString()$ssa")).value)
        assertEquals(35, FindingScore.confidence(f(intentFlow, scope = SecurityScanner.Scope.LIB)).value)
    }

    @Test fun thePrefsSourceIsTheSwitchedPart() {
        FindingScore.SOURCE_QUALITY = false
        try { assertEquals(70, FindingScore.confidence(f("Data from SharedPreferences.getString()$ssa")).value) } finally { FindingScore.SOURCE_QUALITY = true }
        assertEquals(49, FindingScore.confidence(f("Data from SharedPreferences.getString()$ssa")).value)
    }

    @Test fun evidenceMovesTheScore() {
        assertEquals(56, FindingScore.confidence(f("Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method A.b(). The value was followed inside this class.")).value)   // class-level rule 0.8
        val ruleOnly = FindingScore.confidence(f("A pattern in the text.", rule = "weak-hash"))
        assertEquals(0.6, ruleOnly.evidence, 0.0)                                                // no SSA flow: 0.6
        assertEquals(1.0, ruleOnly.source, 0.0)                                                  // no source named: neutral
        assertTrue(ruleOnly.why, ruleOnly.why.contains("a rule's pattern match, no data flow traced"))
    }

    @Test fun validationOnThePathIsLowEvidence() {
        val c = FindingScore.confidence(f("$intentFlow The chain also contains validation-like calls (startsWith, matches, getHost ...): verify that they really restrict this value."))
        assertEquals(0.3, c.evidence, 0.0)
        assertEquals(21, c.value)
        assertTrue(c.why.endsWith("validation-like calls seen on the path (check them)"))
        assertEquals(1.0, FindingScore.confidence(f(intentFlow)).evidence, 0.0)                // twin: no validation sentence, full evidence
    }

    @Test fun allFactorsAtTheBottom() {
        val c = FindingScore.confidence(f("Data from SharedPreferences.getString()$ssa The method also contains validation-like calls.", Severity.INFO, "NO", scope = SecurityScanner.Scope.LIB))
        assertEquals(1, c.value)                                                                  // 5 x 0.7 x 0.5 x 0.3 = 0.5 -> 1
        assertEquals("severity 5 x reach 0.7 x source 0.5 x evidence 0.3", c.factors)
    }

    @Test fun rendersUnderEachCard() {
        val cards = listOf(f(intentFlow, reach = "YES").also { it.chain = "Entry: com.x.Main.onCreate\nPath: a" })
        val md = ReportBuilder.securitySection(cards, 400, "com.x")
        assertTrue(md, md.contains("- Confidence: 70/100 - severity 70 x reach 1.0 x source 1.0 x evidence 1.0\n- Why: reachable from exported com.x.Main.onCreate"))
        val html = ReportBuilder.html("com.x", "", cards, emptyList())
        assertTrue(html.contains("Confidence: 70/100 - severity 70 x reach 1.0 x source 1.0 x evidence 1.0<br>Why: reachable"))
    }
}
