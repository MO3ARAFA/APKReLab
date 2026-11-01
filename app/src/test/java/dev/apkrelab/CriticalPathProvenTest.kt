package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.1.0 (WE Wallet report 3): the Verdict's CRITICAL PATH names only a HIGH / CRITICAL scenario with a HIGH / CRITICAL card whose path is not approximate. */
class CriticalPathProvenTest {
    private fun card(sev: Severity, reach: String, cls: String = "Lcom/x/Web;") =
        Finding(sev, "Untrusted input is loaded into a WebView", "Data from Intent.getStringExtra() reaches WebView.loadUrl() in method m(). Found by the SSA data-flow engine.", "Fix it. More text.", cls, 1, 0, "CWE-79")
            .also { it.reach = reach; it.confidence = "HIGH"; it.ruleId = "taint-flow"; it.scope = SecurityScanner.Scope.APP }

    private fun scenario(sev: Severity, vararg chain: Finding) =
        AttackScenarios.Scenario("s", "Attacker-chosen web content in a WebView", sev, "high", "exported", "any app", "com.x.Start (exported, launcher)", chain.toList(), "page runs script", "", "", emptyList())

    private val full = Verdict.Coverage(deepScan = true, classesScanned = 1200)

    @Test fun aMediumCardWithAnApproximateReachIsNotACriticalPath() {
        val c = card(Severity.MEDIUM, "YES~")
        val v = Verdict.build(listOf(c), listOf(scenario(Severity.HIGH, c)), full)
        assertTrue(v.criticalPath.single(), v.criticalPath.single().startsWith("none: no HIGH or CRITICAL attack scenario has a proven path"))
    }

    @Test fun aHighCardWithAnApproximateReachIsNotEither() {
        val c = card(Severity.HIGH, "YES~")
        assertTrue(Verdict.build(listOf(c), listOf(scenario(Severity.HIGH, c)), full).criticalPath.single().startsWith("none: no HIGH or CRITICAL"))
    }

    // twins
    @Test fun aHighCardWithAProvenReachIsStillACriticalPath() {
        val c = card(Severity.HIGH, "YES")
        assertEquals("card #1: Attacker-chosen web content in a WebView", Verdict.build(listOf(c), listOf(scenario(Severity.HIGH, c)), full).criticalPath[0])
    }

    @Test fun aHighCardOfAnUntracedRuleStillCounts() {
        val c = card(Severity.HIGH, "")
        assertEquals("card #1: Attacker-chosen web content in a WebView", Verdict.build(listOf(c), listOf(scenario(Severity.HIGH, c)), full).criticalPath[0])
    }

    @Test fun aMediumScenarioIsNotACriticalPathEvenWithAProvenHighCard() {
        val c = card(Severity.HIGH, "YES")
        assertTrue(Verdict.build(listOf(c), listOf(scenario(Severity.MEDIUM, c)), full).criticalPath.single().startsWith("none"))
    }

    @Test fun mutantSwitchOffShowsTheApproximateOne() {
        val was = Verdict.CRITICAL_PATH_PROVEN
        Verdict.CRITICAL_PATH_PROVEN = false
        try {
            val c = card(Severity.MEDIUM, "YES~")
            assertTrue(Verdict.build(listOf(c), listOf(scenario(Severity.HIGH, c)), full).criticalPath[0].startsWith("card #1"))
        } finally { Verdict.CRITICAL_PATH_PROVEN = was }
    }
}
