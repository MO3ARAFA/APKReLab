package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Scope
import dev.apkrelab.SecurityScanner.Severity
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.69.3: the priority number is deterministic, ordered the way a reviewer expects, and reaches the SARIF export. */
class FindingScoreTest {

    private fun f(sev: Severity, conf: String = "HIGH", reach: String = "", scope: Scope = Scope.APP, title: String = "T"): Finding {
        val x = Finding(sev, title, "detail", "fix", "Lcom/x/Y;", 0, 0, "CWE-1")
        x.confidence = conf
        x.reach = reach
        x.scope = scope
        return x
    }

    @Test fun baseValuesAtFullConfidenceAndNoDiscount() {
        assertEquals(90, FindingScore.of(f(Severity.CRITICAL)).value)
        assertEquals(70, FindingScore.of(f(Severity.HIGH)).value)
        assertEquals(45, FindingScore.of(f(Severity.MEDIUM)).value)
        assertEquals(20, FindingScore.of(f(Severity.LOW)).value)
        assertEquals(3, FindingScore.of(f(Severity.INFO)).value)      // FindingPolish.confidenceOf is always LOW for INFO: 5 x 0.6
    }

    @Test fun eachFactorOnlyEverLowersTheNumber() {
        val top = FindingScore.of(f(Severity.HIGH, "HIGH", "YES")).value
        assertTrue(FindingScore.of(f(Severity.HIGH, "MEDIUM", "YES")).value < top)
        assertTrue(FindingScore.of(f(Severity.HIGH, "LOW", "YES")).value < FindingScore.of(f(Severity.HIGH, "MEDIUM", "YES")).value)
        assertTrue(FindingScore.of(f(Severity.HIGH, "HIGH", "YES~")).value < top)
        assertTrue(FindingScore.of(f(Severity.HIGH, "HIGH", "NO")).value < FindingScore.of(f(Severity.HIGH, "HIGH", "YES~")).value)
        assertTrue(FindingScore.of(f(Severity.HIGH, "HIGH", "YES", Scope.OBF)).value < top)
        assertTrue(FindingScore.of(f(Severity.HIGH, "HIGH", "YES", Scope.LIB)).value < FindingScore.of(f(Severity.HIGH, "HIGH", "YES", Scope.OBF)).value)
    }

    @Test fun exactNumbersForAMixedCase() {
        // HIGH 70 x MEDIUM 0.85 x no path 0.7 x library 0.5 = 20.825 -> 21
        assertEquals(21, FindingScore.of(f(Severity.HIGH, "MEDIUM", "NO", Scope.LIB)).value)
        // CRITICAL 90 x HIGH 1.0 x reachable 1.0 x app 1.0
        assertEquals(90, FindingScore.of(f(Severity.CRITICAL, "HIGH", "YES")).value)
        // MEDIUM 45 x LOW 0.6 = 27
        assertEquals(27, FindingScore.of(f(Severity.MEDIUM, "LOW")).value)
    }

    @Test fun neverBelowOneNeverAboveOneHundred() {
        val lo = FindingScore.of(f(Severity.INFO, "LOW", "NO", Scope.LIB)).value
        assertTrue(lo >= 1)
        assertTrue(FindingScore.of(f(Severity.CRITICAL)).value <= 100)
    }

    @Test fun bandsFollowTheThresholds() {
        assertEquals("P1", FindingScore.of(f(Severity.CRITICAL)).band)
        assertEquals("P1", FindingScore.of(f(Severity.HIGH)).band)          // 70
        assertEquals("P2", FindingScore.of(f(Severity.HIGH, "MEDIUM")).band) // 59.5 -> 60
        assertEquals("P2", FindingScore.of(f(Severity.MEDIUM)).band)        // 45
        assertEquals("P3", FindingScore.of(f(Severity.MEDIUM, "LOW")).band) // 27
        assertEquals("P4", FindingScore.of(f(Severity.LOW)).band)           // 20
    }

    @Test fun aCriticalInLibraryCodeRanksBelowAMediumInAppCode() {
        assertTrue(FindingScore.of(f(Severity.CRITICAL, "HIGH", "NO", Scope.LIB)).value < FindingScore.of(f(Severity.HIGH, "HIGH", "YES")).value)
    }

    @Test fun theAiVerdictDoesNotMoveTheNumber() {
        val a = f(Severity.HIGH)
        val b = f(Severity.HIGH)
        b.verdict = "FP"
        assertEquals(FindingScore.of(a).value, FindingScore.of(b).value)
    }

    @Test fun theSarifResultCarriesRankAndTheBand() {
        val fi = f(Severity.HIGH, "MEDIUM", "YES")
        val json = JSONObject(SarifExport.build("com.x", "0.69.3", listOf(fi)))
        val res = json.getJSONArray("runs").getJSONObject(0).getJSONArray("results").getJSONObject(0)
        assertEquals(60.0, res.getDouble("rank"), 0.0001)           // 70 x 0.85 = 59.5 -> 60
        assertEquals("P2", res.getJSONObject("properties").getString("priorityBand"))
        assertTrue(res.getJSONObject("properties").getString("priorityWhy").contains("confidence MEDIUM"))
    }

    @Test fun theHtmlReportShowsThePriorityLine() {
        val fi = f(Severity.HIGH, "HIGH", "YES")
        val html = ReportBuilder.html("com.x", "info", listOf(fi), emptyList())
        assertTrue(html.contains("Priority: 70/100 (P1)"))
    }
}
