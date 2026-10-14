package dev.apkrelab

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.51.0: SARIF structure and the AI false-positive guard. */
class SarifExportTest {

    private fun finding(sev: SecurityScanner.Severity, title: String, rule: String, type: String? = "Lcom/x/Y;"): SecurityScanner.Finding {
        val f = SecurityScanner.Finding(sev, title, "detail of $title", "fix it", type, if (type == null) -1 else 0, 0, "CWE-89")
        f.ruleId = rule
        return f
    }

    @Test fun structureAndLevels() {
        val list = listOf(
            finding(SecurityScanner.Severity.HIGH, "A", "rule-a"),
            finding(SecurityScanner.Severity.MEDIUM, "B", "rule-b"),
            finding(SecurityScanner.Severity.LOW, "C", "rule-a")
        )
        val j = JSONObject(SarifExport.build("com.x", "0.51.0", list))
        assertEquals("2.1.0", j.getString("version"))
        val run = j.getJSONArray("runs").getJSONObject(0)
        assertEquals(3, run.getJSONArray("results").length())
        assertEquals(2, run.getJSONObject("tool").getJSONObject("driver").getJSONArray("rules").length())   // rule-a is listed once
        val lv = (0 until 3).map { run.getJSONArray("results").getJSONObject(it).getString("level") }
        assertEquals(listOf("error", "warning", "note"), lv)
        val uri = run.getJSONArray("results").getJSONObject(0).getJSONArray("locations").getJSONObject(0)
            .getJSONObject("physicalLocation").getJSONObject("artifactLocation").getString("uri")
        assertEquals("smali/com/x/Y.smali", uri)
    }

    @Test fun falsePositiveBecomesSuppressionNotDeletion() {
        val f = finding(SecurityScanner.Severity.MEDIUM, "A", "rule-a")
        f.verdict = "FP"
        f.verdictNote = "looks safe"
        val r = JSONObject(SarifExport.build("p", "1", listOf(f))).getJSONArray("runs").getJSONObject(0).getJSONArray("results").getJSONObject(0)
        assertTrue(r.has("suppressions"))
    }

    @Test fun missingRuleIdGetsAStableSlug() {
        val f = finding(SecurityScanner.Severity.LOW, "Weak hash: MD5", "", null)
        assertEquals("apkrelab-weak-hash-md5", SarifExport.ruleIdOf(f))
        assertEquals("AndroidManifest.xml", SarifExport.uriOf(f))
    }

    @Test fun guardKeepsExactAndReachedFindingsFromBeingBuried() {
        val exact = finding(SecurityScanner.Severity.HIGH, "A", "crypto-hardcoded-key")
        exact.confidence = "HIGH"; exact.verdict = "FP"; exact.verdictNote = "x"
        assertTrue(FindingPolish.guardFalsePositive(exact))
        assertEquals("REVIEW", exact.verdict)

        val reached = finding(SecurityScanner.Severity.HIGH, "B", "taint-flow")
        reached.confidence = "MEDIUM"; reached.reach = "YES~"; reached.verdict = "FP"; reached.verdictNote = "x"
        assertTrue(FindingPolish.guardFalsePositive(reached))

        val confident = finding(SecurityScanner.Severity.MEDIUM, "D", "deeplink-host-validation")
        confident.confidence = "MEDIUM"; confident.reach = "YES"; confident.verdict = "FP"; confident.verdictNote = "equals check\n(confidence 90%)"
        assertFalse(FindingPolish.guardFalsePositive(confident))
        assertEquals("FP", confident.verdict)

        val shell = finding(SecurityScanner.Severity.MEDIUM, "E", "shell-exec")
        shell.confidence = "MEDIUM"; shell.reach = "YES"; shell.verdict = "FP"; shell.verdictNote = "x"
        assertFalse(FindingPolish.guardFalsePositive(shell))

        val plain = finding(SecurityScanner.Severity.MEDIUM, "C", "taint-flow")
        plain.confidence = "MEDIUM"; plain.reach = "NO"; plain.verdict = "FP"; plain.verdictNote = "x"
        assertFalse(FindingPolish.guardFalsePositive(plain))
        assertEquals("FP", plain.verdict)
    }
}
