package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.106.0: LOW rule findings in renamed or library code are one card per rule across classes, listing every class; everything else keeps one card per class. */
class CrossClassLow0106Test {
    private fun f(sev: SecurityScanner.Severity, type: String, idx: Int, scope: SecurityScanner.Scope, rule: String = "receiver-export-flag", title: String = "Dynamic receiver registered without export flag") =
        SecurityScanner.Finding(sev, title, "detail", "fix", type, idx, 10).also { it.ruleId = rule; it.scope = scope }

    @Test fun lowCardsOfRenamedCodeBecomeOneCardThatNamesEveryClass() {
        val obf = listOf("Laq8;", "Lc66;", "Ld62;", "Lfy;").mapIndexed { i, t -> f(SecurityScanner.Severity.LOW, t, i, SecurityScanner.Scope.OBF) }
        val out = SecurityScanner.aggregate(obf)
        assertEquals(1, out.size); assertEquals(4, out[0].count)
        assertTrue(out[0].detail, out[0].detail.contains("3 more renamed class(es)") && out[0].detail.contains("c66") && out[0].detail.contains("d62") && out[0].detail.contains("fy"))
        // library code: its own card, also merged
        val lib = listOf("Lbo/app/f0;", "Lbo/app/s;").mapIndexed { i, t -> f(SecurityScanner.Severity.LOW, t, 10 + i, SecurityScanner.Scope.LIB) }
        assertEquals(2, SecurityScanner.aggregate(obf + lib).size)
    }

    @Test fun appCodeMediumAndFlowsKeepOneCardPerClass() {
        val app = listOf("Lcom/x/A;", "Lcom/x/B;").mapIndexed { i, t -> f(SecurityScanner.Severity.LOW, t, i, SecurityScanner.Scope.APP) }
        assertEquals(2, SecurityScanner.aggregate(app).size)
        val med = listOf("La;", "Lb;").mapIndexed { i, t -> f(SecurityScanner.Severity.MEDIUM, t, i, SecurityScanner.Scope.OBF) }
        assertEquals(2, SecurityScanner.aggregate(med).size)
        val flows = listOf("La;", "Lb;").mapIndexed { i, t -> f(SecurityScanner.Severity.LOW, t, i, SecurityScanner.Scope.OBF, "taint-flow", "Untrusted input is used as a file path") }
        assertEquals(2, SecurityScanner.aggregate(flows).size)
    }

    @Test fun brazesObfuscatedInternalsAreLibraryCode() {
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lbo/app/f0;", "com.x"))
        assertTrue(SecurityScanner.scopeOf("Lbo/application/Main;", "com.x") != SecurityScanner.Scope.LIB)    // twin: only the bo/app/ package
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lantlr/JavaCodeGenerator;", "com.x"))   // 0.108.0: ANTLR 2, bundled by jadx
    }
}
