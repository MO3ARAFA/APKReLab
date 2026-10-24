package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Scope
import dev.apkrelab.SecurityScanner.Severity
import dev.apkrelab.ScanCompare.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.71.0: Before / After compare. */
class ScanCompareTest {

    private fun f(sev: Severity, title: String, cls: String = "Lcom/x/A;", rule: String = "r1", scope: Scope = Scope.APP,
                  count: Int = 1, at: Int = 0, cwe: String = "CWE-79"): Finding {
        val x = Finding(sev, title, "detail", "fix", cls, 0, at, cwe)
        x.ruleId = rule
        x.confidence = "HIGH"
        x.scope = scope
        x.count = count
        return x
    }

    private fun snap(label: String, vararg l: Finding) = ScanCompare.snapshot("com.x", "1.0", label, 1L, l.toList())

    @Test fun identicalScansAreNoChange() {
        val a = snap("a", f(Severity.HIGH, "T1"), f(Severity.LOW, "T2", "Lcom/x/B;"))
        val b = snap("b", f(Severity.HIGH, "T1"), f(Severity.LOW, "T2", "Lcom/x/B;"))
        val d = ScanCompare.diff(a, b)
        assertEquals("NO CHANGE", d.verdict)
        assertEquals(2, d.same.size)
        assertEquals(0, d.scoreDelta)
    }

    @Test fun removedFindingIsFixedAndNewOneIsNew() {
        val a = snap("a", f(Severity.HIGH, "T1"), f(Severity.MEDIUM, "T2", "Lcom/x/B;"))
        val b = snap("b", f(Severity.HIGH, "T1"), f(Severity.MEDIUM, "T3", "Lcom/x/C;", rule = "r9", cwe = "CWE-1"))
        val d = ScanCompare.diff(a, b)
        assertEquals(1, d.fixed.size)
        assertEquals("T2", d.fixed[0].title)
        assertEquals(1, d.added.size)
        assertEquals("T3", d.added[0].title)
        assertEquals(1, d.same.size)
    }

    @Test fun fixedOnlyIsImproved() {
        val a = snap("a", f(Severity.HIGH, "T1"), f(Severity.HIGH, "T2", "Lcom/x/B;"))
        val b = snap("b", f(Severity.HIGH, "T1"))
        val d = ScanCompare.diff(a, b)
        assertEquals("IMPROVED", d.verdict)
        assertTrue(d.scoreDelta < 0)
    }

    @Test fun newFindingMakesItRegressedEvenIfNothingElseChanged() {
        val a = snap("a", f(Severity.HIGH, "T1"))
        val b = snap("b", f(Severity.HIGH, "T1"), f(Severity.LOW, "T9", "Lcom/x/Z;", rule = "r9", cwe = "CWE-9"))
        assertEquals("REGRESSED", ScanCompare.diff(a, b).verdict)
    }

    @Test fun oneFixedOneNewIsMixedWhenScoreDrops() {
        val a = snap("a", f(Severity.CRITICAL, "Big", "Lcom/x/B;", rule = "r2", cwe = "CWE-2"))
        val b = snap("b", f(Severity.LOW, "Small", "Lcom/x/C;", rule = "r3", cwe = "CWE-3"))
        val d = ScanCompare.diff(a, b)
        assertEquals("MIXED", d.verdict)
        assertTrue(d.scoreDelta < 0)
    }

    @Test fun severityChangeIsWorseOrBetter() {
        val a = snap("a", f(Severity.MEDIUM, "T1"))
        assertEquals(Status.WORSE, ScanCompare.diff(a, snap("b", f(Severity.HIGH, "T1"))).changes[0].status)
        assertEquals(Status.BETTER, ScanCompare.diff(a, snap("b", f(Severity.LOW, "T1"))).changes[0].status)
    }

    @Test fun countChangeAtSameSeverity() {
        val a = snap("a", f(Severity.HIGH, "T1", count = 3))
        assertEquals(Status.BETTER, ScanCompare.diff(a, snap("b", f(Severity.HIGH, "T1", count = 1))).changes[0].status)
        assertEquals(Status.WORSE, ScanCompare.diff(a, snap("b", f(Severity.HIGH, "T1", count = 5))).changes[0].status)
    }

    @Test fun offsetAndAiVerdictDoNotMatter() {
        val x = f(Severity.HIGH, "T1", at = 10)
        val y = f(Severity.HIGH, "T1", at = 9999)
        y.verdict = "FP"
        val d = ScanCompare.diff(snap("a", x), snap("b", y))
        assertEquals("NO CHANGE", d.verdict)
    }

    @Test fun infoAndLibraryAreLeftOut() {
        val s = snap("a", f(Severity.INFO, "I"), f(Severity.HIGH, "L", scope = Scope.LIB), f(Severity.HIGH, "A"))
        assertEquals(1, s.entries.size)
        assertEquals("A", s.entries[0].title)
    }

    @Test fun sameRuleAndPlaceWithNewTitleIsChangedNotFixedPlusNew() {
        val a = snap("a", f(Severity.HIGH, "Hardcoded key abc123"))
        val b = snap("b", f(Severity.HIGH, "Hardcoded key zzz999"))
        val d = ScanCompare.diff(a, b)
        assertEquals(0, d.fixed.size)
        assertEquals(0, d.added.size)
        assertEquals(Status.CHANGED, d.changes[0].status)
        assertEquals("NO CHANGE", d.verdict)
    }

    @Test fun differentRuleAtSamePlaceIsNotMerged() {
        val a = snap("a", f(Severity.HIGH, "T1", rule = "r1"))
        val b = snap("b", f(Severity.HIGH, "T2", rule = "r2"))
        val d = ScanCompare.diff(a, b)
        assertEquals(1, d.fixed.size)
        assertEquals(1, d.added.size)
    }

    @Test fun duplicateKeysAreMergedWorstSeverityAndSummedCount() {
        val s = snap("a", f(Severity.LOW, "T1", count = 2), f(Severity.HIGH, "T1", count = 3))
        assertEquals(1, s.entries.size)
        assertEquals("HIGH", s.entries[0].severity)
        assertEquals(5, s.entries[0].count)
    }

    @Test fun jsonRoundTripKeepsEverythingTheDiffNeeds() {
        val a = snap("before", f(Severity.HIGH, "T \"quoted\" \n line"), f(Severity.LOW, "T2", "Lcom/x/B;"))
        val back = ScanCompare.fromJson(ScanCompare.toJson(a))
        assertNotNull(back)
        assertEquals(a.entries.size, back!!.entries.size)
        assertEquals("before", back.label)
        assertEquals("NO CHANGE", ScanCompare.diff(a, back).verdict)
        assertEquals(a.totalScore, back.totalScore)
    }

    @Test fun damagedOrForeignJsonIsNullNotACrash() {
        assertNull(ScanCompare.fromJson(""))
        assertNull(ScanCompare.fromJson("{not json"))
        assertNull(ScanCompare.fromJson("{\"format\":99,\"findings\":[]}"))
        assertNull(ScanCompare.fromJson("{\"format\":1}"))
    }

    @Test fun markdownListsEachGroupAndTheHonestyNote() {
        val a = snap("old.apk", f(Severity.HIGH, "Gone", "Lcom/x/G;", rule = "r5", cwe = "CWE-5"), f(Severity.MEDIUM, "Stays"))
        val b = snap("new.apk", f(Severity.HIGH, "Stays"), f(Severity.LOW, "Added", "Lcom/x/N;", rule = "r6", cwe = "CWE-6"))
        val md = ScanCompare.markdown(ScanCompare.diff(a, b))
        assertTrue(md.contains("## Fixed (1)"))
        assertTrue(md.contains("## New findings (1)"))
        assertTrue(md.contains("## Got worse (1)"))
        assertTrue(md.contains("MEDIUM -> HIGH"))
        assertTrue(md.contains("old.apk") && md.contains("new.apk"))
        assertTrue(md.contains("does not prove"))
    }

    @Test fun newAndWorseComeFirstInTheList() {
        val a = snap("a", f(Severity.HIGH, "Fixed one", "Lcom/x/F;", rule = "r5", cwe = "CWE-5"), f(Severity.LOW, "Up"))
        val b = snap("b", f(Severity.HIGH, "Up"), f(Severity.LOW, "New one", "Lcom/x/N;", rule = "r6", cwe = "CWE-6"))
        val order = ScanCompare.diff(a, b).changes.map { it.status }
        assertEquals(listOf(Status.NEW, Status.WORSE, Status.FIXED), order)
    }
}
