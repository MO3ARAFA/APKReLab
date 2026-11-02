package dev.apkrelab

import dev.apkrelab.ScanCompare.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 2.2 session 1: ReportDiff (two Markdown reports -> findings, MUST FIX and manifest delta). Synthetic reports in the real report layout + two real pairs. */
class ReportDiffTest {

    /** The switches as they were when the class loaded: a mutation of a default (done by hand to check the tests) must survive a reset. */
    private companion object {
        val D_KEYS = ReportDiff.COMPARE_KEYS; val D_MANIFEST = ReportDiff.MANIFEST_DELTA; val D_REMOVED = ReportDiff.REPORT_REMOVED
    }
    private fun reset() { ReportDiff.COMPARE_KEYS = D_KEYS; ReportDiff.MANIFEST_DELTA = D_MANIFEST; ReportDiff.REPORT_REMOVED = D_REMOVED }

    private class Card(val sev: String, val title: String, val rule: String = "r1", val loc: String = "com.x.A", val score: Int = 40)

    private fun report(
        cards: List<Card>, mustFixNos: List<Int>? = emptyList(), comps: List<String>? = null, perms: List<String>? = null,
        links: List<String>? = null, target: String? = null, min: String? = null
    ): String {
        val sb = StringBuilder("# APK ReLab report: com.x\n\n## Verdict\n\n")
        sb.append("- **VERDICT:** 0 critical\n")
        if (mustFixNos != null) {
            if (mustFixNos.isEmpty()) sb.append("- **MUST FIX:** no HIGH/CRITICAL finding passes the MUST FIX gate (a, b)\n")
            else {
                sb.append("- **MUST FIX:**\n")
                for (n in mustFixNos) sb.append("  - CHECK FIRST: #").append(n).append(" [").append(cards[n - 1].sev).append("] ").append(cards[n - 1].title).append(" in A (60/100 (P2)): fix it\n")
                sb.append("  - Evidence: 0.8 (source only)\n")
            }
        }
        sb.append("- **CONFIDENCE:** weak\n\n## Security scan\n\n### Findings\n\n")
        cards.forEachIndexed { i, c ->
            sb.append("#### ").append(i + 1).append(". [").append(c.sev).append("] ").append(c.title).append("\n\n")
            sb.append("- Location: `").append(c.loc).append("`\n")
            sb.append("- CWE: CWE-79 | OWASP: M4 x | MASVS: y | Confidence: HIGH | Rule: ").append(c.rule).append("\n")
            sb.append("- Priority: ").append(c.score).append("/100 (P2)\n- Why: z\n\n")
        }
        if (target != null) sb.append("<uses-sdk android:minSdkVersion=\"").append(min ?: "21").append("\" android:targetSdkVersion=\"").append(target).append("\" />\n\n")
        if (comps != null || perms != null) {
            sb.append("## Attack surface\n\nExported components: **").append(comps?.size ?: 0).append("**\n\n")
            sb.append("| Component | Kind | Intent-filter actions | Protection (permission a caller needs) |\n|---|---|---|---|\n")
            for (c in comps ?: emptyList()) sb.append(c).append("\n")
            sb.append("\n")
            if (perms != null && perms.isNotEmpty()) sb.append("**Permissions:** ").append(perms.joinToString(", ")).append("\n")
            sb.append("\n")
        }
        if (links != null) {
            sb.append("## Deep links\n\n").append(links.size).append(" link filter(s)\n\n| Links accepted | Activity | Launch mode | Verified App Link | Parameters |\n|---|---|---|---|---|\n")
            for (l in links) sb.append(l).append("\n")
            sb.append("\n")
        }
        sb.append("## Next section\n\ntext\n")
        return sb.toString()
    }

    private fun comp(name: String, kind: String = "activity", prot: String = "NONE (open to any app)") = "| `$name` | $kind | VIEW | $prot |"

    // ---- the 8 required tests ----

    @Test fun newFinding() {
        val r = ReportDiff.diff(report(listOf(Card("MEDIUM", "T1"))), report(listOf(Card("MEDIUM", "T1"), Card("HIGH", "T2", "r2", "com.x.B"))))
        assertEquals(1, r.diff.added.size)
        assertEquals("T2", r.diff.added[0].title)
        assertEquals(1, r.diff.same.size)
        assertEquals("REGRESSED", r.diff.verdict)
    }

    @Test fun resolvedFinding() {
        val r = ReportDiff.diff(report(listOf(Card("MEDIUM", "T1"), Card("HIGH", "T2", "r2", "com.x.B"))), report(listOf(Card("MEDIUM", "T1"))))
        assertEquals(1, r.diff.fixed.size)
        assertEquals("T2", r.diff.fixed[0].title)
        assertEquals("IMPROVED", r.diff.verdict)
        assertTrue(ReportDiff.markdown(r).contains("no longer reports"))
    }

    @Test fun severityUp() {
        val r = ReportDiff.diff(report(listOf(Card("MEDIUM", "T1"))), report(listOf(Card("HIGH", "T1"))))
        assertEquals(1, r.diff.worse.size)
        assertEquals(0, r.diff.added.size)
        assertEquals(0, r.diff.fixed.size)
    }

    @Test fun severityDown() {
        val r = ReportDiff.diff(report(listOf(Card("HIGH", "T1"))), report(listOf(Card("LOW", "T1"))))
        assertEquals(1, r.diff.better.size)
        assertEquals(0, r.diff.added.size)
        assertEquals(0, r.diff.fixed.size)
    }

    @Test fun noChange() {
        val c = listOf(Card("HIGH", "T1"), Card("LOW", "T2", "r2", "com.x.B"))
        val r = ReportDiff.diff(report(c, listOf(1), listOf(comp("com.x.M")), listOf("CAMERA"), listOf("| `https://a.b` | `com.x.M` | singleTask | yes | none |"), "34"),
            report(c, listOf(1), listOf(comp("com.x.M")), listOf("CAMERA"), listOf("| `https://a.b` | `com.x.M` | singleTask | yes | none |"), "34"))
        assertEquals("NO CHANGE", r.diff.verdict)
        assertEquals(2, r.diff.same.size)
        assertFalse(r.manifestChanged)
        assertEquals(0, r.mustFix!!.added.size + r.mustFix!!.removed.size)
    }

    @Test fun componentDelta() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A"))),
            report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A"), comp("com.x.Svc", "service"))))
        assertEquals(listOf("com.x.Svc"), r.components!!.added.map { it.name })
        assertTrue(r.components!!.removed.isEmpty())
        assertTrue(r.manifestChanged)
        assertTrue(ReportDiff.markdown(r).contains("exported component added: `com.x.Svc`"))
    }

    @Test fun permissionDelta() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("CAMERA", "INTERNET")),
            report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("INTERNET", "READ_SMS")))
        assertEquals(listOf("READ_SMS"), r.permissions!!.added)
        assertEquals(listOf("CAMERA"), r.permissions!!.removed)
    }

    @Test fun deepLinkDelta() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), links = listOf("| `a://x` | `com.x.M` | standard | n/a | none |")),
            report(listOf(Card("LOW", "T1")), links = listOf("| `a://x`, `https://new.host` | `com.x.M` | standard | n/a | none |")))
        assertEquals(listOf("com.x.M <- https://new.host"), r.deepLinks!!.added)
        assertTrue(r.deepLinks!!.removed.isEmpty())
    }

    // ---- twins ----

    @Test fun twinSameKeyDifferentSeverityIsWorseNotNewPlusResolved() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1"))), report(listOf(Card("CRITICAL", "T1"))))
        assertEquals(listOf(Status.WORSE), r.diff.changes.map { it.status })
    }

    @Test fun twinSameRuleDifferentLocationIsNewAndFixedNotSame() {
        val r = ReportDiff.diff(report(listOf(Card("MEDIUM", "T1", loc = "com.x.A"))), report(listOf(Card("MEDIUM", "T1", loc = "com.x.B"))))
        assertEquals(0, r.diff.same.size)
        assertEquals(1, r.diff.added.size)
        assertEquals(1, r.diff.fixed.size)
    }

    @Test fun twinCardNumbersMovingAreNotAChange() {
        val a = listOf(Card("HIGH", "T1"), Card("LOW", "T2", "r2", "com.x.B"))
        val b = listOf(Card("LOW", "T2", "r2", "com.x.B"), Card("HIGH", "T1"))     // numbers swapped
        val r = ReportDiff.diff(report(a, listOf(1)), report(b, listOf(2)))
        assertEquals("NO CHANGE", r.diff.verdict)
        assertTrue(r.mustFix!!.added.isEmpty() && r.mustFix!!.removed.isEmpty())    // MUST FIX is mapped number -> key inside each report
    }

    @Test fun twinRemovedPermissionIsReportedNotIgnored() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("CAMERA")),
            report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("INTERNET")))
        assertEquals(listOf("CAMERA"), r.permissions!!.removed)
        assertTrue(ReportDiff.markdown(r).contains("permission removed: CAMERA"))
    }

    @Test fun twinMissingSectionIsNotComparableNotEverythingRemoved() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("CAMERA")), report(listOf(Card("LOW", "T1"))))
        assertNull(r.components)
        assertNull(r.permissions)
        assertFalse(r.manifestChanged)
        assertTrue(ReportDiff.markdown(r).contains("Not comparable"))
    }

    @Test fun twinInfoCardsAreLeftOutLikeTheReportDoes() {
        val r = ReportDiff.diff(report(listOf(Card("INFO", "I1"))), report(listOf(Card("INFO", "I1"), Card("INFO", "I2", "r2"))))
        assertEquals("NO CHANGE", r.diff.verdict)
        assertEquals(0, r.diff.added.size)
    }

    @Test fun mustFixDeltaTracksCardsEnteringAndLeaving() {
        val a = listOf(Card("HIGH", "T1"), Card("HIGH", "T2", "r2", "com.x.B"))
        val r = ReportDiff.diff(report(a, listOf(1)), report(a, listOf(2)))
        assertEquals(listOf("T2"), r.mustFix!!.added.map { it.title })
        assertEquals(listOf("T1"), r.mustFix!!.removed.map { it.title })
        assertEquals(2, r.diff.same.size)                 // the cards themselves did not change
    }

    @Test fun twinNoMustFixLineIsNotComparable() {
        val c = listOf(Card("HIGH", "T1"))
        assertNull(ReportDiff.diff(report(c, null), report(c, listOf(1))).mustFix)
    }

    @Test fun protectionChangeOfSameComponentIsReported() {
        val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A", prot = "`perm.X` (signature)"))),
            report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A", prot = "NONE (open to any app)"))))
        assertEquals(1, r.protectionChanged.size)
        assertTrue(r.components!!.added.isEmpty())
        assertTrue(r.manifestChanged)
    }

    @Test fun sdkLevelsAreComparedOnlyWhenBothReportsShowThem() {
        val c = listOf(Card("LOW", "T1"))
        assertEquals(listOf("targetSdk 33 -> 35"), ReportDiff.diff(report(c, target = "33"), report(c, target = "35")).sdkChanges)
        assertTrue(ReportDiff.diff(report(c, target = "33"), report(c)).sdkChanges.isEmpty())
    }

    @Test fun garbageInputNeverThrows() {
        val r = ReportDiff.diff("not a report \u0000 ### \n#### x\n| `a|b` |", "")
        assertEquals(0, r.diff.changes.size)
        assertTrue(ReportDiff.diffFiles("/nonexistent/a.md", "/nonexistent/b.md").startsWith("error:"))
    }

    // ---- mutants: each switch must break at least one test above (run by hand below: the assertions flip) ----

    @Test fun mutantKeyComparisonOffMakesSeverityUpInvisible() {
        try {
            ReportDiff.COMPARE_KEYS = false
            val r = ReportDiff.diff(report(listOf(Card("MEDIUM", "T1"))), report(listOf(Card("HIGH", "T1"))))
            assertEquals(0, r.diff.worse.size)                // the positive test severityUp would fail
        } finally { reset() }
    }

    @Test fun mutantManifestDeltaOffMakesComponentDeltaInvisible() {
        try {
            ReportDiff.MANIFEST_DELTA = false
            val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A"))),
                report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A"), comp("com.x.Svc", "service"))))
            assertNull(r.components)
            assertFalse(r.manifestChanged)
        } finally { reset() }
    }

    @Test fun mutantRemovedNotReportedMakesPermissionRemovalInvisible() {
        try {
            ReportDiff.REPORT_REMOVED = false
            val r = ReportDiff.diff(report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("CAMERA")),
                report(listOf(Card("LOW", "T1")), comps = listOf(comp("com.x.A")), perms = listOf("INTERNET")))
            assertTrue(r.permissions!!.removed.isEmpty())
        } finally { reset() }
    }

    // ---- real pairs (private/, git-ignored: skipped when the files are not on this machine) ----

    private fun root(): File? {
        var d: File? = File(System.getProperty("user.dir")).absoluteFile
        while (d != null) { if (File(d, "private").isDirectory && File(d, "CLAUDE.md").isFile) return d; d = d.parentFile }
        return null
    }

    private fun realPair(a: String, b: String): Pair<File, File>? {
        val r = root() ?: return null
        val fa = File(r, a); val fb = File(r, b)
        return if (fa.isFile && fb.isFile) fa to fb else null
    }

    @Test fun realPairPaperlessTwoScannerVersions() {
        val p = realPair("private/qa120/paperless_121.md", "private/qa120/paperless_phase3_on.md")
        if (p == null) return   // private/ is git-ignored: not on this machine, not run
        val out = ReportDiff.diffFiles(p.first.path, p.second.path)
        assertFalse(out, out.startsWith("error:"))
        assertTrue(out.contains("# Before / After") && out.contains("## MUST FIX delta") && out.contains("## Manifest attack-surface delta"))
        val r = ReportDiff.diff(p.first.readText(), p.second.readText())
        assertTrue("old report parsed no cards", r.before.snapshot.entries.size > 10)
        assertTrue("new report parsed no cards", r.after.snapshot.entries.size > 10)
        assertNotNull(r.mustFix)
    }

    @Test fun realPairZulipTwoScannerVersions() {
        val p = realPair("private/hybrid/zulip_before.md", "private/hybrid/zulip_after.md")
        if (p == null) return   // private/ is git-ignored: not on this machine, not run
        val out = ReportDiff.diffFiles(p.first.path, p.second.path)
        assertFalse(out, out.startsWith("error:"))
        assertTrue(out.contains("# Before / After") && out.contains("## MUST FIX delta"))
        val r = ReportDiff.diff(p.first.readText(), p.second.readText())
        assertTrue(r.before.snapshot.entries.size > 10 && r.after.snapshot.entries.size > 10)
    }

    @Test fun realDeviceReportHasComponentsDeepLinksAndPermissions() {
        val r0 = root() ?: return
        val f = File(r0, "private/dev201/axis10.md"); if (!f.isFile) return
        val p = ReportDiff.parse(f.readText())
        assertTrue("components: ${p.components?.size}", (p.components?.size ?: 0) >= 10)
        assertTrue("permissions: ${p.permissions?.size}", (p.permissions?.size ?: 0) >= 10)
        assertTrue("deep links: ${p.deepLinks?.size}", (p.deepLinks?.size ?: 0) >= 5)
        assertNotNull(p.mustFix)
    }
}
