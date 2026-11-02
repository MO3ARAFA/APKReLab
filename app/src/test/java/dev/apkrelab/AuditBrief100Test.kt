package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.0.0: the audit_brief page (deterministic, numbered like get_findings) and the structural hint on cards of renamed code. */
class AuditBrief100Test {
    private fun f(title: String, type: String, sev: SecurityScanner.Severity, scope: SecurityScanner.Scope, reach: String = "", detail: String = "d") =
        SecurityScanner.Finding(sev, title, detail, "fix", type, 1, 0, "CWE-22").also { it.scope = scope; it.reach = reach; it.ruleId = "taint-flow" }

    @Test fun theBriefPutsReachableAppFindingsFirstAndNumbersThemLikeGetFindings() {
        val list = listOf(
            f("Lib path", "Lokhttp3/A;", SecurityScanner.Severity.HIGH, SecurityScanner.Scope.LIB, "YES"),
            f("Unreached path", "Lcom/x/B;", SecurityScanner.Severity.HIGH, SecurityScanner.Scope.APP, "NO"),
            f("Reached path", "Lcom/x/C;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.APP, "YES"),
            f("Low one", "Lcom/x/D;", SecurityScanner.Severity.LOW, SecurityScanner.Scope.APP, "YES"))
        val b = AuditBrief.build("com.x", list, emptyList(), "finished")
        val first = b.substringAfter("VERIFY FIRST").substringBefore("\n\n")
        assertTrue(first.indexOf("#3 ") in 0 until first.indexOf("#2 "))       // reachable before unreachable; the number is the position in the list
        assertFalse(first.contains("Lib path")); assertFalse(first.contains("Low one"))
        assertTrue(b.contains("HIGH 2")); assertTrue(b.contains("libraries 1"))
        assertEquals(b, AuditBrief.build("com.x", list, emptyList(), "finished"))  // the same input, the same page
        assertTrue(AuditBrief.build("com.x", emptyList(), emptyList(), "").startsWith("No scan results"))
    }

    @Test fun mergedClassFlowsAndSignalOnlyControlsAreNamed() {
        val merged = f("Through m42", "Lg34;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF, "YES", "The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes")
        val b = AuditBrief.build("com.x", listOf(merged), emptyList(), "")
        assertTrue(b.contains("THROUGH R8-MERGED CODE")); assertTrue(b.contains("#1 Through m42"))
        assertTrue(b.contains("AUTH-1"))                                           // known only by posture signals
        val plain = AuditBrief.build("com.x", listOf(f("Plain", "Lcom/x/B;", SecurityScanner.Severity.HIGH, SecurityScanner.Scope.APP)), emptyList(), "")
        assertFalse(plain.contains("THROUGH R8-MERGED CODE"))                     // twin
    }

    @Test fun renamedCodeCardsGetTheStructuralHintOnce() {
        val inMerged = f("A", "Lm42;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF)
        val inHolder = f("B", "Lct1;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF)
        val viaMerged = f("C", "Lg34;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF).also { it.sourceMethod = "Lm42;->c()V" }
        val plainObf = f("D", "Lzz;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF)
        val app = f("E", "Lcom/x/E;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.APP)
        val sdk = f("F", "Laq8;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.LIB)
        val all = listOf(inMerged, inHolder, viaMerged, plainObf, app, sdk)
        assertEquals(4, ClassTools.obfHint(all, setOf("Lm42;"), setOf("Lct1;")))
        assertTrue(inMerged.detail.contains("class-id field")); assertTrue(inHolder.detail.contains("static merger"))
        assertTrue(viaMerged.detail.contains("comes from a class R8 merged")); assertTrue(plainObf.detail.contains("no single bundled library"))
        assertFalse(app.detail.contains(ClassTools.OBF_HINT_MARK)); assertFalse(sdk.detail.contains(ClassTools.OBF_HINT_MARK))   // twins
        assertEquals(0, ClassTools.obfHint(all, setOf("Lm42;"), setOf("Lct1;")))   // a second pass adds nothing
    }

    // 3.0.0: the packages a renamed class names are printed inside the card, so nobody has to run classify_class by hand
    private val obfText = """
        .class public Lzz;
        .super Ljava/lang/Object;
        invoke-virtual {v0}, Lcom/facebook/appevents/AppEventsLogger;->flush()V
        invoke-virtual {v0}, Lcom/facebook/appevents/internal/Foo;->bar()V
        invoke-virtual {v0}, Lcom/google/firebase/Bar;->baz()V
        invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
        invoke-virtual {v0}, Lcom/acme/app/Own;->x()V
        invoke-virtual {v0}, Lab;->y()V
    """.trimIndent()

    @Test fun renamedCodeCardNamesTheLibraryPackagesItUses() {
        val p = ClassTools.namedPackages("Lzz;", obfText, "com.acme.app")
        assertTrue(p, p.startsWith("com.facebook.appevents (2)")); assertTrue(p, p.contains("com.google.firebase (1)"))
        assertFalse(p, p.contains("android")); assertFalse(p, p.contains("acme")); assertFalse(p, p.contains("ab"))   // twins: platform, own package, renamed roots stay out
        val c = f("D", "Lzz;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF)
        ClassTools.obfHint(listOf(c), emptySet(), emptySet()) { ClassTools.namedPackages(it, obfText, "com.acme.app") }
        assertTrue(c.detail, c.detail.contains("Its code names the packages: com.facebook.appevents (2)")); assertFalse(c.detail.contains("Run classify_class to see"))
        val none = f("E", "Lyy;", SecurityScanner.Severity.MEDIUM, SecurityScanner.Scope.OBF)
        ClassTools.obfHint(listOf(none), emptySet(), emptySet()) { "" }      // no library named: the old sentence stays
        assertTrue(none.detail.contains("Run classify_class to see which packages"))
    }
}
