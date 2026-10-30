package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.106.0: renamed root-package classes given to the one bundled SDK whose classes name them, with the guards measured on R8-repackaged real apps. */
class SdkAttributionTest {
    private val pkg = "com.myapp"
    private fun cls(type: String, body: String = "", sup: String = "Ljava/lang/Object;") = ".class public $type\n.super $sup\n$body\n"
    private fun calls(vararg types: String) = ".method public run()V\n    .locals 1\n" + types.joinToString("") { "    invoke-static {}, $it->go()V\n" } + "    return-void\n.end method\n"
    private fun isLib(t: String) = SecurityScanner.scopeOf(t, pkg) == SecurityScanner.Scope.LIB

    private fun run(vararg classes: Pair<String, String>): Map<String, String> {
        val a = SdkAttribution(pkg)
        for ((t, x) in classes) a.observe(t, x)
        return a.compute(::isLib)
    }

    @Test fun aRenamedClassNamedByOneSdkIsThatSdksAndItsHelpersFollow() {
        val r = run(
            "Lcom/google/firebase/analytics/FirebaseAnalytics;" to cls("Lcom/google/firebase/analytics/FirebaseAnalytics;", calls("Laq8;")),
            "Laq8;" to cls("Laq8;", calls("Lbx2;")),
            "Lbx2;" to cls("Lbx2;", ".field public a:I\n"),                        // named only by aq8: one hop
            "Lq1;" to cls("Lq1;", calls("Landroid/os/Bundle;")))                  // twin: named by nobody (the app's own entry, or dead): not attributed
        assertEquals("com.google.firebase", r["Laq8;"]); assertEquals("com.google.firebase", r["Lbx2;"] ?: "missing")
        assertNull(r["Lq1;"])
        assertEquals("com.google.firebase", SdkAttribution.family("Lcom/google/firebase/x/Y;")); assertEquals("com.moengage", SdkAttribution.family("Lcom/moengage/push/T;"))
    }

    @Test fun mergedOrAppBoundClassesAndTwoSdksAreNeverAttributed() {
        val lib = "Lcom/moengage/pushbase/PushTracker;"
        val r = run(
            lib to cls(lib, calls("Lu5;", "Lm42;", "Lk4;", "Lct1;", "Lj4;", "Lw;", "Lv9;")),
            "Lcom/braze/Braze;" to cls("Lcom/braze/Braze;", calls("Lj4;")),
            "Lcom/myapp/Main;" to cls("Lcom/myapp/Main;", calls("Lw;", "Lv9;")),
            "Lv9;" to cls("Lv9;"),                                                     // the SDK and the app's own Main name it (a devirtualised callback)
            "Lu5;" to cls("Lu5;", calls("Landroid/os/Bundle;")),
            "Lm42;" to cls("Lm42;", ".field public final synthetic b:I\n"),            // R8's class-id discriminator
            "Lw;" to cls("Lw;", ".field public final synthetic p:B\n"),                // a byte one; and the app's Main names it too
            "Lk4;" to cls("Lk4;", "    sget-object v0, Lcom/myapp/data/Cache;->x:Lcom/myapp/data/Cache;\n"),   // names the app's package
            "Lct1;" to cls("Lct1;", (1..12).joinToString("") { ".method public static m$it()V\n    return-void\n.end method\n" }),   // static class merger
            "Lj4;" to cls("Lj4;"))                                                     // two SDKs name it
        assertEquals("com.moengage", r["Lu5;"])
        for (t in listOf("Lm42;", "Lw;", "Lk4;", "Lct1;", "Lj4;", "Lv9;")) assertNull(t, r[t])
        // twin of the static holder: a class with a few statics, or with instance state, is attributed
        val r2 = run(lib to cls(lib, calls("Lh1;", "Lh2;")), "Lh1;" to cls("Lh1;", (1..3).joinToString("") { ".method public static m$it()V\n    return-void\n.end method\n" }),
            "Lh2;" to cls("Lh2;", ".field public a:I\n" + (1..12).joinToString("") { ".method public static m$it()V\n    return-void\n.end method\n" }))
        assertEquals(2, r2.size)
    }

    @Test fun aHelperAlsoNamedByAnUnattributedRenamedClassIsNotGivenAway() {
        val lib = "Lcom/moengage/pushbase/PushTracker;"
        val r = run(lib to cls(lib, calls("Lu5;")), "Lu5;" to cls("Lu5;", calls("Lh9;")), "La;" to cls("La;", calls("Lh9;")), "Lh9;" to cls("Lh9;"))
        assertEquals("com.moengage", r["Lu5;"]); assertNull(r["Lh9;"])       // h9 is also used by `a`, which nothing attributes: it may be the app's
    }

    @Test fun thePostureTableCountsAnAttributedClassAsLibrary() {
        PostureScanner.clear(); PostureScanner.clearApk()
        val su = ".method public static t()V\n    .locals 1\n    const-string v0, \"/system/xbin/su\"\n    return-void\n.end method\n"
        PostureScanner.observe("Laq8;", cls("Laq8;", su), pkg); PostureScanner.observe("Lzz1;", cls("Lzz1;", su), pkg)
        PostureScanner.sdkTypes = setOf("Laq8;")
        val row = PostureScanner.rows().first { it.sig.id == "root-paths" }
        assertEquals(listOf("Laq8;"), row.lib); assertEquals(listOf("Lzz1;"), row.obf)
        PostureScanner.clearApk(); assertTrue(PostureScanner.rows().first { it.sig.id == "root-paths" }.lib.isEmpty())
        PostureScanner.clear()
    }
}
