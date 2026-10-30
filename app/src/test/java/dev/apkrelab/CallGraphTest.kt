package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.50.1: JVM unit tests for the call graph (SecurityScanner.collectEdges / trace / componentActions) and the reach policy
 * (FindingPolish.wantsReach / applyReach). They use tiny hand-written smali, no APK, no device. Run: ./gradlew testDebugUnitTest
 */
class CallGraphTest {

    private fun method(sig: String, vararg lines: String): String =
        ".method public $sig\n    .locals 3\n" + lines.joinToString("") { "    $it\n" } + "    return-void\n.end method\n"

    private fun smali(type: String, vararg methods: String): String =
        ".class public $type\n.super Ljava/lang/Object;\n\n" + methods.joinToString("\n")

    /** Classes by index; builds the call index the same way the Deep scan does. */
    private class Graph(val types: List<String>, texts: List<String>) {
        val idx = SecurityScanner.CallIndex()

        init {
            for (i in texts.indices) SecurityScanner.collectEdges(types[i], i, texts[i], idx)
        }

        fun trace(
            sinkCls: Int, sinkMethod: String, entries: Set<Int>,
            actions: Map<Int, List<String>> = emptyMap(), maxDepth: Int = 6
        ): SecurityScanner.Trace = SecurityScanner.trace(
            idx, types[sinkCls] + "->" + sinkMethod, sinkCls,
            { ci -> if (ci in entries) "exported " + types[ci] else null },
            typeOf = { ci -> types.getOrNull(ci) },
            actionsOf = { ci -> actions[ci] ?: emptyList() },
            maxDepth = maxDepth
        )
    }

    private val intentCtorCls = "invoke-direct {v1, p0, v0}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V"
    private val intentCtorStr = "invoke-direct {v1, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V"

    // ---------- plain invoke edges ----------

    @Test fun directCallChainReachesEntry() {
        val g = Graph(
            listOf("Lt/A;", "Lt/B;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("m()V", "invoke-static {}, Lt/B;->m()V")),
                smali("Lt/B;", method("m()V", "invoke-static {}, Lt/C;->run()V")),
                smali("Lt/C;", method("run()V"))
            )
        )
        val tr = g.trace(2, "run()V", setOf(0))
        assertNotNull(tr.entry)
        assertEquals(3, tr.hops.size)
    }

    @Test fun noEdgeMeansNoPath() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(smali("Lt/A;", method("m()V")), smali("Lt/C;", method("run()V")))
        )
        assertNull(g.trace(1, "run()V", setOf(0)).entry)
    }

    @Test fun sinkInsideExportedClassIsReachedAtOnce() {
        val g = Graph(listOf("Lt/A;"), listOf(smali("Lt/A;", method("run()V"))))
        val tr = g.trace(0, "run()V", setOf(0))
        assertNotNull(tr.entry)
        assertEquals(1, tr.hops.size)
    }

    @Test fun depthLimitIsRespected() {
        // c0 (exported) -> c1 -> ... -> c7 (sink): 7 calls up from the sink
        val types = (0..7).map { "Lt/K$it;" }
        val texts = (0..7).map { i ->
            if (i < 7) smali(types[i], method("m()V", "invoke-static {}, ${types[i + 1]}->m()V")) else smali(types[i], method("m()V"))
        }
        val g = Graph(types, texts)
        assertNull(g.trace(7, "m()V", setOf(0)).entry)
        assertNotNull(g.trace(7, "m()V", setOf(0), maxDepth = 8).entry)
    }

    // ---------- 0.49.4: explicit launches ----------

    @Test fun explicitLaunchLinksLauncherToLaunchedComponent() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-class v0, Lt/C;", intentCtorCls)),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNotNull(g.trace(1, "run()V", setOf(0)).entry)
    }

    @Test fun classConstantWithoutIntentIsNotALaunch() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-class v0, Lt/C;")),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNull(g.trace(1, "run()V", setOf(0)).entry)
    }

    @Test fun innerClassOfLaunchedComponentIsReached() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C\$Inner;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-class v0, Lt/C;", intentCtorCls)),
                smali("Lt/C\$Inner;", method("run()V"))
            )
        )
        assertNotNull(g.trace(1, "run()V", setOf(0)).entry)
    }

    // ---------- 0.50.0: implicit custom actions ----------

    @Test fun customActionLinksSenderToDeclaringComponent() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-string v0, \"t.action.OPEN\"", intentCtorStr)),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNotNull(g.trace(1, "run()V", setOf(0), actions = mapOf(1 to listOf("t.action.OPEN"))).entry)
    }

    @Test fun setActionVariantAlsoLinks() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali(
                    "Lt/A;",
                    method(
                        "go()V", "const-string v0, \"t.action.OPEN\"",
                        "invoke-virtual {v1, v0}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;"
                    )
                ),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNotNull(g.trace(1, "run()V", setOf(0), actions = mapOf(1 to listOf("t.action.OPEN"))).entry)
    }

    @Test fun actionStringWithoutAnIntentIsIgnored() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-string v0, \"t.action.OPEN\"")),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNull(g.trace(1, "run()V", setOf(0), actions = mapOf(1 to listOf("t.action.OPEN"))).entry)
    }

    @Test fun frameworkActionsAreNeverLinked() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-string v0, \"android.intent.action.VIEW\"", intentCtorStr)),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNull(g.trace(1, "run()V", setOf(0), actions = mapOf(1 to listOf("android.intent.action.VIEW"))).entry)
    }

    @Test fun differentActionDoesNotLink() {
        val g = Graph(
            listOf("Lt/A;", "Lt/C;"),
            listOf(
                smali("Lt/A;", method("go()V", "const-string v0, \"t.action.OTHER\"", intentCtorStr)),
                smali("Lt/C;", method("run()V"))
            )
        )
        assertNull(g.trace(1, "run()V", setOf(0), actions = mapOf(1 to listOf("t.action.OPEN"))).entry)
    }

    @Test fun componentActionsReadsCustomActionsOnly() {
        val xml = """
            <manifest package="t">
              <application>
                <activity android:name="t.Web" android:exported="false">
                  <intent-filter>
                    <action android:name="t.action.WEBVIEW" />
                    <action android:name="android.intent.action.VIEW" />
                  </intent-filter>
                </activity>
                <activity android:name=".Plain" />
                <receiver android:name="Rx">
                  <intent-filter><action android:name="t.action.PING" /></intent-filter>
                </receiver>
              </application>
            </manifest>
        """.trimIndent()
        val m = SecurityScanner.componentActions(xml, "t")
        assertEquals(listOf("t.action.WEBVIEW"), m["Lt/Web;"])
        assertEquals(listOf("t.action.PING"), m["Lt/Rx;"])
        assertNull(m["Lt/Plain;"])
    }

    // ---------- 0.49.5: which findings are traced / annotated ----------

    private fun finding(rule: String, sev: SecurityScanner.Severity, scope: SecurityScanner.Scope, cls: Int = 3, detail: String = "d"): SecurityScanner.Finding {
        val f = SecurityScanner.Finding(sev, "t", detail, "r", "Lt/A;", cls, 10)
        f.ruleId = rule
        f.scope = scope
        return f
    }

    @Test fun wantsReachPolicy() {
        val app = SecurityScanner.Scope.APP
        val lib = SecurityScanner.Scope.LIB
        val H = SecurityScanner.Severity.HIGH
        val M = SecurityScanner.Severity.MEDIUM
        val L = SecurityScanner.Severity.LOW
        assertTrue(FindingPolish.wantsReach(finding("taint-flow", H, lib)))
        assertTrue(FindingPolish.wantsReach(finding("taint-flow", M, app)))      // 0.73.0: taint-flow is in REACH_RULES, MEDIUM APP flows are traced (the old assertion was stale)
        assertTrue(!FindingPolish.wantsReach(finding("taint-flow", L, app)))
        assertTrue(FindingPolish.wantsReach(finding("shell-exec", M, app)))
        assertTrue(!FindingPolish.wantsReach(finding("shell-exec", M, lib)))
        assertTrue(!FindingPolish.wantsReach(finding("shell-exec", L, app)))
        assertTrue(!FindingPolish.wantsReach(finding("crypto-hardcoded-key", H, app)))
        assertTrue(!FindingPolish.wantsReach(finding("shell-exec", M, app, cls = -1)))
    }

    @Test fun applyReachAddsNoteOnlyWhereItMeans() {
        val app = SecurityScanner.Scope.APP
        val M = SecurityScanner.Severity.MEDIUM
        val a = finding("shell-exec", M, app).also { it.reach = "NO" }
        val b = finding("external-storage", M, app).also { it.reach = "NO" }
        val c = finding("shell-exec", M, app).also { it.reach = "YES" }
        val d = finding("taint-flow", M, app, detail = "Data from SharedPreferences reaches x").also { it.reach = "NO" }
        val e = finding("taint-flow", M, app, detail = "Data from Intent.getData() reaches x").also { it.reach = "NO" }
        FindingPolish.applyReach(listOf(a, b, c, d, e))
        assertTrue(a.adjusted.startsWith("Not reached"))
        assertEquals("", b.adjusted)
        assertEquals("", c.adjusted)
        assertEquals("", d.adjusted)
        assertTrue(e.adjusted.startsWith("Not reached"))
        assertEquals(SecurityScanner.Severity.MEDIUM, a.severity)   // never lowered
    }

    // ---------- 0.50.2: approximate class-level trace ----------

    private fun Graph.approx(sinkCls: Int, sinkMethod: String, entries: Set<Int>, hubLimit: Int = 25): SecurityScanner.Trace =
        SecurityScanner.traceApprox(
            idx, types[sinkCls] + "->" + sinkMethod, sinkCls,
            { ci -> if (ci in entries) "exported " + types[ci] else null },
            typeOf = { ci -> types.getOrNull(ci) }, hubLimit = hubLimit
        )

    @Test fun approxStepsOverAMethodThatTheExactTraceCannotFollow() {
        // A.m calls B.other(); the sink is B.run(). Nothing calls B.run(), so the exact trace fails, but A calls into class B.
        val g = Graph(
            listOf("Lt/A;", "Lt/B;"),
            listOf(
                smali("Lt/A;", method("m()V", "invoke-static {}, Lt/B;->other()V")),
                smali("Lt/B;", method("other()V"), method("run()V"))
            )
        )
        assertNull(g.trace(1, "run()V", setOf(0)).entry)
        val ap = g.approx(1, "run()V", setOf(0))
        assertNotNull(ap.entry)
        assertTrue(ap.approximate)
        assertEquals(2, ap.hops.size)
    }

    @Test fun approxNeedsSomeClassLevelLink() {
        val g = Graph(
            listOf("Lt/A;", "Lt/B;"),
            listOf(smali("Lt/A;", method("m()V")), smali("Lt/B;", method("run()V")))
        )
        assertNull(g.approx(1, "run()V", setOf(0)).entry)
    }

    @Test fun approxFrameworkCallsAreNotLinks() {
        val g = Graph(
            listOf("Lt/A;", "Lt/B;"),
            listOf(smali("Lt/A;", method("m()V", "invoke-static {}, Landroid/util/Log;->d()V")), smali("Lt/B;", method("run()V")))
        )
        assertNull(g.approx(1, "run()V", setOf(0)).entry)
    }

    @Test fun approxInnerClassCallCountsAsItsOuterClass() {
        val g = Graph(
            listOf("Lt/A;", "Lt/B;"),
            listOf(
                smali("Lt/A;", method("m()V", "invoke-static {}, Lt/B\$1;->go()V")),
                smali("Lt/B;", method("run()V"))
            )
        )
        assertNotNull(g.approx(1, "run()V", setOf(0)).entry)
    }

    @Test fun approxHubClassIsNotExpandedBeyondTheFirstLevel() {
        // E (exported) -> Hub; Hub is called by 3 classes; sink S is called by Hub. With hubLimit = 2 the walk must stop at Hub.
        val types = listOf("Lt/E;", "Lt/Hub;", "Lt/X1;", "Lt/X2;", "Lt/X3;", "Lt/S;")
        val g = Graph(
            types,
            listOf(
                smali("Lt/E;", method("m()V", "invoke-static {}, Lt/Hub;->h()V")),
                smali("Lt/Hub;", method("h()V", "invoke-static {}, Lt/S;->other()V")),
                smali("Lt/X1;", method("m()V", "invoke-static {}, Lt/Hub;->h()V")),
                smali("Lt/X2;", method("m()V", "invoke-static {}, Lt/Hub;->h()V")),
                smali("Lt/X3;", method("m()V", "invoke-static {}, Lt/Hub;->h()V")),
                smali("Lt/S;", method("other()V"), method("run()V"))
            )
        )
        assertNotNull(g.approx(5, "run()V", setOf(0), hubLimit = 25).entry)
        assertNull(g.approx(5, "run()V", setOf(0), hubLimit = 2).entry)
    }

    @Test fun approxClassThatIsItselfExportedIsReachedAtOnce() {
        val g = Graph(listOf("Lt/A;"), listOf(smali("Lt/A;", method("run()V"))))
        val ap = g.approx(0, "run()V", setOf(0))
        assertNotNull(ap.entry)
        assertEquals(1, ap.hops.size)
    }
}
