package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import dev.apkrelab.ir.SmaliParser
import dev.apkrelab.ir.SsaBridge
import dev.apkrelab.ir.TaintIr
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 2.2 session 2: three shapes seen in real device reports (a non-exported WebView activity, an R8 dispatcher in front of a WebView sink, an obfuscated
 * trust-all HostnameVerifier that the app installs), each with a twin. The METHOD names are rules; the fixtures are hand-written smali + a manifest fragment.
 * Test-only: no engine code changes.
 *
 * The helper [run] repeats what the app does after a scan, in the same order, with the pieces that are plain Kotlin / Java:
 * scanSmali (rule cards) -> SsaBridge.newFlows (data-flow cards, reach label `YES~` when the item went through a hub, as MainActivity.ssaFindings does)
 * -> FindingPolish.apply -> dedupe -> restoreInstalledTls -> lowerUnforwardedPrivateIntentFlows -> Verdict.build (the MUST FIX gate).
 * NOT repeated: MainActivity.reachPass (Android-only). Where a rule card needs a reach label, [reached] stands in for it (the label the device pass gives a
 * class that an exported entry reaches), and SandboxScan's own mirror for a rule card inside an exported component's class is repeated.
 */
class DeviceReportShapesTest {

    private val pkg = "com.app.shape"

    /** The app always has an exported launcher activity (the graph's entry list is the exported components, as in every real app); [WebActivity] is the one under test. */
    private fun manifest(exported: Boolean) =
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"$pkg\">\n <application>\n" +
            "  <activity android:name=\"$pkg.Main\" android:exported=\"true\">\n" +
            "   <intent-filter><action android:name=\"android.intent.action.MAIN\"/><category android:name=\"android.intent.category.LAUNCHER\"/></intent-filter>\n  </activity>\n" +
            "  <activity android:name=\"$pkg.WebActivity\" android:exported=\"$exported\"/>\n </application>\n</manifest>\n"

    private val mainType = "Lcom/app/shape/Main;"
    /** The launcher reaches the screen under test by a plain call (a method-call path, not a data flow: it passes no value into the Intent that starts the screen). */
    private val mainSmali = ".class public $mainType\n.super Landroid/app/Activity;\n.method protected onCreate(Landroid/os/Bundle;)V\n    .locals 2\n" +
        "    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n" +
        "    new-instance v0, Lcom/app/shape/WebActivity;\n    invoke-direct {v0}, Lcom/app/shape/WebActivity;-><init>()V\n" +
        "    const/4 v1, 0x0\n    invoke-virtual {v0, v1}, Lcom/app/shape/WebActivity;->onCreate(Landroid/os/Bundle;)V\n    return-void\n.end method\n"

    private class Out(val all: List<Finding>, val mustFix: String) {
        fun card(titlePart: String): Finding = all.filter { it.title.contains(titlePart) }.minByOrNull { it.severity.rank }
            ?: throw AssertionError("no card with '$titlePart' in " + all.map { "[" + it.severity.label + "] " + it.title })
        fun cards(titlePart: String) = all.filter { it.title.contains(titlePart) }
    }

    private fun run(manifest: String, classes: List<Pair<String, String>>, reached: Set<String> = emptySet()): Out {
        SecurityScanner.tlsInstalled.clear(); TaintIr.clearForwarded()
        val mc = ManifestContext(manifest)
        val all = ArrayList<Finding>()
        for ((i, c) in classes.withIndex()) all.addAll(SecurityScanner.scanSmali(c.first, i, c.second, pkg))
        val entries = mc.exportedComponents.map { mc.smaliTypeOf(it) }
        val idx = classes.withIndex().associate { it.value.first to it.index }
        val items = SsaBridge.newFlows(classes.map { SmaliParser.parse(it.second) }, entries, ArrayList<TaintIr.Old>())
        for (item in items) {
            val sev = Severity.values().firstOrNull { it.label == item.sev } ?: Severity.HIGH
            val f = Finding(sev, item.title, item.detail, item.fix, item.classType, idx[item.classType] ?: -1, item.at, item.cwe)
            f.ruleId = "taint-flow"; f.confidence = item.confidence
            f.reach = if (item.reachable) (if (item.viaHub) "YES~" else "YES") else "NO"        // as MainActivity.ssaFindings and SandboxScan
            if (item.reachable) f.chain = "Entry: " + item.entry + "\nPath: " + item.path
            f.scope = SecurityScanner.scopeOfText(item.classType, pkg, classes.firstOrNull { it.first == item.classType }?.second ?: "")
            all.addAll(FindingPolish.apply(listOf(f), item.classType, false))
        }
        val final = SecurityScanner.dedupe(all)
        FindingPolish.restoreInstalledTls(final)                                            // as MainActivity, after the scan loop
        val entryTypes = entries.filter { it.isNotEmpty() }.toSet()
        for (f in final) {                                                                  // the reach pass: SandboxScan's mirror for a rule card in an exported class + the stand-in
            val t = f.classType ?: continue
            val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
            if (f.reach.isEmpty() && f.clsIndex >= 0 && FindingPolish.wantsReach(f) && (outer in entryTypes || outer in reached)) {
                f.reach = "YES"; f.chain = "Entry: exported activity (no permission)\nPath: " + outer
            }
        }
        FindingPolish.lowerUnforwardedPrivateIntentFlows(final, FindingPolish.privateActivitiesAndServices(mc), TaintIr.forwardedComponents(), TaintIr.openRedirectorSeen())
        val cards = ReportBuilder.reportable(final)
        val lines = Verdict.build(cards, emptyList(), Verdict.Coverage(deepScan = true, classesScanned = classes.size), pkg, final, guard = PermissionGuard(mc))
        return Out(final, lines.mustFix.joinToString("\n"))
    }

    // ------------------------------------------------------------------------------------------------ shape 1: WebView activity, exported or not

    private val webActivity = "Lcom/app/shape/WebActivity;"
    private val webActivitySmali = """
.class public $webActivity
.super Landroid/app/Activity;
.field private web:Landroid/webkit/WebView;
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Lcom/app/shape/WebActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    iget-object v1, p0, Lcom/app/shape/WebActivity;->web:Landroid/webkit/WebView;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

    @Test fun nonExportedWebViewActivityIsMedium() {
        val o = run(manifest(exported = false), listOf(mainType to mainSmali, webActivity to webActivitySmali))
        val f = o.card("loaded into a WebView")
        assertEquals(Severity.MEDIUM, f.severity)                                   // the SSA engine lowers an Intent flow in a component the manifest does not export
        assertEquals("LOW", f.confidence)
        assertTrue(f.detail, f.detail.contains("component that the manifest does not export"))
        assertEquals("YES", f.reach)                                                // the launcher CALLS the screen: a call path, not a data flow. (YES~ is what FindingPolish.lowerUnforwardedPrivateIntentFlows gives a rule card: PrivateComponentCardsTest)
        assertTrue(o.mustFix, o.mustFix.startsWith("no HIGH/CRITICAL finding passes"))
    }

    @Test fun exportedWebViewActivityFromIntentIsHigh() {
        val o = run(manifest(exported = true), listOf(mainType to mainSmali, webActivity to webActivitySmali))
        val f = o.card("loaded into a WebView")
        assertEquals(Severity.HIGH, f.severity)
        assertEquals("YES", f.reach)
        assertEquals("HIGH", f.confidence)
        assertFalse(f.detail, f.detail.contains("component that the manifest does not export"))
        assertTrue(o.mustFix, o.mustFix.contains("Untrusted input is loaded into a WebView"))
    }

    // ------------------------------------------------------------------------------------------------ shape 2: an R8 dispatcher in front of a WebView sink

    private val sinkClass = "Lq/R0;"

    /** R0.go() reads the Intent extra itself and loads it (in the Axis Pay report the value is read after the dispatcher too: the card's origin method is behind the hub). */
    private fun target(i: Int) = ".class public Lq/R$i;\n.super Ljava/lang/Object;\n" +
        ".field public static w:Landroid/webkit/WebView;\n" +
        ".method public static go()V\n    .locals 6\n" +
        (if (i == 0) "    new-instance v5, Landroid/content/Intent;\n    invoke-direct {v5}, Landroid/content/Intent;-><init>()V\n    const-string v1, \"html\"\n" +
            "    invoke-virtual {v5, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1\n" +
            "    sget-object v0, Lq/R0;->w:Landroid/webkit/WebView;\n    const/4 v2, 0x0\n    const-string v3, \"text/html\"\n    const-string v4, \"utf-8\"\n" +
            "    invoke-virtual {v0, v2, v1, v3, v4, v2}, Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V\n" else "") +
        "    return-void\n.end method\n"

    /** D.run(which): a packed-switch whose cases each call another class (the shape R8 gives merged lambdas: ONE method, [CallGraph.HUB_FANOUT] distinct app classes). */
    private fun dispatcher(): String {
        val sb = StringBuilder(".class public Lq/D;\n.super Ljava/lang/Object;\n.method public static run(I)V\n    .locals 0\n    packed-switch p0, :pswitch_data\n")
        for (i in 0 until CALLEES) sb.append("    :pswitch_$i\n    invoke-static {}, Lq/R$i;->go()V\n    goto :done\n")
        sb.append("    :done\n    return-void\n    :pswitch_data\n    .packed-switch 0x0\n")
        for (i in 0 until CALLEES) sb.append("        :pswitch_$i\n")
        return sb.append("    .end packed-switch\n.end method\n").toString()
    }

    private val CALLEES = dev.apkrelab.ir.CallGraph.HUB_FANOUT

    /** The exported launcher calls the dispatcher, or straight the class that holds the sink. */
    private fun launcher(viaDispatcher: Boolean) = ".class public $mainType\n.super Landroid/app/Activity;\n.method protected onCreate(Landroid/os/Bundle;)V\n    .locals 2\n" +
        "    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n" +
        (if (viaDispatcher) "    const/4 v0, 0x0\n    invoke-static {v0}, Lq/D;->run(I)V\n" else "    invoke-static {}, Lq/R0;->go()V\n") +
        "    return-void\n.end method\n"

    private fun shape2(viaDispatcher: Boolean): Out {
        val cls = ArrayList<Pair<String, String>>()
        cls.add(mainType to launcher(viaDispatcher))
        if (viaDispatcher) cls.add("Lq/D;" to dispatcher())
        for (i in 0 until CALLEES) cls.add("Lq/R$i;" to target(i))
        return run(manifest(exported = false), cls)
    }

    @Test fun r8DispatcherKeepsReachApproximateButStaysInMustFix() {
        val o = shape2(true)
        val f = o.card("loaded into a WebView")
        assertEquals("YES~", f.reach)                                               // every path to the method that reads the value goes through the switch method
        assertEquals(Severity.HIGH, f.severity)                                     // the sink rule's severity is not lowered
        assertTrue(f.detail, f.detail.contains("Every call path from an exported component goes through"))
        assertTrue(o.mustFix, o.mustFix.contains("Untrusted input is loaded into a WebView"))   // MustFixGate accepts YES and YES~ (MustFixGate.check: reachable)
    }

    @Test fun directCallChainKeepsExactReachInMustFix() {
        val o = shape2(false)
        val f = o.card("loaded into a WebView")
        assertEquals("YES", f.reach)
        assertEquals(Severity.HIGH, f.severity)
        assertFalse(f.detail, f.detail.contains("Every call path from an exported component goes through"))
        assertTrue(o.mustFix, o.mustFix.contains("Untrusted input is loaded into a WebView"))
    }

    // ------------------------------------------------------------------------------------------------ shape 3: an obfuscated trust-all HostnameVerifier

    private val trustAll = "Lar/c;"
    private val trustAllSmali = ".class public $trustAll\n.super Ljava/lang/Object;\n.implements Ljavax/net/ssl/HostnameVerifier;\n" +
        ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n" +
        ".method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"

    private val netType = "Lcom/app/shape/Net;"
    private fun net(installs: Boolean) = ".class public $netType\n.super Ljava/lang/Object;\n.method public static setup()V\n    .locals 1\n" +
        (if (installs) "    new-instance v0, Lar/c;\n    invoke-direct {v0}, Lar/c;-><init>()V\n    invoke-static {v0}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V\n" else "") +
        "    return-void\n.end method\n"

    @Test fun trustAllHostnameVerifierInstantiatedInAppCodeIsHigh() {
        val o = run(manifest(exported = false), listOf(mainType to mainSmali, trustAll to trustAllSmali, netType to net(true)))
        val f = o.card("Hostname verification disabled")
        assertEquals(SecurityScanner.Scope.OBF, f.scope)
        assertEquals(Severity.HIGH, f.severity)                                      // lowered to MEDIUM as obfuscated code, then restored: the app installs it
        assertTrue(f.adjusted, f.adjusted.startsWith("Restored one level"))
    }

    @Test fun unusedTrustAllHostnameVerifierStaysLoweredToMedium() {
        val o = run(manifest(exported = false), listOf(mainType to mainSmali, trustAll to trustAllSmali, netType to net(false)))
        val f = o.card("Hostname verification disabled")
        assertEquals(SecurityScanner.Scope.OBF, f.scope)
        assertEquals(Severity.MEDIUM, f.severity)                                    // stays one level down: nothing in the app installs the class
        assertTrue(f.adjusted, f.adjusted.startsWith("Lowered one level: obfuscated"))
        assertFalse(f.adjusted, f.adjusted.contains("Restored"))
    }
}
