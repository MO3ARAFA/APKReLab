package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.93.0: each scenario needs the findings that make its chain real; every pattern has twins that must produce nothing. */
class AttackScenariosTest {
    private val pkg = "com.x"
    private fun f(rule: String, title: String, sev: SecurityScanner.Severity, cls: String = "Lcom/x/Web;", scope: SecurityScanner.Scope = SecurityScanner.Scope.APP, reach: String = "") =
        SecurityScanner.Finding(sev, title, "detail", "fix", cls, 0, 0, "CWE-79").also { it.ruleId = rule; it.scope = scope; it.reach = reach }
    private fun mf(components: String) = ManifestContext("<manifest package=\"com.x\"><application>$components</application></manifest>")
    private val H = SecurityScanner.Severity.HIGH; private val M = SecurityScanner.Severity.MEDIUM; private val C = SecurityScanner.Severity.CRITICAL

    private val sink = f("taint-flow", "Untrusted input is loaded into a WebView", H)
    private val bridge = f("webview-js-interface", "WebView addJavascriptInterface", M)

    @Test fun aWebViewSinkWithABridgeInAnExportedActivityIsAScenarioWithAnAdbLine() {
        val s = AttackScenarios.build(listOf(sink, bridge), mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"><intent-filter><data android:scheme=\"wallet\" android:host=\"open\"/></intent-filter></activity>"), pkg)
        assertEquals(1, s.size); assertEquals("HIGH", s[0].likelihood); assertEquals(SecurityScanner.Severity.HIGH, s[0].severity)
        assertTrue(s[0].test, s[0].test.contains("wallet://open/")); assertEquals(2, s[0].chain.size)
        val noLink = AttackScenarios.build(listOf(sink, bridge), mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"/>"), pkg)
        assertTrue(noLink[0].test.contains("am start -n com.x/com.x.Web"))
    }

    @Test fun withoutBothHalvesOfTheChainThereIsNoScenario() {
        val mc = mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"/>")
        assertTrue(AttackScenarios.build(listOf(sink), mc, pkg).isEmpty())                                             // a sink, no bridge
        assertTrue(AttackScenarios.build(listOf(bridge), mc, pkg).isEmpty())                                           // a bridge nobody can feed
        assertTrue(AttackScenarios.build(listOf(sink, bridge.also { it.scope = SecurityScanner.Scope.LIB }), mc, pkg).isEmpty())   // the bridge is a library's
        bridge.scope = SecurityScanner.Scope.APP
        assertTrue(AttackScenarios.build(listOf(f("taint-flow", "Untrusted input is loaded into a WebView", SecurityScanner.Severity.INFO), bridge), mc, pkg).isEmpty())
        assertTrue(AttackScenarios.build(listOf(f("taint-flow", "Untrusted input is loaded into a WebView", H, scope = SecurityScanner.Scope.LIB), bridge), mc, pkg).isEmpty())
    }

    @Test fun aBridgeInAnotherClassIsNotAChainAndAnUnreachableChainIsNotAScenario() {              // Markor: found by reading the scenarios of eleven real apps
        val elsewhere = f("webview-js-interface", "WebView addJavascriptInterface", M, "Lcom/x/Editor;")
        assertTrue(AttackScenarios.build(listOf(sink, elsewhere), mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"/>"), pkg).isEmpty())
        val unreachable = f("taint-flow", "Untrusted input is loaded into a WebView", H)             // internal class, no path from an exported component: LOW likelihood
        assertTrue(AttackScenarios.build(listOf(unreachable, bridge), mf("<activity android:name=\"com.x.Web\" android:exported=\"false\"/>"), pkg).isEmpty())
    }

    @Test fun anOpenWebViewActivityWithFileAccessIsAScenarioWithoutAnyBridge() {                    // Vuldroid / OVAA: WebView sink + file access in an exported activity
        val fa = f("webview-file-access", "WebView: setAllowFileAccessFromFileURLs(true)", H)
        val s = AttackScenarios.build(listOf(sink, fa), mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"/>"), pkg)
        assertEquals(1, s.size); assertTrue(s[0].id.startsWith("webview-file-read")); assertEquals("HIGH", s[0].likelihood)
        assertTrue(AttackScenarios.build(listOf(sink, fa), mf("<activity android:name=\"com.x.Web\" android:exported=\"false\"/>"), pkg).isEmpty())   // not startable by others
        assertTrue(AttackScenarios.build(listOf(sink), mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"/>"), pkg).isEmpty())          // no file access
    }

    @Test fun aSecretHardcodedInTheCodeIsNotDataAtRestForABackupScenario() {                       // Breezy: three JWTs in the code made a "backup" chain
        val bk = f("manifest-allow-backup", "Backup allowed", M, null.toString())
        val hard = f("secrets-known-formats", "Hardcoded credential: JWT", H, "Lcom/x/Cfg;")
        assertTrue(AttackScenarios.build(listOf(bk, hard, f("high-entropy-strings", "High entropy", H, "Lcom/x/Cfg;")), null, pkg).isEmpty())
        assertEquals(1, AttackScenarios.build(listOf(bk, f("fintech-unencrypted-storage", "Credential stored in plain SharedPreferences", M, "Lcom/x/Login;")), null, pkg).size)
    }

    @Test fun anInternalWebViewWithFileAccessReachedFromAnExportedEntryIsAMediumLikelihoodScenario() {      // OVAA: WebViewActivity (not exported) behind a deep-link activity
        val fa = f("webview-file-access", "WebView: setAllowFileAccessFromFileURLs(true)", H)
        val viaPath = f("taint-flow", "Untrusted input is loaded into a WebView", H, reach = "YES").also { it.chain = "Entry: exported activity com.x.DeepLink\nPath: a -> b" }
        val s = AttackScenarios.build(listOf(viaPath, fa), mf("<activity android:name=\"com.x.Web\" android:exported=\"false\"/>"), pkg)
        assertEquals(1, s.size); assertEquals("MEDIUM", s[0].likelihood); assertTrue(s[0].entry.contains("com.x.DeepLink"))
        assertTrue(AttackScenarios.build(listOf(f("taint-flow", "Untrusted input is loaded into a WebView", H), fa), mf("<activity android:name=\"com.x.Web\" android:exported=\"false\"/>"), pkg).isEmpty())   // no path
    }

    @Test fun anInternalWebViewIsOnlyAsLikelyAsItsPath() {
        val mc = mf("<activity android:name=\"com.x.Web\" android:exported=\"false\"/>")
        val viaPath = f("taint-flow", "Untrusted input is loaded into a WebView", H, reach = "YES~").also { it.chain = "Entry: exported activity com.x.Start (launcher)\nPath: a -> b" }
        val s = AttackScenarios.build(listOf(viaPath, bridge), mc, pkg)
        assertEquals("MEDIUM", s[0].likelihood); assertTrue(s[0].entry.contains("com.x.Start")); assertTrue(s[0].test.startsWith("Not directly startable"))
        assertTrue(AttackScenarios.build(listOf(f("taint-flow", "Untrusted input is loaded into a WebView", H), bridge), mc, pkg).isEmpty())   // LOW: not a scenario
        val protectedC = mf("<activity android:name=\"com.x.Web\" android:exported=\"true\" android:permission=\"com.x.PRIV\"/>")
        assertTrue(AttackScenarios.build(listOf(sink, bridge), protectedC, pkg).isEmpty())                            // a permission closes the direct entry, and no path remains: LOW, not a scenario
        val viaPath2 = AttackScenarios.build(listOf(viaPath, bridge), protectedC, pkg)
        assertFalse(viaPath2.isEmpty() || viaPath2[0].likelihood == "HIGH")                                           // with a path it stays, but never HIGH
    }

    @Test fun disabledCertificateValidationIsATrafficInterceptionScenarioOnlyWhenItIsInAppCode() {
        val tm = f("tls-trustmanager", "Trust-all", C, "Lcom/x/Net;")
        val s = AttackScenarios.build(listOf(tm, f("manifest-cleartext-traffic", "Cleartext", M, null.toString())), null, pkg)
        assertEquals("traffic-interception", s[0].id); assertEquals("HIGH", s[0].likelihood); assertEquals(SecurityScanner.Severity.CRITICAL, s[0].severity)
        assertTrue(AttackScenarios.build(listOf(f("tls-trustmanager", "Trust-all", C, scope = SecurityScanner.Scope.LIB)), null, pkg).isEmpty())          // an SDK's
        assertTrue(AttackScenarios.build(listOf(f("tls-trustmanager", "Weak", M)), null, pkg).isEmpty())                                                 // not severe enough
    }

    @Test fun adbDataExtractionNeedsADebuggableOrBackupFlagAndSomethingWorthTaking() {
        val dbg = f("manifest-debuggable", "Debuggable build", C, null.toString()); val bk = f("manifest-allow-backup", "Backup allowed", M, null.toString())
        val secret = f("fintech-unencrypted-storage", "Credential stored in plain SharedPreferences", M, "Lcom/x/Cfg;")
        val a = AttackScenarios.build(listOf(dbg, secret), null, pkg); assertEquals("local-data-extraction", a[0].id); assertTrue(a[0].test.contains("run-as com.x"))
        val b = AttackScenarios.build(listOf(bk, secret), null, pkg); assertEquals(SecurityScanner.Severity.MEDIUM, b[0].severity); assertTrue(b[0].test.contains("adb backup"))
        assertTrue(AttackScenarios.build(listOf(dbg), null, pkg).isEmpty()); assertTrue(AttackScenarios.build(listOf(secret), null, pkg).isEmpty())          // twins
    }

    @Test fun anExportedProviderWithAnInjectionIsAScenarioAndAProtectedOneIsNot() {
        val inj = f("provider-sql-injection", "Provider SQL injection", H, "Lcom/x/Prov;")
        val open = mf("<provider android:name=\"com.x.Prov\" android:authorities=\"com.x.data;other\" android:exported=\"true\"/>")
        val s = AttackScenarios.build(listOf(inj), open, pkg)
        assertEquals(1, s.size); assertTrue(s[0].test.contains("content://com.x.data/")); assertEquals("HIGH", s[0].likelihood)
        assertTrue(AttackScenarios.build(listOf(inj), mf("<provider android:name=\"com.x.Prov\" android:authorities=\"a\" android:exported=\"true\" android:permission=\"com.x.P\"/>"), pkg).isEmpty())
        assertTrue(AttackScenarios.build(listOf(inj), mf("<provider android:name=\"com.x.Prov\" android:authorities=\"a\" android:exported=\"false\"/>"), pkg).isEmpty())
    }

    @Test fun theSectionStatesItsLimitsAndIsEmptyWithoutScenarios() {
        assertEquals("", AttackScenarios.section(emptyList(), null, pkg))
        val md = AttackScenarios.section(listOf(f("tls-trustmanager", "Trust-all", C)), null, pkg)
        assertTrue(md.contains("## Attack scenarios")); assertTrue(md.contains("static inference")); assertTrue(md.contains("No scenario here does not mean there is none"))
        assertNotNull(Regex("### 1\\. \\[CRITICAL\\]").find(md))
    }
}

/** 0.95.0: the extras the sink reads, where they are written and from what; found by reading a wallet app's single scenario ("Not directly startable", bridge named by class). */
class IntentExtrasScenarioTest {
    private val pkg = "com.x"
    private fun f(rule: String, title: String, sev: SecurityScanner.Severity, cls: String, detail: String = "d", reach: String = "", chain: String = "") =
        SecurityScanner.Finding(sev, title, detail, "fix", cls, 0, 0, "CWE-79").also { it.ruleId = rule; it.scope = SecurityScanner.Scope.APP; it.reach = reach; it.chain = chain }
    private fun mf(components: String) = ManifestContext("<manifest package=\"com.x\"><application>$components</application></manifest>")
    private val H = SecurityScanner.Severity.HIGH; private val M = SecurityScanner.Severity.MEDIUM

    private val web = """
        .class public Lcom/x/Web;
        .super Landroid/app/Activity;
        .method public setUrl()V
            .locals 3
            invoke-virtual {p0}, Lcom/x/Web;->getIntent()Landroid/content/Intent;
            move-result-object v0
            const-string v1, "target_url"
            invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v1
            return-void
        .end method
    """.trimIndent()
    private fun login(valueSource: String) = """
        .class public Lcom/x/Login;
        .super Landroid/app/Activity;
        .method public openSignUp()V
            .locals 4
            new-instance v0, Landroid/content/Intent;
            $valueSource
            const-string v2, "target_url"
            invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
            return-void
        .end method
    """.trimIndent()
    private val sink get() = f("taint-flow", "Untrusted input is loaded into a WebView", H, "Lcom/x/Web;", "Data from Intent.getStringExtra() reaches WebView.loadUrl() in method setUrl(): x", "YES~",
        "Entry: exported activity com.x.Start (launcher) | Approximate path (class level): com.x.Start.onCreate() -> com.x.Login.openSignUp() -> com.x.Web.setUrl()")
    private val bridge get() = f("webview-js-interface", "WebView addJavascriptInterface", M, "Lcom/x/Web;")
    private val internal = mf("<activity android:name=\"com.x.Web\" android:exported=\"false\"/>")

    private fun scan(loginSmali: String) { SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Web;", 0, web, "com.x"); SecurityScanner.scanSmali("Lcom/x/Login;", 1, loginSmali, "com.x") }

    @Test fun theExtraKeyAndItsWriterAreRecorded() {
        scan(login("const-string v1, \"https://signup.example/\""))
        assertEquals(listOf("target_url"), IntentExtras.readsOf("com.x.Web", "setUrl").map { it.key })
        val w = IntentExtras.writesOf("target_url").single(); assertEquals("CONSTANT", w.origin); assertEquals("openSignUp", w.method)
    }

    @Test fun aConstantUrlSetByTheAppDropsTheChainAndSaysWhy() {
        scan(login("const-string v1, \"https://signup.example/\""))
        val dropped = ArrayList<String>()
        assertTrue(AttackScenarios.build(listOf(sink, bridge), internal, pkg, dropped).isEmpty())
        assertTrue(dropped.single().contains("a constant"))
        assertTrue(AttackScenarios.section(listOf(sink, bridge), internal, pkg).contains("Not shown as scenarios"))
    }

    @Test fun aValueFromTheUserTheServerOrAnIncomingIntentKeepsTheChainWithTheWriterNamed() {
        for ((src, kind) in listOf(
            "invoke-virtual {v3}, Landroid/widget/EditText;->getText()Landroid/text/Editable;\n    move-result-object v1" to "text typed by the user",
            "invoke-virtual {v3, v3}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1" to "server response",
            "invoke-virtual {v3}, Landroid/content/Intent;->getDataString()Ljava/lang/String;\n    move-result-object v1" to "incoming Intent",
            "invoke-static {}, Lcom/x/Config;->signUpUrl()Ljava/lang/String;\n    move-result-object v1" to "com.x.Config.signUpUrl()")) {
            scan(login(src))
            val s = AttackScenarios.build(listOf(sink, bridge), internal, pkg)
            assertEquals(src, 1, s.size); assertTrue(s[0].likelihoodWhy, s[0].likelihoodWhy.contains("Login.openSignUp() sets \"target_url\"")); assertTrue(s[0].likelihoodWhy.contains(kind))
            assertTrue(s[0].test.contains("The value is set by"))
        }
    }

    @Test fun anExportedActivityGetsAnAdbLineWithItsRealExtraName() {
        scan(login("const-string v1, \"x\""))
        val s = AttackScenarios.build(listOf(sink, bridge), mf("<activity android:name=\"com.x.Web\" android:exported=\"true\"/>"), pkg)
        assertTrue(s[0].test, s[0].test.contains("--es target_url \"https://attacker.example/\""))                    // the constant writer is irrelevant when anybody can start the activity
        assertTrue(s[0].frida.contains("trace('com.x.Web', 'setUrl')")); assertTrue(s[0].frida.contains("android.webkit.WebView"))
    }

    @Test fun theBridgeMethodsTheScannerFoundAreNamedNotTheClass() {
        scan(login("invoke-virtual {v3}, Landroid/widget/EditText;->getText()Landroid/text/Editable;\n    move-result-object v1"))
        val bm = f("webview-js-bridge-method", "JavaScript-exposed method reaches a sensitive API", H, "LAll;", "Methods of this class are annotated @JavascriptInterface, and they reach: postMessage(): reflection / code loading (via a()).")
        val s = AttackScenarios.build(listOf(sink, bridge, bm), internal, pkg)
        assertTrue(s[0].impact, s[0].impact.contains("postMessage() in All")); assertFalse(s[0].impact.contains("exposed methods (Web)"))
    }

    @Test fun noRecordedWriterMeansNoOriginClaimAndTheOldBehaviourStays() {
        SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Web;", 0, web, "com.x")                     // nobody writes target_url in the scanned code
        val s = AttackScenarios.build(listOf(sink, bridge), internal, pkg)
        assertEquals(1, s.size); assertTrue(s[0].test.startsWith("Not directly startable")); assertFalse(s[0].likelihoodWhy.contains("sets \""))
    }
}

/** 0.97.0: an exported component that feeds attacker data to a dangerous operation (shell, SQL, file path, code, deserialization, redirection, ...). InjuredAndroid's CRITICAL RCEActivity had no scenario. */
class ExportedSinkScenarioTest {
    private val pkg = "com.x"
    private val C = SecurityScanner.Severity.CRITICAL; private val H = SecurityScanner.Severity.HIGH; private val M = SecurityScanner.Severity.MEDIUM
    private fun flow(title: String, sev: SecurityScanner.Severity, cls: String = "Lcom/x/Run;", detail: String = "Data from Intent.getStringExtra() reaches Runtime.exec() in method onCreate(): x", reach: String = "", chain: String = "", rule: String = "taint-flow") =
        SecurityScanner.Finding(sev, title, detail, "fix", cls, 0, 0, "CWE-78").also { it.ruleId = rule; it.scope = SecurityScanner.Scope.APP; it.reach = reach; it.chain = chain }
    private fun mf(components: String) = ManifestContext("<manifest package=\"com.x\"><application>$components</application></manifest>")
    private val activity = ".class public Lcom/x/Run;\n.super Landroid/app/Activity;\n.method public onCreate()V\n    .locals 3\n    invoke-virtual {p0}, Lcom/x/Run;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"cmd\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1\n    return-void\n.end method\n"
    private fun scan() { SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Run;", 0, activity, "com.x") }
    private val shell = "Untrusted input reaches a shell command"

    @Test fun anExportedActivityThatRunsAShellCommandIsACriticalScenarioWithItsRealExtra() {
        scan()
        val s = AttackScenarios.build(listOf(flow(shell, C)), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg)
        assertEquals(1, s.size); assertEquals(SecurityScanner.Severity.CRITICAL, s[0].severity); assertEquals("HIGH", s[0].likelihood)
        assertTrue(s[0].title, s[0].title.contains("shell command")); assertTrue(s[0].test, s[0].test.contains("am start -n com.x/com.x.Run --es cmd"))
        assertTrue(s[0].frida.contains("trace('com.x.Run', 'onCreate')")); assertTrue(s[0].frida.contains("java.lang.Runtime")); assertTrue(s[0].masvs.contains("MASVS-CODE-4"))
    }

    @Test fun noExportNoPathMeansNoScenarioAndMediumFindingsAreIgnored() {
        scan()
        assertTrue(AttackScenarios.build(listOf(flow(shell, C)), mf("<activity android:name=\"com.x.Run\" android:exported=\"false\"/>"), pkg).isEmpty())
        assertTrue(AttackScenarios.build(listOf(flow(shell, C)), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\" android:permission=\"com.x.P\"/>"), pkg).isEmpty())
        assertTrue(AttackScenarios.build(listOf(flow(shell, M)), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg).isEmpty())
        assertTrue(AttackScenarios.build(listOf(flow("Untrusted input is loaded into a WebView", H)), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg).isEmpty())   // WebView sinks have their own patterns
    }

    @Test fun everySinkKindGetsItsOwnScenarioText() {
        scan(); val mc = mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>")
        val titles = listOf("Untrusted input reaches an SQL statement", "Untrusted input is used as a file path", "Untrusted input is loaded as code or a native library", "Untrusted data is deserialized (ObjectInputStream)",
            "Untrusted Intent is launched by this app (intent redirection)", "Untrusted input selects a class or method by name", "Untrusted input chooses the server the app contacts", "Untrusted input chooses the file or content URI the app opens")
        val out = titles.map { t -> AttackScenarios.build(listOf(flow(t, H)), mc, pkg).single().title }
        assertEquals(titles.size, out.toSet().size); assertTrue(out.all { it.startsWith("Another app can") })
    }

    @Test fun anInternalActivityBehindAnExportedEntryKeepsTheChainOnlyWhenTheValueIsNotAConstant() {
        val login = { v: String -> ".class public Lcom/x/Login;\n.super Landroid/app/Activity;\n.method public go()V\n    .locals 4\n    new-instance v0, Landroid/content/Intent;\n    $v\n    const-string v2, \"cmd\"\n    invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n    return-void\n.end method\n" }
        val f = flow(shell, C, reach = "YES", chain = "Entry: exported activity com.x.Start (launcher) | Path: com.x.Start.onCreate() -> com.x.Login.go() -> com.x.Run.onCreate()")
        val internal = mf("<activity android:name=\"com.x.Run\" android:exported=\"false\"/>")
        SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Run;", 0, activity, "com.x"); SecurityScanner.scanSmali("Lcom/x/Login;", 1, login("invoke-virtual {v3}, Landroid/content/Intent;->getDataString()Ljava/lang/String;\n    move-result-object v1"), "com.x")
        val s = AttackScenarios.build(listOf(f), internal, pkg)
        assertEquals("MEDIUM", s.single().likelihood); assertTrue(s.single().likelihoodWhy, s.single().likelihoodWhy.contains("Login.go() sets \"cmd\""))
        SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Run;", 0, activity, "com.x"); SecurityScanner.scanSmali("Lcom/x/Login;", 1, login("const-string v1, \"ls\""), "com.x")
        val dropped = ArrayList<String>()
        assertTrue(AttackScenarios.build(listOf(f), internal, pkg, dropped).isEmpty()); assertTrue(dropped.single().contains("shell flow"))     // a constant command: nobody outside controls it
    }

    @Test fun servicesAndReceiversGetTheirOwnAdbVerbAndAProviderIsLeftToItsOwnRule() {
        scan()
        val svc = AttackScenarios.build(listOf(flow(shell, C)), mf("<service android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg).single()
        assertTrue(svc.test, svc.test.contains("am startservice -n com.x/com.x.Run"))
        val rcv = AttackScenarios.build(listOf(flow(shell, C)), mf("<receiver android:name=\"com.x.Run\" android:exported=\"true\"><intent-filter><action android:name=\"com.x.DO\"/></intent-filter></receiver>"), pkg).single()
        assertTrue(rcv.test, rcv.test.contains("am broadcast -a com.x.DO -n com.x/com.x.Run --es cmd"))
        val prov = AttackScenarios.build(listOf(flow("Untrusted input reaches an SQL statement", H)), mf("<provider android:name=\"com.x.Run\" android:authorities=\"a;b\" android:exported=\"true\"/>"), pkg).single()
        assertTrue(prov.test, prov.test.startsWith("adb shell content query --uri content://a/ --where")); assertEquals("content://a", prov.entry)        // an open provider: a benign probe, not an invented extra
        assertTrue(AttackScenarios.build(listOf(flow("Untrusted input reaches an SQL statement", H)), mf("<provider android:name=\"com.x.Run\" android:authorities=\"a\" android:exported=\"true\" android:permission=\"com.x.P\"/>"), pkg).isEmpty())
        // pattern 4 already covers the provider (rule provider-sql-injection): no second scenario for the same class
        val both = AttackScenarios.build(listOf(flow("Untrusted input reaches an SQL statement", H), SecurityScanner.Finding(H, "Provider SQL injection", "d", "f", "Lcom/x/Run;", 0, 0, "CWE-89").also { it.ruleId = "provider-sql-injection"; it.scope = SecurityScanner.Scope.APP }),
            mf("<provider android:name=\"com.x.Run\" android:authorities=\"a\" android:exported=\"true\"/>"), pkg)
        assertEquals(1, both.size); assertTrue(both[0].id.startsWith("provider-leak"))
    }

    @Test fun parcelableOnlyExtrasGetNoInventedExtraAndSeveralQueryKeysAreAllUsed() {
        val parc = ".class public Lcom/x/Run;\n.super Landroid/app/Activity;\n.method public onCreate()V\n    .locals 3\n    invoke-virtual {p0}, Lcom/x/Run;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"target\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n    move-result-object v1\n    return-void\n.end method\n"
        SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Run;", 0, parc, "com.x")
        val a = AttackScenarios.build(listOf(flow("Untrusted Intent is launched by this app (intent redirection)", H)), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg).single()
        assertTrue(a.test, a.test.startsWith("No adb line: the code reads target (Parcelable)")); assertFalse(a.test.contains("--es"))
        val q = ".class public Lcom/x/Run;\n.super Landroid/app/Activity;\n.method public onCreate()V\n    .locals 4\n    invoke-virtual {p0}, Lcom/x/Run;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;\n    move-result-object v0\n    const-string v1, \"binary\"\n    invoke-virtual {v0, v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;\n    const-string v1, \"param\"\n    invoke-virtual {v0, v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;\n    return-void\n.end method\n"
        SecurityScanner.clearKeyTracking(); SecurityScanner.scanSmali("Lcom/x/Run;", 0, q, "com.x")
        val b = AttackScenarios.build(listOf(flow(shell, C, detail = "Data from Intent.getData() reaches Runtime.exec() in method onCreate(): x")),
            mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"><intent-filter><data android:scheme=\"flag\" android:host=\"rce\"/></intent-filter></activity>"), pkg).single()
        assertTrue(b.test, b.test.contains("flag://rce/?binary=https://attacker.example/&param=https://attacker.example/"))
    }

    @Test fun theChainListsEachFindingOnce() {
        scan()
        val f = flow(shell, C)
        val s = AttackScenarios.build(listOf(f, flow(shell, C), flow(shell, C)), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg).single()
        assertEquals(1, s.chain.size)
    }

    @Test fun aSourceThatIsNotAnIntentExtraGetsHonestTextInsteadOfAWrongAdbLine() {
        scan()
        val s = AttackScenarios.build(listOf(flow(shell, C, detail = "Data from Parcel.readString() reaches Runtime.exec() in method onCreate(): x")), mf("<activity android:name=\"com.x.Run\" android:exported=\"true\"/>"), pkg).single()
        assertTrue(s.test, s.test.startsWith("No adb line")); assertTrue(s.test.contains("Parcel.readString"))
    }
}

/** 0.97.1: a JavaScript bridge whose only "reflection" is an obfuscator's marshalling helper is not a finding; a helper that can receive the page's text still is. */
class JsBridgePlumbingTest {
    private fun bridge(helperSig: String, helperCall: String) = """
        .class public LAll;
        .super Ljava/lang/Object;
        .method public postMessage(Ljava/lang/String;)V
            .annotation runtime Landroid/webkit/JavascriptInterface;
            .end annotation
            .locals 4
            $helperCall
            return-void
        .end method
        .method private static a$helperSig
            .locals 3
            invoke-virtual {v0, v1, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
            return-void
        .end method
    """.trimIndent()

    @Test fun theObfuscatorsHelperIsNotReflectionReachedFromJavaScript() {
        val t = bridge("(ICI[Ljava/lang/Object;)V", "invoke-static {v0, v1, v2, v3}, LAll;->a(ICI[Ljava/lang/Object;)V")
        assertTrue(JsBridgeMethodRule.dangerousExposed(t).isEmpty())
    }

    @Test fun aHelperThatTakesTheTextOfThePageStillCounts() {
        val t = bridge("(Ljava/lang/String;)V", "invoke-static {p1}, LAll;->a(Ljava/lang/String;)V")
        assertTrue(JsBridgeMethodRule.dangerousExposed(t).single().contains("reflection / code loading (via a())"))
        val u = bridge("(ILjava/lang/String;[Ljava/lang/Object;)V", "invoke-static {v0, p1, v3}, LAll;->a(ILjava/lang/String;[Ljava/lang/Object;)V")
        assertEquals(1, JsBridgeMethodRule.dangerousExposed(u).size)          // an Object[] out-array with a String parameter is not plumbing
    }

    @Test fun otherApisReachedThroughPlumbingStillCount() {
        val t = bridge("(ICI[Ljava/lang/Object;)V", "invoke-static {v0, v1, v2, v3}, LAll;->a(ICI[Ljava/lang/Object;)V").replace("Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;")
        assertTrue(JsBridgeMethodRule.dangerousExposed(t).single().contains("process execution (via a())"))
    }
}
