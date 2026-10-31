package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Maturity protocol phase 2: the four-condition MUST FIX gate (MustFixGate) and the permission rule it applies (no device: no system resolver). */
class MustFixGateTest {

    private val xml = """
        <manifest package="com.example.app">
          <permission android:name="com.example.SIG" android:protectionLevel="signature"/>
          <permission android:name="com.example.SOS" android:protectionLevel="signatureOrSystem"/>
          <permission android:name="com.example.PRIVSYS" android:protectionLevel="privileged|system"/>
          <permission android:name="com.example.DNG" android:protectionLevel="dangerous"/>
          <permission android:name="com.example.NRM" android:protectionLevel="normal"/>
          <application>
            <activity android:name=".SmsGuarded" android:exported="true" android:permission="android.permission.READ_SMS"/>
            <activity android:name=".AppDangerous" android:exported="true" android:permission="com.example.DNG"/>
            <activity android:name=".AppNormal" android:exported="true" android:permission="com.example.NRM"/>
            <activity android:name=".Open" android:exported="true"/>
            <activity android:name=".Sig" android:exported="true" android:permission="com.example.SIG"/>
            <activity android:name=".Sos" android:exported="true" android:permission="com.example.SOS"/>
            <activity android:name=".PrivSys" android:exported="true" android:permission="com.example.PRIVSYS"/>
            <service android:name=".Job" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE"/>
          </application>
        </manifest>
    """.trimIndent()
    private val guard = PermissionGuard(ManifestContext(xml))     // no resolver: what the sandbox and an unknown permission see

    private val ssa = "Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method com.example.app.X.a(). Found by the SSA data-flow engine."
    private fun card(component: String, tag: String = "activity", detail: String = ssa, reach: String = "YES", rule: String = "taint-flow", sev: Severity = Severity.HIGH) =
        Finding(sev, "Untrusted input is used as a file path", detail, "Fix it. More.", "Lcom/example/app/$component;", 1, 0, "CWE-22").also {
            it.ruleId = rule; it.scope = SecurityScanner.Scope.APP; it.confidence = "HIGH"; it.reach = reach
            it.chain = if (reach.isEmpty() || reach == "NO") "" else "Entry: exported $tag com.example.app.$component\nPath: com.example.app.$component.onCreate() -> com.example.app.X.a()"
        }
    private val full = Verdict.Coverage(deepScan = true, classesScanned = 100)
    private fun mustFix(f: Finding) = Verdict.build(listOf(f), emptyList(), full, "com.example.app", guard = guard).mustFix
    private fun inMustFix(f: Finding) = mustFix(f).single().startsWith("#1 ")

    // ---- the mandatory case: a dangerous permission is not a guard ----
    @Test fun readSmsGuardedComponentStaysUnprotectedAndEntersMustFix() {
        assertEquals(PermissionGuard.Guard.WEAK, guard.strengthOf("android.permission.READ_SMS"))
        val f = card("SmsGuarded")
        val r = MustFixGate.check(f, guard)
        assertTrue("READ_SMS must leave the entry unprotected", r.reach)
        assertTrue(r.failed.toString(), r.passes)
        assertTrue(mustFix(f).toString(), inMustFix(f))
    }

    @Test fun appDeclaredDangerousAndNormalPermissionsAreNotGuardsEither() {
        assertTrue(inMustFix(card("AppDangerous")))
        assertTrue(inMustFix(card("AppNormal")))
        assertTrue(inMustFix(card("Open")))
    }

    // twins of (b): the four kinds of guard that DO count
    @Test fun signatureLevelGuardsAndBindPermissionsKeepTheCardOut() {
        for (c in listOf("Sig", "Sos", "PrivSys")) {
            assertFalse(c, MustFixGate.check(card(c), guard).reach)
            assertFalse(c, inMustFix(card(c)))
        }
        assertEquals(PermissionGuard.Guard.SIGNATURE, guard.strengthOf("android.permission.BIND_JOB_SERVICE"))   // no resolver needed
        val job = card("Job", tag = "service")
        assertEquals(listOf("b"), MustFixGate.check(job, guard).failed)
        assertFalse(inMustFix(job))
    }

    @Test fun noReachIsNoMustFix() {
        assertEquals(listOf("b"), MustFixGate.check(card("Open", reach = "NO"), guard).failed)
        assertEquals(listOf("b"), MustFixGate.check(card("Open", reach = ""), guard).failed)
    }

    // (a) high-impact sink, and its twins
    @Test fun onlyHighImpactSinksPass() {
        for (s in listOf("Runtime.exec", "ProcessBuilder.<init>", "WebView.loadUrl", "SQLiteDatabase.rawQuery", "ParcelFileDescriptor.open", "ObjectInputStream.<init>",
                "Class.forName", "DexClassLoader.<init>", "Context.startActivity", "MainActivity.startActivity", "ContentResolver.openInputStream"))
            assertTrue(s, MustFixGate.highImpactSink(s))
        for (s in listOf(null, "URL.<init>", "Request\$Builder.url", "Class.getMethod", "Log.d", "SharedPreferences\$Editor.putString", "WebView.loadUrlX"))
            assertFalse(s.toString(), MustFixGate.highImpactSink(s))
        val ssrf = card("Open", detail = "Data from Intent.getStringExtra() reaches URL.<init>() in method com.example.app.X.a(). Found by the SSA data-flow engine.")
        assertEquals(listOf("a"), MustFixGate.check(ssrf, guard).failed)
        assertFalse(inMustFix(ssrf))
    }

    // (c) unsanitized path, and its twin
    @Test fun validationSeenOnThePathKeepsTheCardOut() {
        val v = card("Open", detail = "$ssa The chain also contains validation-like calls (startsWith); check them.")
        assertEquals(listOf("c"), MustFixGate.check(v, guard).failed)
        assertFalse(inMustFix(v))
    }

    // (d) proof, and its twins
    @Test fun aRuleMatchNeedsAnExactPathFromTheManifestEntry() {
        val rule = "Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method com.example.app.X.a()."
        val exact = card("Open", detail = rule, rule = "path-rule")
        assertTrue(MustFixGate.check(exact, guard).passes)
        val approx = card("Open", detail = rule, rule = "path-rule", reach = "YES~")
        assertEquals(listOf("d"), MustFixGate.check(approx, guard).failed)
        assertFalse(inMustFix(approx))
        // the SSA flow is its own proof, even on a class-level path
        assertTrue(MustFixGate.check(card("Open", reach = "YES~"), guard).passes)
    }

    @Test fun entryTypeIsReadFromTheReachChain() {
        assertEquals("Lcom/example/app/Open;", MustFixGate.entryType(card("Open")))
        val dl = card("Open").also { it.chain = "Entry: exported activity com.example.app.Open (deep link)\nPath: x" }
        assertEquals("Lcom/example/app/Open;", MustFixGate.entryType(dl))
        assertEquals(null, MustFixGate.entryType(card("Open", reach = "NO")))
    }

    // mutation checks: each switch off must break one of the tests above
    @Test fun everySwitchIsLoadBearing() {
        val cases = listOf(
            Triple({ MustFixGate.CHECK_SINK = false }, card("Open", detail = "Data from Intent.getStringExtra() reaches URL.<init>() in method com.example.app.X.a(). Found by the SSA data-flow engine."), "a"),
            Triple({ MustFixGate.CHECK_GUARD = false }, card("Sig"), "b"),
            Triple({ MustFixGate.CHECK_SANITIZED = false }, card("Open", detail = "$ssa The chain also contains validation-like calls (startsWith); check them."), "c"),
            Triple({ MustFixGate.CHECK_PROOF = false }, card("Open", detail = "Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method com.example.app.X.a().", rule = "path-rule", reach = "YES~"), "d"))
        for ((off, f, cond) in cases) {
            assertFalse(cond, MustFixGate.check(f, guard).passes)
            off()
            try { assertTrue("switch of ($cond) is not load-bearing", MustFixGate.check(f, guard).passes) }
            finally { MustFixGate.CHECK_SINK = true; MustFixGate.CHECK_GUARD = true; MustFixGate.CHECK_SANITIZED = true; MustFixGate.CHECK_PROOF = true }
        }
    }
}
