package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 0.82.0: from the JustMarkets read (renamed app code lowered as "likely third-party", descriptor literal, native split). */
class JustMarketsFixes0820Test {

    private val appRefs = "invoke-static {}, Lcom/justmarkets/a/B;->x()V\n    sget-object v0, Lcom/justmarkets/c/D;->y:I\n    new-instance v1, Lcom/justmarkets/e/F;\n"

    @Test fun renamedClassThatReferencesTheAppIsAppCode() {
        assertTrue(SecurityScanner.isAppBoundObf(appRefs, "com.justmarkets"))
        assertFalse(SecurityScanner.isAppBoundObf("invoke-static {}, Lcom/justmarkets/a/B;->x()V\n", "com.justmarkets"))   // one ref = library glue
        assertFalse(SecurityScanner.isAppBoundObf(appRefs, ""))
        // a merged class that also carries an SDK's own code (Ivy I4/n: Crashlytics + com.ivy Room entities) stays obfuscated / lowered
        assertFalse(SecurityScanner.isAppBoundObf(appRefs + "    const-string v2, \"FirebaseCrashlytics\"\n", "com.justmarkets"))
        // an app feature flag that only mentions a vendor name is still app code (JustMarkets mu.h "isIntercomEnabled")
        assertTrue(SecurityScanner.isAppBoundObf(appRefs + "    const-string v2, \"isIntercomEnabled\"\n", "com.justmarkets"))
    }

    private fun obfFinding() = SecurityScanner.Finding(SecurityScanner.Severity.MEDIUM, "Sensitive value saved to SharedPreferences (plaintext)", "d", "r", "Lmu/j;", 1, 1, "CWE-312")
        .also { it.scope = SecurityScanner.Scope.OBF; it.confidence = "MEDIUM"; it.ruleId = "androgoat-checks" }

    @Test fun appBoundObfuscatedFindingIsNotLoweredAndBecomesAppScope() {
        val kept = FindingPolish.apply(listOf(obfFinding()), "Lmu/j;", appBound = true)[0]
        assertEquals(SecurityScanner.Severity.MEDIUM, kept.severity)
        assertEquals(SecurityScanner.Scope.APP, kept.scope)
        val lowered = FindingPolish.apply(listOf(obfFinding()), "Lmu/j;")[0]
        assertEquals(SecurityScanner.Severity.LOW, lowered.severity)
    }

    @Test fun jvmMethodDescriptorsAreNotSecrets() {
        assertTrue(SecurityScanner.looksLikeName("getAccessToken()Ljava/lang/String;"))
        assertTrue(SecurityScanner.looksLikeName("setTimeout(J)V"))
        assertFalse(SecurityScanner.looksLikeName("x7Kp2QvLm9Rt4Zw8Yb3Nc6Hd"))
    }

    private fun apk(vararg entries: Pair<String, ByteArray>): ZipFile {
        val f = File.createTempFile("apk", ".zip"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }

    @Test fun nativeCoverageCardForASplitApkAndForBundledLibraries() {
        val dex = "dex\n035 ... Ljava/lang/System; loadLibrary ...".toByteArray()
        val split = nativeCoverageFinding(apk("classes.dex" to dex), "<manifest android:requiredSplitTypes=\"base__abi,base__density\">")
        assertNotNull(split)
        assertTrue(split!!.title.startsWith("Native code not in this APK"))
        val bundled = nativeCoverageFinding(apk("classes.dex" to dex, "lib/arm64-v8a/libcore.so" to ByteArray(4)), "<manifest>")
        assertTrue(bundled!!.title.contains("1 .so"))
        assertNull(nativeCoverageFinding(apk("classes.dex" to "dex\n035 nothing".toByteArray()), "<manifest>"))
    }

    // ---------------- AI triage context (0.82.0): the method where the value is read
    @Test fun methodExcerptFindsTheMethodByKeyAndCutsAtALineEnd() {
        val cls = """
            .class public Lcom/x/A;
            .method public onCreate(Landroid/os/Bundle;)V
                .locals 2
                const-string v0, "a"
                return-void
            .end method
            .method public other(Ljava/lang/String;)V
                .locals 1
                return-void
            .end method
        """.trimIndent()
        val m = SecurityScanner.methodExcerpt(cls, "Lcom/x/A;->onCreate(Landroid/os/Bundle;)V")
        assertTrue(m.startsWith(".method public onCreate") && m.contains("const-string v0") && !m.contains("other("))
        assertEquals("", SecurityScanner.methodExcerpt(cls, "Lcom/x/A;->missing()V"))
        val long = ".method public big()V\n" + (1..200).joinToString("\n") { "    const/4 v0, 0x$it" } + "\n.end method"
        val cut = SecurityScanner.methodExcerpt(long, "Lx;->big()V", 300)
        assertTrue(cut.length < 400 && cut.endsWith("# ... (method continues)"))
    }
}

