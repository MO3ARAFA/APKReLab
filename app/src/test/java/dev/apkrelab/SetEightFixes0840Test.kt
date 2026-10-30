package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.84.0: trust-all TrustManager with R8 null checks, and providers the manifest does not export (real-app set 8: Quillpad, OpenTracks, Orbot). */
class SetEightFixes0840Test {

    private fun tm(body: String) = """
        .class public Lcom/x/Tm;
        .implements Ljavax/net/ssl/X509TrustManager;
        .method public final checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
            .locals 0
            $body
            return-void
        .end method
    """.trimIndent()

    private fun scan(t: String) = TlsTrustmanagerRule.scan(RuleContext("Lcom/x/Tm;", 0, t, "com.x"))

    @Test fun nullChecksBeforeReturnVoidDoNotHideATrustAllManager() {
        val nc = "invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;\n            invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;"
        assertEquals(1, scan(tm(nc)).size)                                                         // Quillpad gq2
        assertEquals(1, scan(tm("invoke-static {p1, p2}, Lkotlin/jvm/internal/Intrinsics;->d(Ljava/lang/Object;Ljava/lang/String;)V")).size)
    }

    @Test fun lineDirectivesBetweenTheNullChecksAreSkippedToo() {                                   // the real Quillpad gq2 text
        val real = ".class public Lcom/x/Tm;\n.implements Ljavax/net/ssl/X509TrustManager;\n" +
            ".method public final checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V\n    .locals 0\n\n    .line 1\n" +
            "    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;\n\n    .line 2\n    .line 3\n    .line 4\n" +
            "    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;\n\n    .line 5\n    .line 6\n    .line 7\n    return-void\n.end method\n"
        assertEquals(1, scan(real).size)
    }

    @Test fun aRealCheckAfterTheNullChecksKeepsTheManagerQuiet() {
        val nc = "invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;\n            invoke-static {p1, p2}, Lcom/x/Pin;->verify([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"
        assertTrue(scan(tm(nc)).isEmpty())
        // an app method that merely takes (Object, String) is a check, not a null check
        assertTrue(scan(tm("invoke-static {p1, p2}, Lcom/x/Pin;->check(Ljava/lang/Object;Ljava/lang/String;)V")).isEmpty())
    }

    @Test fun providerTextRuleFindingsDropWhenTheProviderIsNotExported() {
        val mc = ManifestContext("""
            <manifest package="com.x"><application>
            <provider android:name=".data.Internal" android:authorities="a" android:exported="false"/>
            <provider android:name=".data.Open" android:authorities="b" android:exported="true"/>
            </application></manifest>
        """.trimIndent())
        val np = FindingPolish.nonExportedProviders(mc)
        assertEquals(setOf("Lcom/x/data/Internal;"), np)
        fun f(cls: String) = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "ContentProvider.query() may build SQL by string concatenation", "d", "r", cls, 1, 1, "CWE-89")
            .also { it.ruleId = "provider-sql-injection" }
        val a = f("Lcom/x/data/Internal;"); val b = f("Lcom/x/data/Open;")
        assertEquals(1, FindingPolish.lowerNonExportedProviders(listOf(a, b), np))
        assertEquals(SecurityScanner.Severity.MEDIUM, a.severity)
        assertEquals(SecurityScanner.Severity.HIGH, b.severity)
        assertEquals(0, FindingPolish.lowerNonExportedProviders(listOf(a, b), np))                // idempotent
    }

    @Test fun anInClassTaintCardDoesNotRaiseALoweredSsaCardOfTheSameClassAndTitle() {
        fun taint(ssa: Boolean, sev: SecurityScanner.Severity, conf: String) =
            SecurityScanner.Finding(sev, "Untrusted input reaches an SQL statement",
                "Data from a ContentProvider method parameter reaches SQLiteDatabase.delete()" + if (ssa) " ... Found by the SSA data-flow engine ..." else " ... followed inside this class", "r", "Lcom/x/P;", 4, 1, "CWE-89")
                .also { it.ruleId = "taint-flow"; it.confidence = conf }
        val ssaLow = taint(true, SecurityScanner.Severity.LOW, "LOW")
        val old = taint(false, SecurityScanner.Severity.HIGH, "MEDIUM")
        val d = SecurityScanner.dedupe(listOf(ssaLow, old))
        assertEquals(1, d.size)
        assertEquals(SecurityScanner.Severity.LOW, d[0].severity)
        // an SSA card that was NOT lowered still takes the higher severity of its twin
        val ssaMed = taint(true, SecurityScanner.Severity.MEDIUM, "MEDIUM")
        val d2 = SecurityScanner.dedupe(listOf(ssaMed, taint(false, SecurityScanner.Severity.HIGH, "MEDIUM")))
        assertEquals(SecurityScanner.Severity.HIGH, d2[0].severity)
    }

    @Test fun theAppBaseClassOfAnUnexportedProviderIsUnexportedToo() {                              // OpenTracks CustomContentProvider
        val mc = ManifestContext("""
            <manifest package="com.x"><application>
            <provider android:name=".data.Share" android:authorities="a" android:exported="false"/>
            <provider android:name=".data.Open" android:authorities="b" android:exported="true"/>
            </application></manifest>
        """.trimIndent())
        val supers = mapOf("Lcom/x/data/Share;" to "Lcom/x/data/Base;", "Lcom/x/data/Open;" to "Lcom/x/data/Shared;", "Lcom/x/data/Base;" to "Landroid/content/ContentProvider;",
            "Lcom/x/data/Shared;" to null)
        val np = FindingPolish.nonExportedProviders(mc) { supers[it]?.takeIf { s -> s in supers } }
        assertEquals(setOf("Lcom/x/data/Share;", "Lcom/x/data/Base;"), np)
        // a base class shared with an EXPORTED provider is not lowered
        val shared = mapOf("Lcom/x/data/Share;" to "Lcom/x/data/Base;", "Lcom/x/data/Open;" to "Lcom/x/data/Base;", "Lcom/x/data/Base;" to null)
        assertEquals(setOf("Lcom/x/data/Share;"), FindingPolish.nonExportedProviders(mc) { shared[it] })
    }

    // ---------------- 0.85.0: an obfuscated trust-all manager that the app installs is not "just a library"
    private fun installer(type: String, body: String) = """
        .class public $type
        .super Ljava/lang/Object;
        .method public a()V
            .locals 4
            $body
            return-void
        .end method
    """.trimIndent()

    @Test fun anObfuscatedTlsClassInstalledInAnSslContextIsRestoredOneLevel() {
        SecurityScanner.tlsInstalled.clear()
        SecurityScanner.scanSmali("Leq2;", 1, installer("Leq2;",
            "new-instance v0, Lgq2;\n            invoke-virtual {v1, v2, v0, v3}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V"), "com.x")
        assertTrue("Lgq2;" in SecurityScanner.tlsInstalled)
        fun f(cls: String) = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "TLS certificate validation disabled", "d", "r", cls, 1, 1, "CWE-295")
            .also { it.ruleId = "tls-trustmanager"; it.scope = SecurityScanner.Scope.OBF; it.adjusted = "Lowered one level: obfuscated (likely third-party) code; the pattern is exact ..." }
        val used = f("Lgq2;"); val unused = f("Lr9e;")
        assertEquals(1, FindingPolish.restoreInstalledTls(listOf(used, unused)))
        assertEquals(SecurityScanner.Severity.CRITICAL, used.severity)
        assertEquals(SecurityScanner.Severity.HIGH, unused.severity)                 // Exness r9e: never installed, stays lowered
        assertEquals(0, FindingPolish.restoreInstalledTls(listOf(used, unused)))     // idempotent (the note changed)
        SecurityScanner.tlsInstalled.clear()
    }

    @Test fun aReadableAppClassIsNotRecordedAndSslContextWithoutAnInstanceRecordsNothing() {
        SecurityScanner.tlsInstalled.clear()
        SecurityScanner.scanSmali("Lcom/x/Net;", 1, installer("Lcom/x/Net;",
            "new-instance v0, Lcom/x/MyTrustManager;\n            invoke-virtual {v1, v2, v0, v3}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V"), "com.x")
        assertTrue(SecurityScanner.tlsInstalled.isEmpty())
    }

    @Test fun anInlinedOkHttpHostnameVerifierFieldCountsAsInstalling() {                           // JustMarkets ar.f.p() with ar.c
        SecurityScanner.tlsInstalled.clear()
        SecurityScanner.scanSmali("Lar/f;", 1, installer("Lar/f;",
            "new-instance v6, Lar/c;\n            invoke-direct {v6}, Ljava/lang/Object;-><init>()V\n            iput-object v6, v8, Lokhttp3/OkHttpClient\$Builder;->u:Ljavax/net/ssl/HostnameVerifier;"), "com.x")
        assertTrue("Lar/c;" in SecurityScanner.tlsInstalled)
        SecurityScanner.tlsInstalled.clear()
    }

    @Test fun manifestAttributesWithoutPoolNamesAreStillNamed() {                                   // InstaPay: attr_1010003 = android:name
        assertEquals("name", Axml.fallbackName(0x01010003))
        assertEquals("permission", Axml.fallbackName(0x01010006))
        assertEquals("exported", Axml.fallbackName(0x01010010))
        assertEquals("authorities", Axml.fallbackName(0x01010018))
        assertEquals("grantUriPermissions", Axml.fallbackName(0x0101001b))
        assertEquals("scheme", Axml.fallbackName(0x01010027))
        assertEquals("pathPattern", Axml.fallbackName(0x0101002c))
        assertEquals(null, Axml.fallbackName(0x0101ffff))
    }
}

