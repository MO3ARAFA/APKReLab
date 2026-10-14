package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.74.0: fixes for misses found by the first held-out benchmark (PIVAA / Allsafe / Vuldroid). Hand-written smali in the shape apktool/baksmali really emits. */
class HeldOutFixes0740Test {

    private fun ctx(type: String, text: String) = RuleContext(type, 0, text, "com.example")

    // ---- tls-trustmanager: `throws CertificateException` puts an .annotation block before the first instruction ----

    private fun trustManager(body: String, extra: String = "") = """
        .class public Lcom/example/Tm;
        .implements Ljavax/net/ssl/X509TrustManager;
        .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
            .locals 0
            .annotation system Ldalvik/annotation/Throws;
                value = {
                    Ljava/security/cert/CertificateException;
                }
            .end annotation
        $extra
        $body
        .end method
    """.trimIndent()

    @Test fun noOpTrustManagerWithThrowsAnnotationIsFound() {
        val r = TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", trustManager("    return-void")))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.CRITICAL, r[0].severity)
    }

    @Test fun noOpTrustManagerWithParamsLinesAndPrologueIsFound() {
        val extra = """
                .param p1, "chain"
                .param p2, "authType"
                .prologue
                .line 20
        """.trimIndent()
        val r = TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", trustManager("    return-void", extra)))
        assertEquals(1, r.size)
    }

    @Test fun annotationInsideAParamBlockIsSkippedToo() {
        val t = """
            .class public Lcom/example/Tm;
            .implements Ljavax/net/ssl/X509TrustManager;
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .locals 0
                .param p1    # [Ljava/security/cert/X509Certificate;
                    .annotation build Landroidx/annotation/NonNull;
                    .end annotation
                .end param
                .annotation system Ldalvik/annotation/Throws;
                    value = {
                        Ljava/security/cert/CertificateException;
                    }
                .end annotation
                return-void
            .end method
        """.trimIndent()
        assertEquals(1, TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", t)).size)
    }

    @Test fun trustManagerThatReallyChecksIsNotFlaggedEvenWithTheAnnotation() {
        val body = """
                invoke-static {p1, p2}, Lcom/example/Pin;->verify([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                return-void
        """.trimIndent()
        assertTrue(TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", trustManager(body))).isEmpty())
    }

    @Test fun anAnnotationBlockCannotHideAnInstructionBeforeTheReturn() {
        // the `return-void` after the real call must not be reached by skipping instruction lines
        val body = """
                const/4 v0, 0x1
                invoke-static {v0}, Lcom/example/Log;->d(I)V
                return-void
        """.trimIndent()
        assertTrue(TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", trustManager(body))).isEmpty())
    }

    @Test fun twoMethodsOnlyTheEmptyOneMatches() {
        val t = """
            .class public Lcom/example/Tm;
            .implements Ljavax/net/ssl/X509TrustManager;
            .method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .locals 0
                .annotation system Ldalvik/annotation/Throws;
                    value = {
                        Ljava/security/cert/CertificateException;
                    }
                .end annotation
                return-void
            .end method
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .locals 1
                .annotation system Ldalvik/annotation/Throws;
                    value = {
                        Ljava/security/cert/CertificateException;
                    }
                .end annotation
                invoke-static {p1}, Lcom/example/Pin;->check([Ljava/security/cert/X509Certificate;)V
                return-void
            .end method
        """.trimIndent()
        // checkClientTrusted is not the rule's target and checkServerTrusted really calls the pinning check
        assertTrue(TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", t)).isEmpty())
    }

    @Test fun hostnameVerifierAlwaysTrueStillFoundWithAnnotationBlockInTheMethod() {
        val t = """
            .class public Lcom/example/Hv;
            .implements Ljavax/net/ssl/HostnameVerifier;
            .method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
                .locals 1
                .annotation build Landroidx/annotation/Keep;
                .end annotation
                const/4 v0, 0x1
                return v0
            .end method
        """.trimIndent()
        assertEquals(1, TlsHostnameVerifierRule.scan(ctx("Lcom/example/Hv;", t)).size)
    }

    // ---- constant byte[] (new-array + fill-array-data) as IV / key ----

    private fun ivSmali(mid: String, arrLines: String = "0x0t\n            0x0t\n            0x0t\n            0x0t") = """
        .class public Lcom/example/Enc;
        .method public static enc()V
            .locals 6
            const/16 v1, 0x10
            new-array v0, v1, [B

            fill-array-data v0, :array_0
        $mid
            new-instance v5, Ljavax/crypto/spec/IvParameterSpec;

            invoke-direct {v5, v0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
            return-void

            :array_0
            .array-data 1
                $arrLines
            .end array-data
        .end method
    """.trimIndent()

    @Test fun constantArrayIvIsFlaggedAsStaticIv() {
        val r = CryptoStaticIvRule.scan(ctx("Lcom/example/Enc;", ivSmali("            .line 83\n            .local v0, \"IV\":[B")))
        assertEquals(1, r.size)
        assertTrue(r[0].detail.contains("all zero"))
    }

    @Test fun ivArrayThatIsFilledWithRandomBytesAfterTheConstantIsNotFlagged() {
        val mid = "    new-instance v2, Ljava/security/SecureRandom;\n    invoke-direct {v2}, Ljava/security/SecureRandom;-><init>()V\n    invoke-virtual {v2, v0}, Ljava/security/SecureRandom;->nextBytes([B)V"
        assertTrue(CryptoStaticIvRule.scan(ctx("Lcom/example/Enc;", ivSmali(mid))).isEmpty())
    }

    @Test fun ivArrayChangedWithAputIsNotFlagged() {
        val mid = "    const/4 v3, 0x0\n    aput-byte v3, v0, v3"
        assertTrue(CryptoStaticIvRule.scan(ctx("Lcom/example/Enc;", ivSmali(mid))).isEmpty())
    }

    @Test fun ivArrayFromAParameterIsNotFlagged() {
        val t = """
            .class public Lcom/example/Enc;
            .method public static enc([B)V
                .locals 2
                new-instance v1, Ljavax/crypto/spec/IvParameterSpec;
                invoke-direct {v1, p0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
                return-void
            .end method
        """.trimIndent()
        assertTrue(CryptoStaticIvRule.scan(ctx("Lcom/example/Enc;", t)).isEmpty())
    }

    @Test fun constantArrayKeyIsAHardcodedKeyAndTheValueIsNotPrinted() {
        val t = """
            .class public Lcom/example/Enc;
            .method public static enc()V
                .locals 4
                const/16 v1, 0x10
                new-array v0, v1, [B

                fill-array-data v0, :array_0

                new-instance v2, Ljavax/crypto/spec/SecretKeySpec;

                const-string v3, "AES"

                invoke-direct {v2, v0, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
                return-void

                :array_0
                .array-data 1
                    0x1t
                    0x2t
                    0x7ft
                    -0x1t
                .end array-data
            .end method
        """.trimIndent()
        val r = CryptoHardcodedKeyRule.scan(ctx("Lcom/example/Enc;", t))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.HIGH, r[0].severity)
        assertTrue(!r[0].detail.contains("7f"))
    }

    @Test fun gcmConstantNonceIsFlagged() {
        val t = """
            .class public Lcom/example/Enc;
            .method public static enc()V
                .locals 4
                const/16 v1, 0xc
                new-array v0, v1, [B

                fill-array-data v0, :array_0

                new-instance v2, Ljavax/crypto/spec/GCMParameterSpec;

                const/16 v3, 0x80

                invoke-direct {v2, v3, v0}, Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V
                return-void

                :array_0
                .array-data 1
                    0x1t
                    0x2t
                    0x3t
                .end array-data
            .end method
        """.trimIndent()
        assertEquals(1, CryptoStaticIvRule.scan(ctx("Lcom/example/Enc;", t)).size)
    }

    // ---- algorithm name passed to a hash helper as a constant ----

    private fun hashCaller(algo: String, call: String) = """
        .class public Lcom/example/Auth;
        .method public save(Ljava/lang/String;)V
            .locals 3
            const-string/jumbo v1, "$algo"

            $call

            move-result-object v0
            return-void
        .end method
    """.trimIndent()

    @Test fun md5ConstantPassedToAHashHelperIsFound() {
        val r = CryptoWeakHashRule.scan(ctx("Lcom/example/Auth;", hashCaller("MD5", "invoke-static {v1, p1}, Lcom/example/Encryption;->hash(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, r[0].severity)
    }

    @Test fun sha256ConstantPassedToAHashHelperIsQuiet() {
        assertTrue(CryptoWeakHashRule.scan(ctx("Lcom/example/Auth;", hashCaller("SHA-256", "invoke-static {v1, p1}, Lcom/example/Encryption;->hash(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"))).isEmpty())
    }

    @Test fun md5ConstantPassedToAnUnrelatedMethodIsQuiet() {
        assertTrue(CryptoWeakHashRule.scan(ctx("Lcom/example/Auth;", hashCaller("MD5", "invoke-static {v1, p1}, Lcom/example/Log;->tag(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"))).isEmpty())
    }

    @Test fun directGetInstanceIsNotReportedTwice() {
        val t = """
            .class public Lcom/example/H;
            .method public a()V
                .locals 2
                const-string v0, "MD5"
                invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
                return-void
            .end method
        """.trimIndent()
        assertEquals(1, CryptoWeakHashRule.scan(ctx("Lcom/example/H;", t)).size)
    }
}
