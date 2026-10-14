package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.66.4: regression tests for the false positives found in the Exness / JustMarkets reports (hand-written smali). */
class FpFixes0664Test {

    private fun ctx(type: String, text: String) = RuleContext(type, 0, text, "com.example")

    @Test fun plainTlsIsNotFlaggedButTlsV1Is() {
        fun smali(proto: String) = """
            .class public Lcom/example/Net;
            .method public a()V
                .locals 1
                const-string v0, "$proto"
                invoke-static {v0}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
                return-void
            .end method
        """.trimIndent()
        assertTrue(TlsProtocolVersionRule.scan(ctx("Lcom/example/Net;", smali("TLS"))).isEmpty())
        assertEquals(1, TlsProtocolVersionRule.scan(ctx("Lcom/example/Net;", smali("TLSv1"))).size)
    }

    @Test fun binderDescriptorFieldIsNotASecret() {
        val t = """
            .class public Lcom/example/AdIdInterface;
            .field private static final INTERFACE_TOKEN:Ljava/lang/String; = "com.google.android.gms.ads.identifier.internal.IAdvertisingIdService"
        """.trimIndent()
        assertTrue(SecretsSensitiveFieldsRule.scan(ctx("Lcom/example/AdIdInterface;", t)).isEmpty())
    }

    @Test fun cipherTransformationIsAName() {
        assertTrue(SecurityScanner.looksLikeName("RSA/ECB/PKCS1Padding"))
        assertTrue(SecurityScanner.looksLikeName("SHA256withRSA"))
        assertTrue(!SecurityScanner.looksLikeName("q8Zx3KpL0aVb7Nn2Tt5W"))
    }

    @Test fun sslErrorProceedBehindACheckIsMedium() {
        val t = """
            .class public Lcom/example/Wvc;
            .method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
                .locals 1
                if-eqz p3, :cond_0
                invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
                :cond_0
                return-void
            .end method
        """.trimIndent()
        val r = WebviewSslErrorRule.scan(ctx("Lcom/example/Wvc;", t))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, r[0].severity)
    }

    @Test fun sslErrorBlanketProceedStaysHigh() {
        val t = """
            .class public Lcom/example/Wvc;
            .method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
                .locals 0
                invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
                return-void
            .end method
        """.trimIndent()
        val r = WebviewSslErrorRule.scan(ctx("Lcom/example/Wvc;", t))
        assertEquals(SecurityScanner.Severity.HIGH, r[0].severity)
    }

    @Test fun noOpTrustManagerIsLoweredInObfuscatedCode() {
        val t = """
            .class public Lr9e;
            .implements Ljavax/net/ssl/X509TrustManager;
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .locals 0
                return-void
            .end method
        """.trimIndent()
        val c = RuleContext("Lr9e;", 0, t, "com.example")
        val raw = TlsTrustmanagerRule.scan(c)
        assertEquals(SecurityScanner.Severity.CRITICAL, raw[0].severity)
        raw.forEach { it.ruleId = TlsTrustmanagerRule.id; it.scope = SecurityScanner.Scope.OBF }
        val polished = FindingPolish.apply(raw, "Lr9e;")
        assertEquals(SecurityScanner.Severity.HIGH, polished[0].severity)
    }

    @Test fun threeArgCheckServerTrustedIsNotTheNoOpPattern() {
        val t = """
            .class public Lcom/example/Tm;
            .implements Ljavax/net/ssl/X509TrustManager;
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljava/net/Socket;)V
                .locals 0
                return-void
            .end method
        """.trimIndent()
        assertTrue(TlsTrustmanagerRule.scan(ctx("Lcom/example/Tm;", t)).isEmpty())
    }
}
