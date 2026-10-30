package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.86.0: the name/shape secret detectors give HIGH only with positive evidence (the value reaches a key / credential sink).
 * The cases are the shapes of the judged real cards: Read You `DESUtils.secret` (TP: a DES key) and the public strings that were HIGH before.
 */
class SecretsInversion0860Test {

    private val secret = "mJn':4Nbk};AMVFGEWiY!(8&gp1xOv@/"

    private fun cls(type: String, methods: String) = ".class public $type\n.super Ljava/lang/Object;\n" +
        ".field private static final secret:Ljava/lang/String; = \"$secret\"\n\n$methods"

    private val desUse = """
        .method public static encrypt([B)[B
            .locals 4
            sget-object v0, Lcom/x/DESUtils;->secret:Ljava/lang/String;
            invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
            move-result-object v0
            new-instance v1, Ljavax/crypto/spec/DESKeySpec;
            invoke-direct {v1, v0}, Ljavax/crypto/spec/DESKeySpec;-><init>([B)V
            return-object p0
        .end method
    """.trimIndent()

    private val noUse = """
        .method public static name()Ljava/lang/String;
            .locals 1
            sget-object v0, Lcom/x/DESUtils;->secret:Ljava/lang/String;
            return-object v0
        .end method
    """.trimIndent()

    private fun field(methods: String) = SecretsSensitiveFieldsRule.scan(RuleContext("Lcom/x/DESUtils;", 0, cls("Lcom/x/DESUtils;", methods), "com.x"))

    @Test fun aSecretFieldThatBecomesAKeyIsHigh() {                      // Read You DESUtils: the judged TP stays HIGH
        val f = field(desUse)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.HIGH, f[0].severity)
        assertTrue(f[0].detail.contains("cryptographic key"))
    }

    @Test fun theSameFieldWithoutAnyUseIsOnlyMedium() {
        val f = field(noUse)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity)
        assertEquals("MEDIUM", f[0].confidence)
        assertTrue(f[0].detail.contains("only evidence"))
    }

    @Test fun anInlinedConstantUsedAsAKeyCountsToo() {                    // a Kotlin const val is inlined: the literal, not the field, is used
        val inlined = """
            .method public static k()V
                .locals 3
                const-string v0, "$secret"
                invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
                move-result-object v0
                new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
                const-string v2, "AES"
                invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
                return-void
            .end method
        """.trimIndent()
        assertEquals(SecurityScanner.Severity.HIGH, field(inlined)[0].severity)
    }

    private val token = "Zq8vT2LmX9pR4wK7nB1cY6hJ3fD5sG0"

    private fun entropy(sink: String, sameMethod: Boolean): List<SecurityScanner.Finding> {
        val m1 = ".method public a()V\n    .locals 3\n    const-string v0, \"$token\"\n    const-string v1, \"accessToken\"\n" + (if (sameMethod) sink else "") + "    return-void\n.end method\n"
        val m2 = if (sameMethod) "" else ".method public b()V\n    .locals 3\n$sink    return-void\n.end method\n"
        return SecurityScanner.scanHighEntropyStrings("Lcom/x/Api;", 0, ".class public Lcom/x/Api;\n.super Ljava/lang/Object;\n$m1$m2")
            .filter { it.title.startsWith("High-entropy embedded string near") }
    }

    private val header = "    const-string v2, \"Authorization\"\n    invoke-virtual {v9, v2, v0}, Lokhttp3/Request\$Builder;->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request\$Builder;\n"

    @Test fun anEntropyStringSentAsAnAuthorizationHeaderIsHigh() {
        val f = entropy(header, true)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.HIGH, f[0].severity)
        assertTrue(f[0].detail.contains("Authorization"))
    }

    @Test fun theSameStringWithTheSinkInAnotherMethodIsMedium() {        // negative twin: co-occurrence is per method
        val f = entropy(header, false)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity)
    }

    @Test fun sinkLabels() {
        assertEquals("a Cipher / Mac key", SecretEvidence.sinkIn("invoke-virtual {v0, v1, v2}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V"))
        assertEquals("HTTP credentials", SecretEvidence.sinkIn("invoke-static {v0, v1}, Lokhttp3/Credentials;->basic(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"))
        assertNull(SecretEvidence.sinkIn("const-string v0, \"Authorization\""))                       // a header name alone is not a use
        assertNull(SecretEvidence.sinkIn("invoke-static {v0}, Landroid/util/Log;->d(Ljava/lang/String;)I"))
    }

    @Test fun aSanctumTokenIsASecretByItsFormatAndAKeyQueryParameterIsAUse() {
        assertEquals("a Laravel Sanctum access token (id|40 characters)", SecretEvidence.formatOf("1|8wAbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab"))
        assertNull(SecretEvidence.formatOf("1|short"))
        assertNull(SecretEvidence.formatOf("12|8wAbCdEfGhIjKlMnOpQrStUvWxYz0123456789A-"))     // a '-' is not in the format
        assertEquals("an API-key query parameter", SecretEvidence.sinkIn(
            "const-string v1, \"appid\"\n    invoke-virtual {v0, v1, v2}, Lokhttp3/HttpUrl\$Builder;->addQueryParameter(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/HttpUrl\$Builder;"))
        assertNull(SecretEvidence.sinkIn(                                                         // a query parameter with an ordinary name
            "const-string v1, \"lang\"\n    invoke-virtual {v0, v1, v2}, Lokhttp3/HttpUrl\$Builder;->addQueryParameter(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/HttpUrl\$Builder;"))
    }

    @Test fun anAuthTokenQueryParameterIsAUse() {                              // Allsafe NoteReceiver: ?auth_token=<hardcoded>
        assertEquals("an API-key query parameter", SecretEvidence.sinkIn(
            "const-string v8, \"auth_token\"\n    invoke-virtual {v7, v8, v9}, Lokhttp3/HttpUrl\$Builder;->addQueryParameter(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/HttpUrl\$Builder;"))
        assertNull(SecretEvidence.sinkIn(
            "const-string v8, \"auth_token\"\n    invoke-static {v8}, Landroid/util/Log;->d(Ljava/lang/String;)I"))     // the name without a query call
    }
}

