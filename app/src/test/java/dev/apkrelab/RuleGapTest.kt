package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.50.2: the two InsecureBankv2 gaps, on tiny hand-written smali (field-initializer key, credential FIELDS in a Log message). */
class RuleGapTest {

    private fun ctx(type: String, text: String) = RuleContext(type, 0, text, "com.example")

    @Test fun keyFieldSetFromLiteralInInitIsReported() {
        val t = """
            .class public Lcom/example/CryptoClass;
            .field key:Ljava/lang/String;
            .method public constructor <init>()V
                const-string v0, "This is the super secret key 123"
                .line 17
                iput-object v0, p0, Lcom/example/CryptoClass;->key:Ljava/lang/String;
                return-void
            .end method
            .method public dec(Ljava/lang/String;)Ljava/lang/String;
                iget-object v2, p0, Lcom/example/CryptoClass;->key:Ljava/lang/String;
                new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
                invoke-direct {v1, v2, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
                return-object v3
            .end method
        """.trimIndent()
        val r = CryptoHardcodedKeyRule.scan(ctx("Lcom/example/CryptoClass;", t))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.HIGH, r[0].severity)
    }

    @Test fun staticFinalKeyConstantIsReported() {
        val t = """
            .class public Lcom/example/C;
            .field private static final SECRET_KEY:Ljava/lang/String; = "0123456789abcdef"
            .method public x()V
                new-instance v1, Ljavax/crypto/Cipher;
                return-void
            .end method
        """.trimIndent()
        val r = CryptoHardcodedKeyRule.scan(ctx("Lcom/example/C;", t))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, r[0].severity)
    }

    @Test fun nonKeyNamedFieldOrNonCryptoClassIsIgnored() {
        val a = """
            .class public Lcom/example/C;
            .field private static final TAG:Ljava/lang/String; = "CryptoClassTagX"
            .method public x()V
                new-instance v1, Ljavax/crypto/Cipher;
                return-void
            .end method
        """.trimIndent()
        assertTrue(CryptoHardcodedKeyRule.scan(ctx("Lcom/example/C;", a)).isEmpty())
        val b = """
            .class public Lcom/example/D;
            .field private static final API_KEY:Ljava/lang/String; = "abcdefgh12345678"
        """.trimIndent()
        assertTrue(CryptoHardcodedKeyRule.scan(ctx("Lcom/example/D;", b)).isEmpty())
    }

    @Test fun keystoreAliasIsIgnored() {
        val t = """
            .class public Lcom/example/K;
            .field private static final KEY:Ljava/lang/String; = "my_key_alias_01"
            .method public x()V
                const-string v0, "AndroidKeyStore"
                new-instance v1, Ljavax/crypto/Cipher;
                return-void
            .end method
        """.trimIndent()
        assertTrue(CryptoHardcodedKeyRule.scan(ctx("Lcom/example/K;", t)).isEmpty())
    }

    @Test fun logMessageBuiltFromCredentialFieldsIsReported() {
        val t = """
            .class public Lcom/example/DoLogin;
            .method postData(Ljava/lang/String;)V
                .locals 5
                const-string v1, "Successful Login:"
                new-instance v2, Ljava/lang/StringBuilder;
                const-string v3, ", account="
                invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
                iget-object v3, p0, Lcom/example/DoLogin;->username:Ljava/lang/String;
                iget-object v4, p0, Lcom/example/DoLogin;->password:Ljava/lang/String;
                invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method
        """.trimIndent()
        val r = LogCredentialObjectRule.scan(ctx("Lcom/example/DoLogin;", t))
        assertEquals(1, r.size)
        assertTrue(r[0].detail.contains("password"))
    }

    @Test fun usernameOnlyFieldIsNotEnough() {
        val t = """
            .class public Lcom/example/A;
            .method m()V
                .locals 5
                new-instance v2, Ljava/lang/StringBuilder;
                invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
                iget-object v3, p0, Lcom/example/A;->username:Ljava/lang/String;
                invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method
        """.trimIndent()
        assertTrue(LogCredentialObjectRule.scan(ctx("Lcom/example/A;", t)).isEmpty())
    }

    @Test fun logAndCredentialObjectFarApartAreNotLinked() {
        // a credential-named object and a StringBuilder early in a long method, the Log call 3000+ chars later: no finding
        val filler = (1..120).joinToString("\n") { "    const/4 v9, 0x$it" }
        val t = """
            .class public Lcom/example/Main;
            .method onCreate()V
                .locals 5
                new-instance v1, Lcom/example/TokenData;
                new-instance v2, Ljava/lang/StringBuilder;
                invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
        """.trimIndent() + "\n" + filler + "\n" + """
                invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
                return-void
            .end method
        """.trimIndent()
        assertTrue(LogCredentialObjectRule.scan(ctx("Lcom/example/Main;", t)).isEmpty())
    }
}
