package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.86.1: gaps and calibrations found by the recall-by-injection kit (tools/recall). Every positive has a negative twin. */
class RecallFixes0861Test {

    private fun scan(rule: ScanRule, type: String, text: String) = rule.scan(RuleContext(type, 0, text, "com.x"))

    private fun cls(body: String, fields: String = "") = ".class public Lcom/x/K;\n.super Ljava/lang/Object;\n$fields\n$body\n"

    // ---- hard-coded key hidden one step (cases 41 / 42)
    private fun keyMethod(prefix: String) = """
        .method public static key()Ljavax/crypto/spec/SecretKeySpec;
            .locals 4
            $prefix
            new-instance v2, Ljavax/crypto/spec/SecretKeySpec;
            const-string v3, "AES"
            invoke-direct {v2, v0, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
            return-object v2
        .end method
    """.trimIndent()

    @Test fun aBase64DecodedLiteralKeyIsAHardcodedKey() {
        val t = cls(keyMethod("const-string v0, \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n            const/4 v1, 0x0\n            invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B\n            move-result-object v0"))
        val f = scan(CryptoHardcodedKeyRule, "Lcom/x/K;", t)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.HIGH, f[0].severity)
        assertTrue(f[0].detail.contains("Base64"))
    }

    @Test fun aBase64DecodedValueThatIsNotALiteralIsNotReported() {          // negative twin: the encoded text comes from a parameter
        val t = cls(keyMethod("const/4 v1, 0x0\n            invoke-static {p0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B\n            move-result-object v0").replace("key()", "key(Ljava/lang/String;)").replace(".locals 4", ".locals 4"))
        assertTrue(scan(CryptoHardcodedKeyRule, "Lcom/x/K;", t).isEmpty())
    }

    private val clinit = """
        .method static constructor <clinit>()V
            .locals 2
            const/16 v0, 0x10
            new-array v0, v0, [B
            fill-array-data v0, :k
            sput-object v0, Lcom/x/K;->KEY:[B
            return-void
            :k
            .array-data 1
                0x41t 0x42t 0x43t 0x44t 0x45t 0x46t 0x47t 0x48t 0x49t 0x4at 0x4bt 0x4ct 0x4dt 0x4et 0x4ft 0x50t
            .end array-data
        .end method
    """.trimIndent()

    @Test fun aStaticByteArrayFieldFilledFromConstantsIsAHardcodedKey() {
        val t = cls(clinit + "\n" + keyMethod("sget-object v0, Lcom/x/K;->KEY:[B"), ".field private static final KEY:[B")
        val f = scan(CryptoHardcodedKeyRule, "Lcom/x/K;", t)
        assertEquals(1, f.size)
        assertTrue(f[0].detail.contains("static byte array KEY"))
    }

    @Test fun aStaticByteArrayFieldThatIsNeverFilledFromConstantsIsNotReported() {   // negative twin: <clinit> fills it from SecureRandom
        val rnd = """
            .method static constructor <clinit>()V
                .locals 2
                const/16 v0, 0x10
                new-array v0, v0, [B
                sput-object v0, Lcom/x/K;->KEY:[B
                return-void
            .end method
        """.trimIndent()
        val t = cls(rnd + "\n" + keyMethod("sget-object v0, Lcom/x/K;->KEY:[B"), ".field private static final KEY:[B")
        assertTrue(scan(CryptoHardcodedKeyRule, "Lcom/x/K;", t).isEmpty())
    }

    // ---- SHA1PRNG with a constant seed is HIGH, a runtime seed stays MEDIUM
    private fun prng(seed: String) = cls("""
        .method public static r()Ljava/security/SecureRandom;
            .locals 3
            const-string v0, "SHA1PRNG"
            invoke-static {v0}, Ljava/security/SecureRandom;->getInstance(Ljava/lang/String;)Ljava/security/SecureRandom;
            move-result-object v0
            $seed
            invoke-virtual {v0, v1}, Ljava/security/SecureRandom;->setSeed([B)V
            return-object v0
        .end method
    """.trimIndent())

    @Test fun aConstantSha1PrngSeedIsHighAndARuntimeSeedIsMedium() {
        val c = scan(CryptoSha1prngSeedRule, "Lcom/x/K;", prng("const-string v1, \"fixed-seed\"\n            invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B\n            move-result-object v1"))
        assertEquals(SecurityScanner.Severity.HIGH, c[0].severity)
        val r = scan(CryptoSha1prngSeedRule, "Lcom/x/K;", prng("invoke-static {}, Ljava/lang/System;->nanoTime()J\n            move-result-wide v1\n            invoke-static {v1, v2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;\n            move-result-object v1\n            invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B\n            move-result-object v1"))
        assertEquals(SecurityScanner.Severity.MEDIUM, r[0].severity)
    }

    // ---- RSA under 1024 bits is HIGH, 1024 stays MEDIUM
    private fun rsa(bits: String) = cls("""
        .method public static kp()Ljava/security/KeyPairGenerator;
            .locals 2
            const-string v0, "RSA"
            invoke-static {v0}, Ljava/security/KeyPairGenerator;->getInstance(Ljava/lang/String;)Ljava/security/KeyPairGenerator;
            move-result-object v0
            const/16 v1, $bits
            invoke-virtual {v0, v1}, Ljava/security/KeyPairGenerator;->initialize(I)V
            return-object v0
        .end method
    """.trimIndent())

    @Test fun rsaBelow1024BitsIsHighAnd1024IsMedium() {
        assertEquals(SecurityScanner.Severity.HIGH, scan(WeakKeySizeRule, "Lcom/x/K;", rsa("0x200"))[0].severity)
        assertEquals(SecurityScanner.Severity.MEDIUM, scan(WeakKeySizeRule, "Lcom/x/K;", rsa("0x400"))[0].severity)
        assertTrue(scan(WeakKeySizeRule, "Lcom/x/K;", rsa("0x800")).isEmpty())
    }

    // ---- an empty implicit mutable PendingIntent is MEDIUM, one that names its target stays LOW
    private fun pending(named: Boolean) = cls("""
        .method public static pi(Landroid/content/Context;)Landroid/app/PendingIntent;
            .locals 4
            new-instance v0, Landroid/content/Intent;
            invoke-direct {v0}, Landroid/content/Intent;-><init>()V
            ${if (named) "invoke-virtual {v0, p0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;" else ""}
            const/4 v1, 0x0
            invoke-static {p0, v1, v0, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
            move-result-object v2
            return-object v2
        .end method
    """.trimIndent())

    @Test fun aRemoteViewsTemplateStaysLowBecauseItMustBeMutable() {                       // Catima ListWidget, found by the 31-app regression
        val t = pending(false).replace("    return-object v2\n.end method",
            "    new-instance v3, Landroid/widget/RemoteViews;\n    invoke-virtual {v3, v1, v2}, Landroid/widget/RemoteViews;->setPendingIntentTemplate(ILandroid/app/PendingIntent;)V\n    return-object v2\n.end method")
        assertEquals(SecurityScanner.Severity.LOW, scan(PendingintentMutableRule, "Lcom/x/K;", t)[0].severity)
    }

    @Test fun anEmptyImplicitMutablePendingIntentIsMediumAndANamedOneIsLow() {
        assertEquals(SecurityScanner.Severity.MEDIUM, scan(PendingintentMutableRule, "Lcom/x/K;", pending(false))[0].severity)
        assertEquals(SecurityScanner.Severity.LOW, scan(PendingintentMutableRule, "Lcom/x/K;", pending(true))[0].severity)
    }

    // ---- a secret field used by ANOTHER class (case 03)
    private val tokenClass = ".class public Lcom/x/Consts;\n.super Ljava/lang/Object;\n.field public static final API_TOKEN:Ljava/lang/String; = \"Zq8vT2LmX9pR4wK7nB1cY6hJ3fD5sG0aE\"\n"

    private fun reader(body: String) = ".class public Lcom/x/Interceptor;\n.super Ljava/lang/Object;\n.method public a(Lokhttp3/Request\$Builder;)V\n    .locals 3\n" +
        "    sget-object v0, Lcom/x/Consts;->API_TOKEN:Ljava/lang/String;\n$body    return-void\n.end method\n"

    private fun fieldCard(): SecurityScanner.Finding? =
        SecretsSensitiveFieldsRule.scan(RuleContext("Lcom/x/Consts;", 0, tokenClass, "com.x")).firstOrNull()?.also { it.ruleId = "secrets-sensitive-fields" }   // the registry sets the id

    @Test fun aTokenFieldReadByAnInterceptorThatSendsItIsRaisedToHigh() {
        SecurityScanner.secretFieldsUsed.clear()
        val card = fieldCard()!!
        assertEquals(SecurityScanner.Severity.MEDIUM, card.severity)                       // its own class never uses it
        SecurityScanner.scanSmali("Lcom/x/Interceptor;", 1, reader("    const-string v1, \"Authorization\"\n    invoke-virtual {p1, v1, v0}, Lokhttp3/Request\$Builder;->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request\$Builder;\n"), "com.x")
        assertTrue("Lcom/x/Consts;->API_TOKEN" in SecurityScanner.secretFieldsUsed)
        assertEquals(1, FindingPolish.raiseUsedSecretFields(listOf(card)))
        assertEquals(SecurityScanner.Severity.HIGH, card.severity)
        assertEquals(0, FindingPolish.raiseUsedSecretFields(listOf(card)))                // idempotent
        SecurityScanner.secretFieldsUsed.clear()
    }

    @Test fun aTokenFieldThatAnotherClassOnlyLogsStaysMedium() {                          // negative twin
        SecurityScanner.secretFieldsUsed.clear()
        val card = fieldCard()!!
        SecurityScanner.scanSmali("Lcom/x/Interceptor;", 1, reader("    const-string v1, \"T\"\n    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n"), "com.x")
        assertTrue(SecurityScanner.secretFieldsUsed.isEmpty())
        assertEquals(0, FindingPolish.raiseUsedSecretFields(listOf(card)))
        assertEquals(SecurityScanner.Severity.MEDIUM, card.severity)
    }
}

