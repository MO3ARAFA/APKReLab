package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.94.0: InjuredAndroid's DES challenge, in the same shape as its smali; a key from a constant of another class is found after the scan, a runtime key is not. */
class CrossClassKey0940Test {
    private fun h(src: String) = """
        .class public final Lb/h;
        .super Ljava/lang/Object;
        .field private static final a:[B
        .method static constructor <clinit>()V
            .locals 2
            $src
            sput-object v0, Lb/h;->a:[B
            return-void
        .end method
        .method static b()[B
            .locals 1
            sget-object v0, Lb/h;->a:[B
            return-object v0
        .end method
    """.trimIndent()

    private val k = """
        .class public final Lb/k;
        .super Ljava/lang/Object;
        .field private static final a:[B
        .method static constructor <clinit>()V
            .locals 1
            invoke-static {}, Lb/h;->b()[B
            move-result-object v0
            sput-object v0, Lb/k;->a:[B
            return-void
        .end method
        .method public static d(Ljava/lang/String;)V
            .locals 3
            new-instance v1, Ljavax/crypto/spec/DESKeySpec;
            sget-object v2, Lb/k;->a:[B
            invoke-direct {v1, v2}, Ljavax/crypto/spec/DESKeySpec;-><init>([B)V
            return-void
        .end method
    """.trimIndent()

    private fun run(hSrc: String): List<SecurityScanner.Finding> {
        SecurityScanner.clearKeyTracking()
        val inK = SecurityScanner.scanSmali("Lb/k;", 1, k, "b")                                  // the user of the key is scanned FIRST: the order must not matter
        SecurityScanner.scanSmali("Lb/h;", 0, h(hSrc), "b")
        return inK.filter { it.title == "Hardcoded encryption key" } + FindingPolish.resolvePendingKeys()
    }

    @Test fun aDesKeyFromABase64ConstantInAnotherClassIsFound() {
        val f = run("const-string v0, \"Q2FwdHVyM1RoMXM=\"\n    const/4 v1, 0x0\n    invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B\n    move-result-object v0")
        assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.HIGH, f[0].severity); assertTrue(f[0].detail.contains("DESKeySpec")); assertEquals("crypto-hardcoded-key", f[0].ruleId)
    }

    @Test fun aKeyFilledAtRunTimeIsNotAHardcodedKey() {                                            // twin: the bytes come from SecureRandom
        val f = run("new-instance v1, Ljava/security/SecureRandom;\n    const/16 v0, 0x8\n    new-array v0, v0, [B\n    invoke-virtual {v1, v0}, Ljava/security/SecureRandom;->nextBytes([B)V")
        assertTrue(f.isEmpty())
    }

    @Test fun aLiteralDesKeyInTheSameMethodIsFoundToo() {
        val t = ".class public Lb/z;\n.super Ljava/lang/Object;\n.method public static d()V\n    .locals 3\n    const-string v0, \"Captur3Th1s\"\n    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B\n    move-result-object v2\n    new-instance v1, Ljavax/crypto/spec/DESKeySpec;\n    invoke-direct {v1, v2}, Ljavax/crypto/spec/DESKeySpec;-><init>([B)V\n    return-void\n.end method\n"
        SecurityScanner.clearKeyTracking()
        assertEquals(1, SecurityScanner.scanSmali("Lb/z;", 0, t, "b").count { it.title == "Hardcoded encryption key" })
    }

    @Test fun anExportedProviderThatChecksTheCallersSignatureIsLowAndOneThatDoesNotStaysHigh() {      // K-9 Mail SettingsProvider
        SecurityScanner.clearKeyTracking()
        val checked = ".class public Lapp/k9/SettingsProvider;\n.super Landroid/content/ContentProvider;\n.method public openFile()V\n    .locals 2\n    invoke-virtual {p0}, Landroid/content/ContentProvider;->getCallingPackage()Ljava/lang/String;\n    invoke-virtual {v0}, Landroid/content/pm/SigningInfo;->getSigningCertificateHistory()[Landroid/content/pm/Signature;\n    return-void\n.end method\n"
        SecurityScanner.scanSmali("Lapp/k9/SettingsProvider;", 0, checked, "app.k9")
        fun card(name: String) = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Exported provider without a permission: $name", "d", "r", null, -1, -1, "CWE-926").also { it.ruleId = "manifest-exported-components" }
        val a = card("app.k9.SettingsProvider"); val b = card("app.k9.OtherProvider")
        assertEquals(1, FindingPolish.lowerCallerVerified(listOf(a, b)))
        assertEquals(SecurityScanner.Severity.LOW, a.severity); assertTrue(a.detail.contains("checks the CALLER"))
        assertEquals(SecurityScanner.Severity.HIGH, b.severity)                                         // twin: no check in its code
        SecurityScanner.clearKeyTracking()
        SecurityScanner.scanSmali("Lapp/k9/SettingsProvider;", 0, checked.replace("getSigningCertificateHistory()[Landroid/content/pm/Signature;", "getFoo()V"), "app.k9")
        val c = card("app.k9.SettingsProvider")
        assertEquals(0, FindingPolish.lowerCallerVerified(listOf(c)))                                   // twin: the caller's package is read but nothing verifies it
    }

    private fun nat(body: String) = ".class public Lm/C;\n.super Ljava/lang/Object;\n.implements Ljava/io/Serializable;\n.field private ptr:J\n$body"
    private fun natCards(t: String) = SecurityScanner.scanSmali("Lm/C;", 0, t, "m").filter { it.title == "Native method in a Serializable/Parcelable class" }

    @Test fun aNativeMethodIsHighOnlyWhenDeserialisationCallsIt() {
        // OVAA: finalize() hands the restored pointer to native code
        val ovaa = nat(".method private native freePtr(J)V\n.end method\n.method protected finalize()V\n    .locals 2\n    iget-wide v0, p0, Lm/C;->ptr:J\n    invoke-direct {p0, v0, v1}, Lm/C;->freePtr(J)V\n    return-void\n.end method\n")
        assertEquals(SecurityScanner.Severity.HIGH, natCards(ovaa).single().severity)
        // Organic Maps: a static native getter with no parameters: nothing restored can reach it
        assertTrue(natCards(nat(".method private static native nativeGetBookmarkIconNames()[Ljava/lang/String;\n.end method\n")).isEmpty())
        // a native method with parameters that no hook calls: LOW
        assertEquals(SecurityScanner.Severity.LOW, natCards(nat(".method private static native nativeGetSorting(JZ)[I\n.end method\n")).single().severity)
    }
}

