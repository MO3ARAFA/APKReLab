package dev.apkrelab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.106.0: the agent's patch check and class classification (deterministic, one class). */
class ClassToolsTest {
    private val type = "Lcom/x/Pay;"
    private fun cls(body: String, t: String = type) = ".class public $t\n.super Ljava/lang/Object;\n.method public run()V\n    .locals 3\n$body    return-void\n.end method\n"
    private val ecb = "    const-string v0, \"AES/ECB/PKCS5Padding\"\n    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n"
    private val gcm = ecb.replace("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding")
    private val md5 = "    const-string v1, \"MD5\"\n    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;\n"
    private fun verify(orig: String, mod: String, asm: ((String) -> String?)? = { null }) = ClassTools.verifyEdit(type, orig, mod, "com.x", emptyList(), asm)

    @Test fun aPatchThatFixesTheFindingSaysSoAndOneThatAddsAnIssueToo() {
        val fix = verify(cls(ecb), cls(gcm))
        assertTrue(fix, fix.startsWith("VALID")); assertTrue(fix, fix.contains("Removed by the edit (1)") && fix.contains("ECB")); assertTrue(fix, fix.contains("NEW with the edit (0)"))
        val worse = verify(cls(ecb), cls(gcm + md5))
        assertTrue(worse, worse.contains("NEW with the edit (1)") && worse.contains("MD5"))
        val same = verify(cls(ecb), cls(ecb))                                                          // twin: no change, nothing removed or added
        assertTrue(same, same.contains("Removed by the edit (0)") && same.contains("NEW with the edit (0)"))
    }

    @Test fun anInvalidEditIsRejectedBeforeAnyComparison() {
        assertTrue(verify(cls(ecb), cls(gcm, "Lcom/x/Other;")).startsWith("INVALID: the edit declares"))
        assertTrue(verify(cls(ecb), cls(gcm).replace(".end method", "")).startsWith("INVALID: 1 .method"))
        assertTrue(verify(cls(ecb), cls(gcm)) { "line 5: mismatched input" }.startsWith("INVALID: the smali assembler rejects"))
        assertTrue(verify(cls(ecb), cls(gcm), null).startsWith("Structure OK"))                       // no assembler: said, not assumed
    }

    @Test fun classificationNamesTheSdkTheMergeAndTheAppEvidence() {
        val merged = ".class public final Lm42;\n.super Ljava/lang/Object;\n.field public final synthetic b:I\n.field public c:Ljava/lang/Object;\n"
        val m = ClassTools.classify("Lm42;", merged, "com.x", null, true)
        assertTrue(m, m.contains("R8 HORIZONTAL MERGE") && m.contains("SDK attribution: none"))
        val a = ClassTools.classify("Laq8;", ".class public final Laq8;\n.super Ljava/lang/Object;\n.field public a:I\n    invoke-static {}, Lcom/google/android/gms/measurement/internal/zza;->a()V\n", "com.x", "com.google.android", true)
        assertTrue(a, a.contains("attributed it to com.google.android") && a.contains("com.google.android (1)")); assertFalse(a.contains("MERGE"))
        val holder = ".class public final Lct1;\n.super Ljava/lang/Object;\n" + (1..12).joinToString("") { ".method public static m$it()V\n    return-void\n.end method\n" }
        assertTrue(ClassTools.classify("Lct1;", holder, "com.x", null, true).contains("R8 STATIC MERGE"))
        val appBound = ClassTools.classify("Lb;", ".class public Lb;\n.super Ljava/lang/Object;\n    sget-object v0, Lcom/x/Main;->a:I\n", "com.x", null, false)
        assertTrue(appBound, appBound.contains("not known yet") && appBound.contains("strong evidence of app code"))
    }
}
