package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Test

/** 1.1.0: a credential stored as the result of an encrypting call is not "plaintext" (APKReLab's own Signing: putString("kp", SecureStore.encrypt(pw))). */
class PrefsEncrypted110Test {
    private fun cls(value: String) = """
.class public Lcom/x/Store;
.super Ljava/lang/Object;
.method public save(Landroid/content/SharedPreferences${'$'}Editor;Ljava/lang/String;)V
    .locals 4
    const-string v0, "password"
$value
    invoke-interface {p1, v0, v1}, Landroid/content/SharedPreferences${'$'}Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences${'$'}Editor;
    return-void
.end method
"""

    private fun cards(value: String) = AndroGoatChecks.scan("Lcom/x/Store;", 0, cls(value), "com.x").count { it.title.startsWith("Sensitive value saved to SharedPreferences") }

    private val viaEncrypt = "    invoke-static {p2}, Lcom/x/SecureStore;->encrypt(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1"
    private val viaCipher = "    invoke-virtual {v2, v3}, Ljavax/crypto/Cipher;->doFinal([B)[B\n    move-result-object v3\n    const/4 v2, 0x2\n" +
        "    invoke-static {v3, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;\n    move-result-object v1"

    @Test fun anEncryptedValueIsNotPlaintext() {
        assertEquals(0, cards(viaEncrypt))
        assertEquals(0, cards(viaCipher))
    }

    @Test fun twinsStayPlaintext() {
        assertEquals(1, cards("    move-object v1, p2"))                                                                        // the parameter itself
        assertEquals(1, cards(viaCipher.replace("Ljavax/crypto/Cipher;->doFinal([B)[B", "Ljava/lang/String;->getBytes()[B")))   // Base64 is an encoding, not encryption
        assertEquals(1, cards(viaEncrypt + "\n    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;\n    move-result-object v1"))   // overwritten after the encryption
    }

    @Test fun theGuardIsTheSwitchedPart() {
        AndroGoatChecks.ENCRYPTED_PUT = false
        try { assertEquals(1, cards(viaEncrypt)) } finally { AndroGoatChecks.ENCRYPTED_PUT = true }
    }
}
