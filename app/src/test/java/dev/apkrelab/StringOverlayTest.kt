package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.102.0: the decoded-strings overlay (an app that decrypts every string through one static (I)String method; the owner imports a dump taken on a device). */
class StringOverlayTest {
    private val dec = "Lvs/C;->d(I)Ljava/lang/String;"
    private fun overlay(vararg p: Pair<Int, String>) = StringOverlay(dec, mapOf(*p))
    private fun cls(body: String) = ".class public Lcom/example/Pay;\n.super Ljava/lang/Object;\n.method public run()V\n    .locals 3\n$body\n    return-void\n.end method\n"
    private fun ctx(text: String) = RuleContext("Lcom/example/Pay;", 0, text, "com.example")

    // ---- parsing ----
    @Test fun aTsvDumpWithAHeaderQuotedStringsAndAMultiLineString() {
        val p = StringOverlay.parse("#decryptor\t$dec\n12\t\"AES/ECB/PKCS5Padding\"\n13\thttp://api.example.com/v1\n14\tline one\nline two\n")
        assertEquals(dec, p.method)
        assertEquals("AES/ECB/PKCS5Padding", p.strings[12]); assertEquals("http://api.example.com/v1", p.strings[13]); assertEquals("line one\nline two", p.strings[14])
        assertEquals(3, p.strings.size)
    }

    @Test fun jsonDumpsInThreeShapesAndAMissingMethodNeedsAFallback() {
        assertEquals("a", StringOverlay.parse("{\"method\":\"$dec\",\"strings\":{\"5\":\"a\"}}").strings[5])
        assertEquals("b", StringOverlay.parse("{\"7\":\"b\"}").strings[7])
        assertEquals("c", StringOverlay.parse("[{\"i\":9,\"s\":\"c\"}]").strings[9])
        assertNull(StringOverlay.from("5\tabc\n", null))                                   // no header and no known decryptor: nothing is guessed
        assertEquals(dec, StringOverlay.from("5\tabc\n", dec)!!.method)
        assertNull(StringOverlay.from("#decryptor\t$dec\n", null))                         // twin: a header with no strings is not an overlay
    }

    // ---- the rewrite ----
    @Test fun aConstantIndexCallBecomesAConstString() {
        val t = cls("    const/16 v0, 0x1a2\n    invoke-static {v0}, $dec\n    .line 9\n    move-result-object v0\n    invoke-virtual {v0}, Ljava/lang/String;->length()I")
        val out = overlay(0x1a2 to "AES/ECB/PKCS5Padding").apply(t, "Lcom/example/Pay;")
        assertTrue(out.contains("const-string v0, \"AES/ECB/PKCS5Padding\""))
        assertFalse(out.contains("invoke-static {v0}, $dec")); assertFalse(out.contains("move-result-object v0"))
        assertTrue(out.contains(".line 9"))                                                   // the directive between the call and move-result stays
        assertTrue(out.contains("length()I"))                                                 // the rest of the method is untouched
    }

    @Test fun theStringRulesSeeThePlaintextAfterTheOverlayAndNotBefore() {
        val t = cls("    const/16 v1, 0x1a2\n    invoke-static {v1}, $dec\n    move-result-object v1\n    invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;")
        assertTrue(CryptoCipherRule.scan(ctx(t)).isEmpty())                                   // blind: the cipher name is encrypted
        val ov = overlay(0x1a2 to "AES/ECB/PKCS5Padding")
        val f = CryptoCipherRule.scan(ctx(ov.apply(t, "Lcom/example/Pay;")))
        assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.HIGH, f[0].severity)
        // twin: a safe cipher name decoded the same way gives no finding
        assertTrue(CryptoCipherRule.scan(ctx(overlay(0x1a2 to "AES/GCM/NoPadding").apply(t, "x"))).isEmpty())
    }

    @Test fun whatCannotBeResolvedIsLeftAloneAndCounted() {
        val ov = overlay(1 to "one")
        val missing = cls("    const/4 v0, 0x2\n    invoke-static {v0}, $dec\n    move-result-object v0")                       // index not in the dump
        assertEquals(missing, ov.apply(missing, "A"))
        val param = cls("    invoke-static {p1}, $dec\n    move-result-object v0")                                                     // computed / parameter index
        assertEquals(param, ov.apply(param, "B"))
        val label = cls("    const/4 v0, 0x1\n    :goto_0\n    invoke-static {v0}, $dec\n    move-result-object v0")                  // a label: the register may come from elsewhere
        assertEquals(label, ov.apply(label, "C"))
        val clobbered = cls("    const/4 v0, 0x1\n    add-int/lit8 v0, v0, 0x1\n    invoke-static {v0}, $dec\n    move-result-object v0")   // overwritten in between
        assertEquals(clobbered, ov.apply(clobbered, "D"))
        val noMove = cls("    const/4 v0, 0x1\n    invoke-static {v0}, $dec\n    invoke-static {}, Lx/Y;->z()V")                // result not taken
        assertEquals(noMove, ov.apply(noMove, "E"))
        assertEquals(0, ov.replaced); assertEquals(5, ov.unresolved)
        val other = cls("    const/4 v0, 0x1\n    invoke-static {v0}, Lother/Z;->d(I)Ljava/lang/String;\n    move-result-object v0")   // twin: another class's method with the same name and index
        assertEquals(other, ov.apply(other, "F"))
    }

    @Test fun rangeFormNegativeIndexAndCountingOncePerClass() {
        val ov = overlay(-1 to "neg", 7 to "seven")
        val t = cls("    const/4 v0, -0x1\n    invoke-static/range {v0 .. v0}, $dec\n    move-result-object v1\n    const/4 v2, 0x7\n    invoke-static {v2}, $dec\n    move-result-object v2")
        val out = ov.apply(t, "Lcom/example/Pay;")
        assertTrue(out.contains("const-string v1, \"neg\"")); assertTrue(out.contains("const-string v2, \"seven\""))
        ov.apply(t, "Lcom/example/Pay;"); ov.apply(t, "Lcom/example/Pay;")                      // the grouped analysis reads a class several times
        assertEquals(2, ov.replaced)
    }

    @Test fun smaliEscapesAndAClassThatNeverCallsTheDecryptorIsReturnedUnchanged() {
        assertEquals("a\\\"b\\\\c\\n\\u0001", StringOverlay.escape("a\"b\\c\n\u0001"))
        val t = cls("    const-string v0, \"plain\"")
        assertTrue(overlay(1 to "x").apply(t, "G") === t)                                        // same instance: nothing was copied
        val ov = overlay(3 to "say \"hi\"\n")
        val out = ov.apply(cls("    const/4 v0, 0x3\n    invoke-static {v0}, $dec\n    move-result-object v0"), "H")
        assertTrue(out.contains("const-string v0, \"say \\\"hi\\\"\\n\""))
    }

    @Test fun theCurrentOverlayIsAppliedByViewAndOffWhenNull() {
        val t = cls("    const/4 v0, 0x3\n    invoke-static {v0}, $dec\n    move-result-object v0")
        try {
            StringOverlay.current = overlay(3 to "x")
            assertTrue(StringOverlay.view(t, "K").contains("const-string v0, \"x\""))
            StringOverlay.current = null
            assertEquals(t, StringOverlay.view(t, "K"))                                          // the switch the mutation check flips
        } finally { StringOverlay.current = null }
    }
}
