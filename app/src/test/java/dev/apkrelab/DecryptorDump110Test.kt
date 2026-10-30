package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.1.0: the dump script hooks every string-table decryptor over the threshold; the overlay says how much of the table it resolved. */
class DecryptorDump110Test {
    private fun callsClass(type: String, target: String, n: Int): String {
        val sb = StringBuilder(".class public $type\n.super Ljava/lang/Object;\n.method public m()V\n    .locals 3\n")
        for (i in 1..n) sb.append("    invoke-static {v0}, ").append(target).append("(I)Ljava/lang/String;\n")
        return sb.append("    return-void\n.end method\n").toString()
    }

    @Test fun everyDecryptorOverTheThresholdIsHooked() {
        PostureScanner.clear()
        PostureScanner.observe("Lcom/x/A;", callsClass("Lcom/x/A;", "Lvs/C;->d", 3000), "com.x")
        PostureScanner.observe("Lcom/x/B;", callsClass("Lcom/x/B;", "Lq/E;->a", 2100), "com.x")
        PostureScanner.observe("Lcom/x/D;", callsClass("Lcom/x/D;", "Lh/H;->x", 500), "com.x")          // twin: an ordinary helper
        val md = PostureScanner.section()
        assertTrue(md, md.contains("vs.C.d(int) is called 3000 times; the static method q.E.a(int) is called 2100 times"))
        assertTrue(md, md.contains("Java.use('vs.C')['d']") && md.contains("Java.use('q.E')['a']"))
        assertTrue(md, md.contains("#decryptor\\tLvs/C;->d(I)Ljava/lang/String;") && md.contains("#decryptor\\tLq/E;->a(I)Ljava/lang/String;"))
        assertTrue(md, md.contains("save each block"))
        assertFalse(md, md.contains("h.H"))
        PostureScanner.clear()
    }

    @Test fun oneDecryptorKeepsOneBlock() {
        PostureScanner.clear()
        PostureScanner.observe("Lcom/x/A;", callsClass("Lcom/x/A;", "Lvs/C;->d", 3000), "com.x")
        val md = PostureScanner.section()
        assertEquals(1, Regex("#decryptor").findAll(md).count())
        assertFalse(md.contains("save each block"))
        PostureScanner.clear()
    }

    @Test fun coverageLine() {
        assertEquals("1,420 / 1,500 decryptor call sites resolved (94.7%)", StringOverlay.coverage(1420, 80))
        assertEquals("0 / 0 decryptor call sites resolved", StringOverlay.coverage(0, 0))
    }
}
