package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.90.0: ElfAnalyzer on synthetic ELF files (the real-file check against readelf is tools/native/oracle.py). Every flag has both states. */
class ElfAnalyzerTest {
    private fun parse(b: ByteArray) = ElfAnalyzer.parse(b)!!

    @Test fun stackRelroAndBindNowAreReadFromTheHeadersAndTheDynamicSection() {
        val good = parse(ElfTestBuilder.build())
        assertTrue(good.gnuStack); assertFalse(good.stackExecutable); assertEquals("full", good.relro); assertFalse(good.textrel)
        assertEquals("partial", parse(ElfTestBuilder.build(bindNow = false)).relro)
        assertEquals("none", parse(ElfTestBuilder.build(relro = false, bindNow = false)).relro)
        assertTrue(parse(ElfTestBuilder.build(stackExec = true)).stackExecutable)
        assertFalse(parse(ElfTestBuilder.build(withStack = false)).gnuStack)
        assertTrue(parse(ElfTestBuilder.build(textrel = true)).textrel)
        assertEquals("/data/local", parse(ElfTestBuilder.build(runpath = "/data/local")).runpath)
    }

    @Test fun importsComeFromTheDynamicSymbolTableNotFromTheTextOfTheFile() {
        val e = parse(ElfTestBuilder.build(imports = listOf("__stack_chk_fail", "__memcpy_chk", "strcpy", "malloc"), exports = listOf("Java_com_x_Native_run"),
            rodata = listOf("system is only a word in a string", "popen")))                      // names in DATA that are not imports
        assertEquals(listOf("__stack_chk_fail", "__memcpy_chk", "strcpy", "malloc"), e.imports)
        assertTrue(e.stackCanary); assertEquals(listOf("__memcpy_chk"), e.fortified); assertEquals(listOf("strcpy"), e.dangerous)
        assertEquals(1, e.exports)
        assertFalse("system" in e.importSet)                                                      // present as TEXT only
        val noCanary = parse(ElfTestBuilder.build(imports = listOf("malloc")))
        assertFalse(noCanary.stackCanary); assertTrue(noCanary.fortified.isEmpty())
    }

    @Test fun sonameNeededAndAlignment() {
        val e = parse(ElfTestBuilder.build(needed = listOf("libc.so", "libm.so"), soname = "libfoo.so", align = 0x1000))
        assertEquals("libfoo.so", e.soname); assertEquals(listOf("libc.so", "libm.so"), e.needed)
        assertEquals(0x1000L, e.minLoadAlign); assertFalse(e.aligned16k)
        assertTrue(parse(ElfTestBuilder.build(align = 0x4000)).aligned16k)
        assertTrue(parse(ElfTestBuilder.build(align = 0x10000)).aligned16k)
        assertTrue(parse(ElfTestBuilder.build(is64 = false, align = 0x1000)).aligned16k)        // the 16 KB rule is for the 64-bit ABIs
    }

    @Test fun elf32IsReadToo() {
        val e = parse(ElfTestBuilder.build(is64 = false, imports = listOf("__stack_chk_fail", "gets"), needed = listOf("libc.so")))
        assertFalse(e.is64); assertTrue(e.stackCanary); assertEquals(listOf("gets"), e.dangerous); assertEquals("full", e.relro)
    }

    @Test fun notElfAndTruncatedInputAreRejectedWithoutAnException() {
        assertNull(ElfAnalyzer.parse(ByteArray(10)))
        assertNull(ElfAnalyzer.parse("PK\u0003\u0004 this is a zip".toByteArray().copyOf(200)))
        val b = ElfTestBuilder.build(imports = listOf("a", "b")).copyOf(100)                      // cut inside the program headers
        assertNotNull(ElfAnalyzer.parse(b).let { it ?: "null" })                                  // no crash: either an info with fewer fields or null
    }

    @Test fun stringsComeFromDataSectionsOnly() {
        val b = ElfTestBuilder.build(imports = listOf("a_very_long_imported_symbol_name"), rodata = listOf("token=abcdefgh12345678", "tiny"))
        val found = ArrayList<String>(); ElfAnalyzer.forEachString(b, 8) { found.add(it) }
        assertTrue(found.contains("token=abcdefgh12345678"))
        assertFalse(found.any { it.contains("a_very_long_imported_symbol_name") })               // the symbol name table is not scanned
        assertFalse(found.contains("tiny"))                                                       // under the minimum length
    }
}
