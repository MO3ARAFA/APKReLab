package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Test

/** 0.86.2: SecurityScanner.codePackage must not pick a kept library when the app's own code is obfuscated (found by a device report vs the sandbox). */
class CodePackage0862Test {
    private fun obf(prefix: String, n: Int) = (1..n).map { "L$prefix/a/b$it;" }.map { it.replace("b$it", "b") + "" }.mapIndexed { i, t -> t.replace("/b;", "/" + ('a' + i % 20) + ('a' + (i / 20) % 20) + ";") }
    private fun readable(prefix: String, n: Int) = (1..n).map { "L$prefix/Class$it;" }

    @Test fun anObfuscatedAppKeepsItsManifestPackageDespiteAKeptReadableLibrary() {       // Read You: me.ash.reader (obfuscated) + com.rometools (readable)
        val types = obf("me/ash/reader", 400) + readable("com/rometools/rome", 389)
        assertEquals("me.ash.reader", SecurityScanner.codePackage(types, "me.ash.reader"))
    }

    @Test fun aRenamedPackageStillFallsBackToTheCommonestReadablePrefix() {               // Quillpad: manifest io.github.quillpad, code org.qosp.notes
        val types = readable("org/qosp/notes/ui", 300) + readable("io/github/quillpad", 2)
        assertEquals("org.qosp", SecurityScanner.codePackage(types, "io.github.quillpad"))
    }

    @Test fun aReadableAppWithAMatchingManifestIsUnchanged() {
        val types = readable("eu/faircode/email", 500) + readable("org/bouncycastle/crypto", 800)
        assertEquals("eu.faircode.email", SecurityScanner.codePackage(types, "eu.faircode.email"))
    }
}
