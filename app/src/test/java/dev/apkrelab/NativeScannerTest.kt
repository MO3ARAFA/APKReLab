package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 0.90.0: NativeScanner on small APK-shaped zips. Every card has a twin that must not fire. */
class NativeScannerTest {
    private fun apk(libs: Map<String, ByteArray>): ZipFile {
        val f = File.createTempFile("native", ".apk"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in libs) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }
    private fun manifest(target: Int) = "<manifest package=\"com.x\"><uses-sdk android:minSdkVersion=\"24\" android:targetSdkVersion=\"$target\"/></manifest>"
    private fun scan(libs: Map<String, ByteArray>, target: Int = 35): List<SecurityScanner.Finding> = apk(libs).use { NativeScanner.scan(it, manifest(target)) }
    private fun List<SecurityScanner.Finding>.byId(id: String) = filter { it.ruleId == id }

    private fun loadFormats() { SecretFormats.load(listOf(File("src/main/assets/secret_formats.json"), File("app/src/main/assets/secret_formats.json")).first { it.exists() }.readText()) }

    @Test fun sixteenKbAlignmentIsMediumWhenTheTargetRequiresItAndInformationBefore() {
        val libs = mapOf("lib/arm64-v8a/libnative-lib.so" to ElfTestBuilder.build(align = 0x1000))
        val f35 = scan(libs, 35).byId("native-16kb-alignment")
        assertEquals(1, f35.size); assertEquals(SecurityScanner.Severity.MEDIUM, f35[0].severity); assertTrue(f35[0].detail.contains("libnative-lib.so"))
        assertEquals(SecurityScanner.Severity.INFO, scan(libs, 34).byId("native-16kb-alignment")[0].severity)
        assertTrue(scan(mapOf("lib/arm64-v8a/libnative-lib.so" to ElfTestBuilder.build(align = 0x4000)), 35).byId("native-16kb-alignment").isEmpty())      // twin
        assertTrue(scan(mapOf("lib/armeabi-v7a/libnative-lib.so" to ElfTestBuilder.build(is64 = false, align = 0x1000)), 35).byId("native-16kb-alignment").isEmpty())   // 32-bit: not required
    }

    @Test fun hardeningDefectsAreMediumInAnOwnLibraryAndLowInAKnownDependency() {
        val own = scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(stackExec = true))).byId("native-hardening")
        assertEquals(SecurityScanner.Severity.MEDIUM, own[0].severity); assertTrue(own[0].detail.contains("executable stack"))
        val dep = scan(mapOf("lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build(textrel = true))).byId("native-hardening")
        assertEquals(SecurityScanner.Severity.LOW, dep[0].severity)
        assertTrue(scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build())).byId("native-hardening").isEmpty())                                      // twin: nothing wrong
    }

    @Test fun aSearchPathIsADefectOnlyWhenSomeoneElseCanWriteThere() {
        val risky = scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(runpath = "/data/local/tmp/lib"))).byId("native-hardening")
        assertEquals(SecurityScanner.Severity.MEDIUM, risky[0].severity)
        for (ok in listOf("\$ORIGIN", "\$ORIGIN/../lib")) assertTrue(scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(runpath = ok))).none { it.ruleId == "native-hardening" })
        val priv = scan(mapOf("lib/arm64-v8a/libpython.so" to ElfTestBuilder.build(runpath = "/data/data/com.termux/files/usr/lib")))      // Seal's libraries
        assertTrue(priv.none { it.ruleId == "native-hardening" }); assertEquals(SecurityScanner.Severity.INFO, priv.byId("native-rpath")[0].severity)
        assertTrue(NativeScanner.searchPathRisky("lib")); assertTrue(NativeScanner.searchPathRisky(".")); assertFalse(NativeScanner.searchPathRisky("/system/lib64:/vendor/lib64"))
    }

    @Test fun aMissingCanaryAloneIsNotACardOnlyUnsafeImportsOfAnOwnLibraryAre() {
        val noCanary = scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(imports = listOf("malloc", "free"))))
        assertTrue(noCanary.none { it.ruleId == "native-hardening" || it.ruleId == "native-unsafe-imports" })
        assertTrue(noCanary.byId("native-coverage")[0].detail.contains("Without a stack canary: 1"))                            // counted in the summary
        val own = scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(imports = listOf("strcpy", "sprintf", "malloc")))).byId("native-unsafe-imports")
        assertEquals(1, own.size); assertEquals(SecurityScanner.Severity.LOW, own[0].severity)
        assertTrue(scan(mapOf("lib/arm64-v8a/libffmpeg.so" to ElfTestBuilder.build(imports = listOf("strcpy")))).byId("native-unsafe-imports").isEmpty())            // a dependency
    }

    @Test fun aCredentialInTheDataSectionsIsHighAndAPlaceholderIsNot() {
        loadFormats()
        val token = "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"
        val hit = scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(rodata = listOf(token)))).byId("native-secrets")
        assertEquals(1, hit.size); assertEquals(SecurityScanner.Severity.HIGH, hit[0].severity); assertEquals("lib/arm64-v8a/libpayments.so", hit[0].file)
        assertFalse(hit[0].detail.contains(token))
        assertTrue(scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(rodata = listOf("sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")))).byId("native-secrets").isEmpty())
        val inNames = scan(mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(imports = listOf(token)))).byId("native-secrets")        // only a symbol NAME
        assertTrue(inNames.isEmpty())
    }

    @Test fun theCoverageCardAlwaysSaysWhatWasAndWasNotLookedAt() {
        val z = mapOf("lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(), "lib/arm64-v8a/libaria2c.zip.so" to "PK\u0003\u0004zipzipzip".toByteArray().copyOf(200))
        val c = scan(z).byId("native-coverage")
        assertEquals(1, c.size); assertEquals(SecurityScanner.Severity.INFO, c[0].severity)
        assertTrue(c[0].detail.contains("1 libraries")); assertTrue(c[0].detail.contains("1 file(s) named .so are not ELF")); assertTrue(c[0].detail.contains("native CODE is not analysed"))
        assertTrue(scan(emptyMap()).isEmpty())
    }

    // 0.103.2 (a device report: the "no RELRO" card carried the biometric-prompt risk text, as did every CWE-693 card)
    @Test fun theRiskTextOfAHardeningCardIsAboutHardeningAndNoCweOf693CardTalksAboutBiometrics() {
        val hard = SecurityScanner.Finding(SecurityScanner.Severity.MEDIUM, "Native libraries without basic hardening (1)", "d", "r", null, -1, -1, "CWE-693", "lib/").also { it.ruleId = "native-hardening" }
        val e = VulnKnowledge.forFinding(hard)!!
        assertTrue(e.scenario.contains("RELRO")); assertTrue(e.owasp.startsWith("M7")); assertTrue(e.good.contains("relro"))
        for (rule in listOf("fintech-frida-detection", "androgoat-checks", "")) {                       // twin: the other CWE-693 cards get the generic text, not the hardening text and not the biometric one
            val g = VulnKnowledge.forFinding(SecurityScanner.Finding(SecurityScanner.Severity.INFO, "Root detection logic (client-side)", "d", "r", null, -1, -1, "CWE-693").also { it.ruleId = rule })!!
            assertFalse(g.scenario.contains("iometric")); assertFalse(g.scenario.contains("RELRO")); assertTrue(g.scenario.contains("client-side"))
        }
        assertTrue(VulnKnowledge.forCwe("CWE-287")!!.scenario.isNotEmpty())                             // the authentication entry is untouched
    }
}
