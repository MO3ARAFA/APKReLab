package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.77.0: fixes from the real-app held-out set 2 (Termux GitHub + Play builds, Monerujo, Ivy Wallet). */
class SetTwoFixes0770Test {

    private fun f(type: String, sev: SecurityScanner.Severity = SecurityScanner.Severity.HIGH, reach: String = "NO") =
        SecurityScanner.Finding(sev, "Untrusted input is used as a file path", "Data from Intent.getStringExtra() ...", "r", type, 3, 10, "CWE-22")
            .also { it.ruleId = "taint-flow"; it.reach = reach }

    @Test fun unreachedHelperDropsOneLevelButAComponentKeepsItsSeverity() {
        val helper = f("Lcom/termux/app/api/KeystoreAPI\$2;")
        val component = f("Lcom/example/WebViewActivity;")
        val guarded = f("Lcom/example/GuardedService\$1;")
        val reached = f("Lcom/termux/app/api/Other;", reach = "YES")
        val crit = f("Lcom/example/Util;", SecurityScanner.Severity.CRITICAL)
        val n = FindingPolish.lowerUnreachedHelpers(listOf(helper, component, guarded, reached, crit),
            setOf("Lcom/example/WebViewActivity;", "Lcom/example/GuardedService;"), setOf("Lcom/example/GuardedService;"))
        assertEquals(3, n)
        assertEquals(SecurityScanner.Severity.MEDIUM, helper.severity)
        assertEquals("LOW", helper.confidence)
        assertEquals(SecurityScanner.Severity.HIGH, component.severity)     // OVAA lesson: implicit forwards
        assertEquals(SecurityScanner.Severity.MEDIUM, guarded.severity)
        assertEquals(SecurityScanner.Severity.HIGH, reached.severity)
        assertEquals(SecurityScanner.Severity.HIGH, crit.severity)
    }

    private fun unzip(source: String) = """
        .class public Lcom/example/Z;
        .method public run()V
            .locals 6
            $source
            new-instance v1, Ljava/util/zip/ZipInputStream;
            invoke-direct {v1, v0}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
            invoke-virtual {v1}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;
            move-result-object v2
            invoke-virtual {v2}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
            move-result-object v3
            new-instance v4, Ljava/io/File;
            invoke-direct {v4, p0, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
            return-void
        .end method
    """.trimIndent()

    @Test fun embeddedArchiveIsLowButADownloadedOneStaysHigh() {
        val embedded = "invoke-static {}, Lcom/example/Z;->loadZipBytes()[B\n            move-result-object v5\n            new-instance v0, Ljava/io/ByteArrayInputStream;\n            invoke-direct {v0, v5}, Ljava/io/ByteArrayInputStream;-><init>([B)V"
        val r = ZipSlipRule.scan(RuleContext("Lcom/example/Z;", 0, unzip(embedded), "com.example"))
        assertEquals(SecurityScanner.Severity.LOW, r[0].severity)
        val downloaded = "new-instance v0, Ljava/io/FileInputStream;\n            invoke-direct {v0, p1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V"
        assertEquals(SecurityScanner.Severity.HIGH, ZipSlipRule.scan(RuleContext("Lcom/example/Z;", 0, unzip(downloaded), "com.example"))[0].severity)
    }
}
