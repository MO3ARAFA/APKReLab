package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.87.0: Maven-style version order and the range semantics of the generated advisory database. */
class ScaVersionTest {
    private fun v(s: String) = LibVersion.parse(s)!!

    @Test fun preReleaseQualifiersOrderLikeMaven() {
        assertTrue(v("2.0.0-beta1") < v("2.0.0-beta2"))
        assertTrue(v("2.0.0-beta2") < v("2.0.0-rc1"))
        assertTrue(v("2.0.0-rc1") < v("2.0.0"))
        assertTrue(v("2.0.0") < v("2.0.0-sp1"))
        assertTrue(v("2.0.0-alpha3") < v("2.0.0-beta1"))
        assertEquals(0, v("4.1.71.Final").compareTo(v("4.1.71")))                      // .Final is a release
        assertEquals(0, v("32.0.0-jre").compareTo(v("32.0.0")))                        // unknown suffixes (-jre, -android) are releases
        assertTrue(v("2.9.10") < v("2.9.10.1"))
        assertTrue(v("1.0") == v("1.0.0") || v("1.0").compareTo(v("1.0.0")) == 0)
    }

    private fun vuln(vararg r: Pair<String, String>) = LibVuln("g", "a", r.toList(), "GHSA-test", SecurityScanner.Severity.HIGH, "s", "fixed")

    @Test fun halfOpenAndInclusiveRanges() {
        val half = vuln("2.0.0-beta1" to "2.9.10.1")
        assertFalse(half.affects(v("1.9.9")))
        assertFalse(half.affects(v("2.0.0-alpha9")))     // before the pre-release that introduced it
        assertTrue(half.affects(v("2.0.0-beta1")))
        assertTrue(half.affects(v("2.9.10")))
        assertFalse(half.affects(v("2.9.10.1")))          // the fixed version is NOT affected
        val last = vuln("1.0" to "1.5+")                  // last_affected: inclusive
        assertTrue(last.affects(v("1.5")))
        assertFalse(last.affects(v("1.5.1")))
        val open = vuln("3.0" to "")                      // introduced, never fixed
        assertTrue(open.affects(v("9.9")))
        assertFalse(open.affects(v("2.9")))
        val all = vuln("" to "2.7.5")                     // every version below the fix
        assertTrue(all.affects(v("0.1")))
        assertFalse(all.affects(v("2.7.5")))
    }

    @Test fun theGeneratedDatabaseFlagsKnownVulnerableVersionsAndNotTheFixedOnes() {
        val text = java.io.File("src/main/assets/vulns.json").let { if (it.exists()) it else java.io.File("app/src/main/assets/vulns.json") }.readText()
        assertTrue(LibraryScanner.loadDbText(text) > 500)
        fun ids(g: String, a: String, ver: String) = LibraryScanner.matches(DetectedLib(g, a, ver, "t", "version file")).map { it.id }
        assertTrue(ids("com.squareup.okhttp", "okhttp", "2.2.0").any { it.contains("CVE-2016-2402") })         // hand-checked entry still there
        assertTrue(ids("com.squareup.okhttp3", "okhttp", "4.9.0").isNotEmpty())                                // GHSA: was reported OK before 0.87.0
        assertTrue(ids("com.squareup.okhttp3", "okhttp", "4.12.0").isEmpty())
        assertTrue(ids("org.bouncycastle", "bcprov-jdk18on", "1.78").isNotEmpty())                             // GHSA: 1.78 was reported OK before
        assertTrue(ids("org.bouncycastle", "bcprov-jdk18on", "1.85").isEmpty())
    }

    @Test fun theGrpcOkhttpTransportVersionIsNotOkhttpsVersion() {          // Ivy: "grpc-java-okhttp/1.62.2" was read as OkHttp 1.62.2 and flagged CVE-2016-2402
        fun found(s: String) = LibraryScanner.okhttpVersionsIn(s.toByteArray())
        assertEquals(emptyList<String>(), found("grpc-java-okhttp/1.62.2"))
        assertEquals(emptyList<String>(), found("some-okhttp/3.4.5"))
        assertEquals(listOf("4.9.0"), found("\u0000okhttp/4.9.0\u0000"))
        assertEquals(listOf("3.14.9"), found("User-Agent: okhttp/3.14.9"))
        assertEquals(emptyList<String>(), found("okhttp/1.78.0"))            // OkHttp has no 1.x user agent
    }

    @Test fun theReportCellListsTheMostSevereFewAndTheNewestFix() {
        fun mk(id: String, sev: SecurityScanner.Severity, fixed: String) = LibVuln("g", "a", listOf("" to "9"), id, sev, "s", fixed)
        val vs = listOf(mk("GHSA-low", SecurityScanner.Severity.LOW, "2.9.10.8 or newer"), mk("GHSA-crit", SecurityScanner.Severity.CRITICAL, "2.12.7, 2.13.4.2 or newer"),
            mk("GHSA-a", SecurityScanner.Severity.HIGH, "2.9.10 or newer"), mk("GHSA-b", SecurityScanner.Severity.HIGH, "2.9.9 or newer"),
            mk("GHSA-c", SecurityScanner.Severity.MEDIUM, "2.8 or newer"), mk("GHSA-d", SecurityScanner.Severity.MEDIUM, "2.7 or newer"))
        val cell = ReportBuilder.advisoryList(vs)
        assertTrue(cell.startsWith("GHSA-crit (critical)"))
        assertTrue(cell.endsWith("+ 2 more"))
        assertFalse(cell.contains("GHSA-low"))
        assertEquals("2.13.4.2 or newer", ReportBuilder.newestFix(vs))                         // one major line among the fixes
        val twoLines = vs + mk("GHSA-3x", SecurityScanner.Severity.HIGH, "3.0.4 or newer")
        assertEquals("2.13.4.2 (2.x) / 3.0.4 (3.x) or newer, within the major line you use", ReportBuilder.newestFix(twoLines))   // WE Wallet: jackson-databind "safe from 3.1.4"
        assertEquals("2.13.4.2 or newer", ReportBuilder.newestFix(twoLines, LibVersion.parse("2.9.8")))                              // known 2.x: stay on 2.x
        assertEquals("3.0.4 or newer", ReportBuilder.newestFix(twoLines, LibVersion.parse("3.0.1")))
        assertTrue(ReportBuilder.newestFix(twoLines, LibVersion.parse("2.14.0")).startsWith("3.0.4 or newer (a new major line")) // nothing newer on 2.x in this list: say so
        assertEquals("see the advisories", ReportBuilder.newestFix(listOf(mk("x", SecurityScanner.Severity.LOW, "see the advisory"))))
    }

    @Test fun aLibraryFindingListsAtMostEightAdvisoriesAndShowsACriticalGeneratedOneAsHigh() {
        val text = java.io.File("src/main/assets/vulns.json").let { if (it.exists()) it else java.io.File("app/src/main/assets/vulns.json") }.readText()
        LibraryScanner.loadDbText(text)
        val f = LibraryScanner.findingsFor(listOf(DetectedLib("org.bouncycastle", "bcprov-jdk18on", "1.78", "classes.dex", "dex string"))).first { it.ruleId == "sca-known-vuln" }
        assertEquals(SecurityScanner.Severity.HIGH, f.severity)                      // the worst advisory is published as CRITICAL
        assertTrue(f.detail.contains("shown as HIGH"))
        val many = LibraryScanner.findingsFor(listOf(DetectedLib("com.fasterxml.jackson.core", "jackson-databind", "2.6.0", "x", "version file"))).first { it.ruleId == "sca-known-vuln" }
        assertTrue(many.detail.lines().count { it.startsWith("- ") } <= 9)           // 8 advisories + the "... and N more" line
        assertTrue(many.detail.contains("more advisories"))
    }

    @Test fun theVerifyBlockListsUnknownVersionLibrariesWithAdvisoriesMostSevereFirst() {
        val text = java.io.File("src/main/assets/vulns.json").let { if (it.exists()) it else java.io.File("app/src/main/assets/vulns.json") }.readText()
        LibraryScanner.loadDbText(text)
        val libs = listOf(DetectedLib("com.google.code.gson", "gson", "?", "com/google/gson/**", "package path"),
            DetectedLib("com.fasterxml.jackson.core", "jackson-databind", "?", "p", "package path"),
            DetectedLib("androidx", "androidx-libraries", "?", "p", "package path"),
            DetectedLib("com.example", "nothing-known", "?", "p", "package path"),
            DetectedLib("com.squareup.okhttp3", "okhttp", "4.12.0", "p", "version file"))
        val b = ReportBuilder.verifyBlock(libs)
        assertTrue(b.contains("dependencyInsight --dependency jackson-databind"))
        assertTrue(b.contains("dependencyInsight --dependency gson"))
        assertFalse(b.contains("androidx-libraries"))     // an aggregate has no single version
        assertFalse(b.contains("nothing-known"))           // no advisory, nothing to verify
        assertFalse(b.contains("okhttp"))                  // the version is known
        assertTrue(b.indexOf("jackson-databind") < b.indexOf("dependency gson"))     // critical advisories before the high one
        assertEquals("", ReportBuilder.verifyBlock(emptyList()))
    }
}

