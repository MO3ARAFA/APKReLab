package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.92.0: the MASVS v2 mapping, its coverage table and the SARIF additions. */
class MasvsTest {
    private fun f(rule: String, title: String = "t", sev: SecurityScanner.Severity = SecurityScanner.Severity.HIGH, cwe: String = "CWE-89"): SecurityScanner.Finding =
        SecurityScanner.Finding(sev, title, "detail", "fix", "Lcom/x/Y;", 0, 0, cwe).also { it.ruleId = rule }

    @Test fun theControlTableIsTheOfficial24() {
        assertEquals(24, Masvs.controls.size)
        assertTrue(Masvs.controls.keys.containsAll(listOf("MASVS-STORAGE-1", "MASVS-CODE-4", "MASVS-RESILIENCE-4", "MASVS-PRIVACY-4", "MASVS-AUTH-3")))
        assertTrue(Masvs.controls.getValue("MASVS-NETWORK-2").contains("identity pinning"))
        assertTrue(Masvs.controls.getValue("MASVS-CODE-3").contains("known vulnerabilities"))
    }

    @Test fun everyControlNamedInTheMappingExistsAndEveryRegisteredRuleIsMapped() {
        for (r in Masvs.mappedRules()) for (c in Masvs.controlsFor(f(r))) assertTrue("$r -> $c", c in Masvs.controls)
        val unmapped = RuleRegistry.ids().map { it.substringBefore(":") }.filter { it !in Masvs.mappedRules() && it != "taint-flow" }      // taint-flow: by sink, see forTaint
        assertEquals("registered rules without a MASVS control: $unmapped", emptyList<String>(), unmapped)      // a new rule must be mapped (or listed here on purpose)
    }

    @Test fun aTaintFindingTakesItsControlsFromTheSink() {
        assertEquals(listOf("MASVS-PLATFORM-2", "MASVS-CODE-4"), Masvs.controlsFor(f("taint-flow", "Untrusted input is loaded into a WebView")))
        assertEquals(listOf("MASVS-CODE-4"), Masvs.controlsFor(f("taint-flow", "Untrusted input reaches a SQL query")))
        assertEquals(listOf("MASVS-PLATFORM-1", "MASVS-CODE-4"), Masvs.controlsFor(f("taint-xclass", "Untrusted input starts an Intent / component")))
        assertEquals(emptyList<String>(), Masvs.controlsFor(f("some-unknown-rule")))                                   // the report then keeps the CWE group
        assertEquals(listOf("MASVS-STORAGE-2"), Masvs.controlsFor(f("", "Keyboard cache: sensitive input field")))       // a legacy finding without a rule id: its title slug
    }

    @Test fun theLabelIsUsedInTheReportCardAndFallsBackToTheCweGroup() {
        val tls = f("tls-trustmanager", "Trust-all", cwe = "CWE-295")
        assertTrue(ReportBuilder.securitySection(listOf(tls), 10).contains("MASVS: MASVS-NETWORK-1"))
        val unknown = f("some-unknown-rule", "x", cwe = "CWE-295")
        assertTrue(ReportBuilder.securitySection(listOf(unknown), 10).contains("MASVS: MASVS-NETWORK"))                // the CWE's group, as before
    }

    @Test fun coverageSaysWhichControlsAreAssessedAndWhichAreNot() {
        val cov = Masvs.coverage(listOf(f("tls-trustmanager", sev = SecurityScanner.Severity.CRITICAL), f("tls-protocol-version")))
        val net1 = cov.first { it.control == "MASVS-NETWORK-1" }
        assertTrue(net1.rules >= 5); assertEquals(2, net1.findings); assertEquals(SecurityScanner.Severity.CRITICAL, net1.worst)
        assertEquals(0, cov.first { it.control == "MASVS-AUTH-1" }.rules)                                              // nothing in this tool assesses it
        assertTrue(cov.first { it.control == "MASVS-RESILIENCE-3" }.rules > 0)                                         // the obfuscation share of the posture
        assertEquals(0, cov.first { it.control == "MASVS-STORAGE-1" }.findings)                                        // assessed, nothing found
        val md = Masvs.section(emptyList())
        assertTrue(md.contains("not assessed by this tool")); assertTrue(md.contains("is NOT a pass"))
    }

    @Test fun sarifCarriesSecuritySeverityMasvsFingerprintAndRegion() {
        val tls = f("tls-trustmanager", "Trust-all", cwe = "CWE-295")
        val run = org.json.JSONObject(SarifExport.build("com.x", "0.92.0", listOf(tls, f("tls-trustmanager", "Trust-all 2", cwe = "CWE-295")))).getJSONArray("runs").getJSONObject(0)
        val rule = run.getJSONObject("tool").getJSONObject("driver").getJSONArray("rules").getJSONObject(0)
        assertEquals("8.0", rule.getJSONObject("properties").getString("security-severity"))
        val tags = rule.getJSONObject("properties").getJSONArray("tags"); assertTrue((0 until tags.length()).map { tags.getString(it) }.contains("external/masvs/masvs-network-1"))
        assertEquals("https://cwe.mitre.org/data/definitions/295.html", rule.getString("helpUri"))
        val res = run.getJSONArray("results").getJSONObject(0)
        assertEquals(0, res.getInt("ruleIndex")); assertEquals(1, res.getJSONArray("locations").getJSONObject(0).getJSONObject("physicalLocation").getJSONObject("region").getInt("startLine"))
        assertEquals("com.x.Y", res.getJSONArray("locations").getJSONObject(0).getJSONArray("logicalLocations").getJSONObject(0).getString("fullyQualifiedName"))
        assertEquals("MASVS-NETWORK-1", res.getJSONObject("properties").getJSONArray("masvs").getString(0))
        val fp1 = res.getJSONObject("partialFingerprints").getString("apkrelab/v1")
        assertEquals(32, fp1.length)
        assertEquals(SarifExport.fingerprint(f("tls-trustmanager", "Trust-all 7")), SarifExport.fingerprint(f("tls-trustmanager", "Trust-all 9")))    // numbers in the title do not change the key
        assertFalse(SarifExport.fingerprint(f("tls-trustmanager", "Trust-all")) == SarifExport.fingerprint(f("tls-hostname-verifier", "Trust-all")))   // another rule: another alert
        fun withDetail(d: String) = f("secrets-known-formats", "Key").also { it.detail = d }
        assertFalse(SarifExport.fingerprint(withDetail("a string (\"AKIA…\")")) == SarifExport.fingerprint(withDetail("a string (\"sk_l…\")")))   // two findings of one rule in one class
        assertEquals(SarifExport.fingerprint(withDetail("seen 3 times")), SarifExport.fingerprint(withDetail("seen 8 times")))
        assertFalse(run.getJSONObject("tool").getJSONObject("driver").has("informationUri"))                           // the placeholder is gone
    }

    @Test fun coverageCountsOnlyWhatAReaderSeesAsAFinding() {                                                              // Session: 145 "STORAGE-1 findings" were 141 INFO and 132 library ones
        val info = f("high-entropy-strings", sev = SecurityScanner.Severity.INFO)
        val lib = f("high-entropy-strings", sev = SecurityScanner.Severity.MEDIUM).also { it.scope = SecurityScanner.Scope.LIB }
        val app = f("high-entropy-strings", sev = SecurityScanner.Severity.MEDIUM)
        val c = Masvs.coverage(listOf(info, info, lib, lib, lib, app)).first { it.control == "MASVS-STORAGE-1" }
        assertEquals(1, c.findings); assertEquals(3, c.libFindings)
    }

    @Test fun twoIdenticalFindingsInOneClassGetDifferentFingerprints() {
        val a = f("secrets-known-formats", "Key"); val b = f("secrets-known-formats", "Key")
        val rs = org.json.JSONObject(SarifExport.build("com.x", "t", listOf(a, b, a))).getJSONArray("runs").getJSONObject(0).getJSONArray("results")
        val fps = (0 until 3).map { rs.getJSONObject(it).getJSONObject("partialFingerprints").getString("apkrelab/v1") }
        assertEquals(3, fps.toSet().size)
        assertEquals(SarifExport.fingerprint(a), fps[0])                                    // the first keeps the plain key: stable when a second one appears later
    }
}

