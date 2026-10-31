package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.2.0: the five-line verdict at the top of every report. */
class Verdict120Test {
    private fun card(sev: Severity, title: String, cls: String, reach: String = "", conf: String = "HIGH", rule: String = "taint-flow", detail: String = "Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method a.b(). Found by the SSA data-flow engine.") =
        Finding(sev, title, detail, "Fix it. More text.", cls, 1, 0, "CWE-22").also { it.reach = reach; it.confidence = conf; it.ruleId = rule; it.scope = SecurityScanner.Scope.APP }

    private val full = Verdict.Coverage(deepScan = true, classesScanned = 1200)

    @Test fun aCleanAppHasWeakConfidenceAndNoMustFix() {
        val cards = listOf(card(Severity.MEDIUM, "Weak hash", "Lcom/x/A;", rule = "weak-hash"), card(Severity.LOW, "Log of data", "Lcom/x/B;", rule = "log"))
        val v = Verdict.build(cards, emptyList(), full)
        assertTrue(v.verdict, v.verdict.startsWith("0 critical / 0 high-priority / 2 informational") && v.verdict.contains("no HIGH or CRITICAL finding"))
        assertEquals(listOf("no HIGH/CRITICAL finding passes the MUST FIX gate (high-impact sink, exported entry without a signature-level guard, no validation seen, traced proof)"), v.mustFix)
        assertTrue(v.confidence, v.confidence.startsWith("weak"))
        assertTrue(v.criticalPath.single().startsWith("none"))
    }

    @Test fun aVulnerableAppNamesItsCriticalPathByCardNumber() {
        val low = card(Severity.LOW, "Log of data", "Lcom/x/B;", rule = "log")
        val sink = card(Severity.HIGH, "Untrusted input is used as a file path", "Lcom/x/Main;", reach = "YES")
        val sc = AttackScenarios.Scenario("s1", "Another app chooses the file the app writes", Severity.HIGH, "high", "exported", "any app", "com.x.Main (exported, no permission)",
            listOf(sink), "overwrite app files", "", "", emptyList())
        val v = Verdict.build(listOf(low, sink), listOf(sc), full)
        assertEquals("card #2: Another app chooses the file the app writes", v.criticalPath[0])
        assertTrue(v.criticalPath[1], v.criticalPath[1].startsWith("entry: com.x.Main (exported, no permission) -> path: #2 ") && v.criticalPath[1].endsWith("sink: FileOutputStream.<init>"))
        assertEquals("impact: overwrite app files", v.criticalPath[2])
        // twin: a scenario without an entry is not a critical path
        val noEntry = AttackScenarios.Scenario("s2", "x", Severity.HIGH, "", "", "", "", listOf(sink), "y", "", "", emptyList())
        assertTrue(Verdict.build(listOf(low, sink), listOf(noEntry), full).criticalPath.single().startsWith("none"))
    }

    @Test fun neverMoreThanThreeMustFixAndOnlyReachableHighOnes() {
        val cards = (1..5).map { card(Severity.HIGH, "Untrusted input is used as a file path", "Lcom/x/C$it;", reach = "YES") } +
            card(Severity.CRITICAL, "Not reachable", "Lcom/x/N;", reach = "NO") + card(Severity.MEDIUM, "Reachable medium", "Lcom/x/M;", reach = "YES")
        val v = Verdict.build(cards, emptyList(), full)
        assertEquals(Verdict.MAX_MUST_FIX, v.mustFix.size)
        assertTrue(v.mustFix.all { it.contains("[HIGH]") })
        assertTrue(v.mustFix[0], v.mustFix[0].startsWith("#1 ") && v.mustFix[0].contains("getCanonicalPath"))            // the file-write template sentence
        // twin: a CRITICAL card with no path from an exported component is not a must-fix
        assertEquals(listOf("no HIGH/CRITICAL finding passes the MUST FIX gate (high-impact sink, exported entry without a signature-level guard, no validation seen, traced proof)"),
            Verdict.build(listOf(card(Severity.CRITICAL, "Not reachable", "Lcom/x/N;", reach = "NO"), card(Severity.HIGH, "Not traced", "Lcom/x/T;")), emptyList(), full).mustFix)
    }

    @Test fun confidenceIsARatio() {
        fun of(sure: Int, n: Int) = Verdict.build((1..n).map { card(Severity.HIGH, "t$it", "Lcom/x/K$it;", conf = if (it <= sure) "HIGH" else "LOW") }, emptyList(), full).confidence
        assertTrue(of(4, 5).startsWith("strong (80%"))
        assertTrue(of(3, 5).startsWith("moderate (60%"))
        assertTrue(of(2, 5).startsWith("weak (40%"))
    }

    @Test fun notSeenReadsTheCoverageValues() {
        val cov = Verdict.Coverage(deepScan = true, classesScanned = 18093, groups = 25, groupsCapped = 2, timeUp = true, nativeMethods = 205, nativeLibs = 0, decryptorCalls = 63575, decrypted = 1420, splits = 0)
        val ns = Verdict.build(listOf(card(Severity.HIGH, "Untrusted input selects a class or method by name", "Lcom/x/R;")), emptyList(), cov).notSeen
        assertTrue(ns, ns.contains("native: 205 native methods, flows into .so not followed, libraries not available"))
        assertTrue(ns, ns.contains("(1 card(s) with a reflection sink)"))
        assertTrue(ns, ns.contains("strings: 1420 / 63575 decryptor call sites decrypted"))
        assertTrue(ns, ns.contains("splits: base only"))
        assertTrue(ns, ns.contains("groups: 2 of 25 groups capped, time limit reached"))
        val clean = Verdict.build(emptyList(), emptyList(), Verdict.Coverage(deepScan = true, classesScanned = 10, groups = 26, nativeLibs = 3, splits = 2)).notSeen
        assertTrue(clean, clean.contains("groups: 26/26 groups") && clean.contains("splits: base + 2 split(s)") && clean.contains("strings: no string decryptor seen"))
    }

    @Test fun notSeenNamesTheHybridCodeTheScanCouldNotRead() {                       // QA 1.2.0: fluffy_board (Flutter), Paperless (React Native)
        fun info(rule: String, title: String) = Finding(Severity.INFO, title, "d", "r").also { it.ruleId = rule }
        val all = listOf(info("native-flutter", "Flutter app: the Dart code is compiled into libapp.so and is NOT analysed"),
            info("assets-coverage", "Hybrid app layer scanned as text: React Native (Hermes bytecode v96, string table scanned)"))
        val ns = Verdict.build(emptyList(), emptyList(), full, "", all).notSeen
        assertTrue(ns, ns.startsWith("Dart code (libapp.so): strings scanned, the code itself not analysed; React Native (Hermes bytecode v96, string table scanned): scanned as text only"))
        // twin: a plain Java app has neither card and gets no hybrid line
        assertFalse(Verdict.build(emptyList(), emptyList(), full, "", listOf(info("other", "x"))).notSeen.contains("not analysed"))
    }

    @Test fun theStatusLineGivesClassesAndGroups() {
        assertEquals(18093 to 25, Verdict.parseStatus("finished, 18093 / 18093 classes; SSA taint: +17 flow(s) (25 groups of up to 3000 classes, 346 classes"))
        assertEquals(500 to 0, Verdict.parseStatus("stopped at 500 / 9000; SSA taint: no extra flow"))
    }

    @Test fun aFailedScanSaysSoInsteadOfAPartialVerdict() {
        val v = Verdict.build(listOf(card(Severity.HIGH, "x", "Lcom/x/A;", reach = "YES")), emptyList(), Verdict.Coverage(deepScan = true, classesScanned = 0))
        assertTrue(v.failed)
        val md = Verdict.markdown(v)
        assertTrue(md, md.contains("**VERDICT: SCAN FAILED"))
        assertFalse(md, md.contains("MUST FIX"))
        // twin: the same cards with classes read give a real verdict
        assertFalse(Verdict.build(listOf(card(Severity.HIGH, "x", "Lcom/x/A;", reach = "YES")), emptyList(), full).failed)
    }

    @Test fun rendersInMarkdownHtmlAndSarif() {
        val cards = listOf(card(Severity.HIGH, "Untrusted input is used as a file path", "Lcom/x/Main;", reach = "YES"))
        val v = Verdict.build(cards, emptyList(), full)
        val md = Verdict.markdown(v)
        for (k in listOf("VERDICT", "CRITICAL PATH", "MUST FIX", "CONFIDENCE", "NOT SEEN")) assertTrue(md, md.contains("**$k:**"))
        val html = ReportBuilder.html("com.x", "", cards, emptyList(), verdict = v)
        assertTrue(html.indexOf("<h2>Verdict</h2>") in 0 until html.indexOf("<h2>Security scan</h2>"))
        assertTrue(html.contains("<b>MUST FIX:</b> #1 [HIGH]"))
        val sarif = org.json.JSONObject(SarifExport.build("com.x", "1.2.0", cards, v))
        val props = sarif.getJSONArray("runs").getJSONObject(0).getJSONObject("properties").getJSONObject("verdict")
        assertTrue(props.getString("mustFix").startsWith("#1 [HIGH]"))
    }
}
