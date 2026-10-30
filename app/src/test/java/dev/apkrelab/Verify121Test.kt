package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.2.1: every MUST FIX / CRITICAL PATH card says what to open to confirm it, and how strong its evidence is. */
class Verify121Test {
    private val ssaTail = ". Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes."
    private fun flow(src: String, sink: String, method: String = "A.run", title: String = "Untrusted input is used as a file path") =
        Finding(Severity.HIGH, title, "Data from $src reaches $sink() in method $method(Ljava/lang/String;)V$ssaTail", "Fix it. More.", "Lcom/x/A;", 1, 40, "CWE-22")
            .also { it.ruleId = "taint-flow"; it.reach = "YES"; it.confidence = "HIGH"; it.scope = SecurityScanner.Scope.APP }

    @Test fun paperless32ShowsTheCanonicalPathCheck() {              // the 1.2.0 QA false positive: the check is in the provider's path strategy
        val f = Finding(Severity.HIGH, "Untrusted input is used as a file path",
            "Data from a ContentProvider method parameter reaches ParcelFileDescriptor.open() in method ClipboardFileProvider.openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;$ssaTail",
            "Reduce the input to a bare file name. More.", "Lexpo/modules/clipboard/ClipboardFileProvider;", 1, 0, "CWE-22").also { it.ruleId = "taint-flow"; it.reach = "YES"; it.confidence = "MEDIUM"; it.scope = SecurityScanner.Scope.APP }
        val m = Verdict.build(listOf(f), emptyList(), Verdict.Coverage(true, 100)).mustFix.single()
        assertTrue(m, m.contains("\n→ to verify: check for a canonical-path check (getCanonicalPath / getCanonicalFile / normalize, then startsWith of the base directory) or a \"..\" check in openFile() or its direct callees. If present, this is a false positive."))
        assertTrue(m, m.endsWith("\nEvidence: 1.0 (real SSA source+path)"))
    }

    @Test fun fileWriteNamesTheSanitizerFamily() {
        assertTrue(Verdict.verifyOf(flow("Intent.getStringExtra()", "FileOutputStream.<init>")).startsWith("check for a canonical-path check"))
    }

    @Test fun theSanitizerFamilyIsTheSwitchedPart() {
        Verdict.SANITIZER_FAMILIES = false
        try { assertFalse(Verdict.verifyOf(flow("Intent.getStringExtra()", "FileOutputStream.<init>")).contains("canonical")) } finally { Verdict.SANITIZER_FAMILIES = true }
    }

    @Test fun sqlAndContentResolverFamilies() {
        assertTrue(Verdict.verifyOf(flow("Intent.getStringExtra()", "SQLiteDatabase.rawQuery", title = "Untrusted input reaches an SQL statement")).contains("selection arguments (? placeholders) or DatabaseUtils.sqlEscapeString in run()"))
        assertTrue(Verdict.verifyOf(flow("Intent.getStringExtra()", "ContentResolver.openInputStream", title = "Untrusted input chooses the file or content URI the app opens")).contains("Uri.getScheme / getAuthority"))
    }

    @Test fun sinksWithoutAStandardSanitizer() {
        assertEquals("SSA flow verified; no sanitizer is standard for Runtime.exec: confirm the value really comes from outside in run()",
            Verdict.verifyOf(flow("Intent.getStringExtra()", "Runtime.exec", title = "Untrusted input reaches a shell command")))
        // twin: the same sink found by the class-level rule does not claim an SSA flow
        val classLevel = flow("Intent.getStringExtra()", "Runtime.exec").also { it.detail = it.detail.replace(ssaTail, ". The value was followed inside this class.") }
        assertFalse(Verdict.verifyOf(classLevel).startsWith("SSA flow verified"))
    }

    @Test fun webViewAndDeepLinkLines() {
        assertTrue(Verdict.verifyOf(flow("Intent.getStringExtra()", "WebView.loadUrl", title = "Untrusted input is loaded into a WebView")).startsWith("check the host allow-list / Uri.parse before loadUrl in run()"))
        assertTrue(Verdict.verifyOf(flow("Intent.getData()", "FileOutputStream.<init>")).startsWith("check the host / path validation in run() before the sink (FileOutputStream.<init>)"))
    }

    @Test fun ruleOnlyAndManifestCards() {
        val rule = Finding(Severity.HIGH, "Weak cipher mode", "Cipher.getInstance(\"AES/ECB\") ...  (around line 150)", "Use GCM.", "Lcom/x/Aes;", 1, 4321, "CWE-327").also { it.ruleId = "crypto-cipher" }
        assertEquals("open com.x.Aes at smali line 150 (offset 4321): the rule matched a pattern there and traced no data flow; confirm the code does what the title says.", Verdict.verifyOf(rule))
        val man = Finding(Severity.HIGH, "Exported provider without a permission: com.x.P", "d", "r").also { it.ruleId = "manifest-exported-components" }
        assertTrue(Verdict.verifyOf(man).startsWith("open AndroidManifest.xml (com.x.P): check the permission and the component's own caller checks"))
    }

    @Test fun anSsaCardWithoutASanitizerFamilyIsNotCalledRuleOnly() {                // 1.2.1 QA: VulnLab #54 (intent redirection)
        val f = flow("Intent.getParcelableExtra()", "Context.startActivity", "IntentRedirectReceiver.onReceive", "Untrusted Intent is launched by this app (intent redirection)")
        assertEquals("SSA flow verified; the scanner knows no standard sanitizer for Context.startActivity: read onReceive() between the source and Context.startActivity and confirm nothing restricts the value.", Verdict.verifyOf(f))
        // twin: a rule card without a flow keeps the rule-only sentence
        val rule = Finding(Severity.HIGH, "Weak cipher mode", "Cipher ... (around line 9)", "Use GCM.", "Lcom/x/B;", 2, 1, "CWE-327").also { it.ruleId = "crypto-cipher" }
        assertTrue(Verdict.verifyOf(rule).contains("traced no data flow"))
    }

    @Test fun applicationFlagsAreNotAskedForCallerChecks() {                         // 1.2.1 QA: Gu3ssWeak #1 / #2
        val flag = Finding(Severity.CRITICAL, "Debuggable build", "android:debuggable=true", "r").also { it.ruleId = "manifest-debuggable" }
        assertEquals("open AndroidManifest.xml and confirm \"Debuggable build\" in the manifest of the build you ship (the rule read the manifest only).", Verdict.verifyOf(flag))
        // twin: an exported component keeps the caller-check sentence
        val comp = Finding(Severity.HIGH, "Exported receiver without a permission: com.x.R", "d", "r").also { it.ruleId = "manifest-exported-components" }
        assertTrue(Verdict.verifyOf(comp).contains("caller checks"))
    }

    @Test fun criticalPathHopsGetAVerifyLine() {
        val sink = flow("Intent.getStringExtra()", "FileOutputStream.<init>")
        val sc = AttackScenarios.Scenario("s", "Another app chooses the file", Severity.HIGH, "", "", "", "com.x.A (exported)", listOf(sink), "overwrite files", "", "", emptyList())
        val p = Verdict.build(listOf(sink), listOf(sc), Verdict.Coverage(true, 100)).criticalPath
        assertTrue(p.last(), p.last().startsWith("→ to verify (#1): check for a canonical-path check"))
    }

    // ---- evidence under each MUST FIX card ----

    private fun must(vararg f: Finding) = Verdict.build(f.toList(), emptyList(), Verdict.Coverage(true, 100)).mustFix

    @Test fun ssaEvidenceIsNotFlagged() {
        val m = must(flow("Intent.getStringExtra()", "FileOutputStream.<init>")).single()
        assertTrue(m.startsWith("#1 ")); assertTrue(m.endsWith("Evidence: 1.0 (real SSA source+path)"))
    }

    @Test fun classLevelFlowIsCheckFirst() {
        val f = flow("Intent.getStringExtra()", "FileOutputStream.<init>").also { it.detail = it.detail.replace(ssaTail, ". The value was followed inside this class.") }
        val m = must(f).single()
        assertTrue(m, m.startsWith("CHECK FIRST: #1 ") && m.endsWith("Evidence: 0.8 (source only: a flow inside one class)"))
    }

    @Test fun validationOnThePathIsCheckFirst() {
        val f = flow("Intent.getStringExtra()", "FileOutputStream.<init>").also { it.detail += " The chain also contains validation-like calls (startsWith ...)." }
        val m = must(f).single()
        assertTrue(m, m.startsWith("CHECK FIRST: ") && m.endsWith("Evidence: 0.3 (validation-like calls on the path)"))
    }

    @Test fun onlyTheWeakCardIsFlagged() {                                          // two cards, two evidences
        val strong = flow("Intent.getStringExtra()", "FileOutputStream.<init>")
        val ruleOnly = Finding(Severity.HIGH, "Weak cipher mode", "Cipher ... (around line 9)", "Use GCM.", "Lcom/x/B;", 2, 1, "CWE-327").also { it.ruleId = "crypto-cipher"; it.reach = "YES"; it.confidence = "HIGH"; it.scope = SecurityScanner.Scope.APP }
        val m = must(strong, ruleOnly)
        assertEquals(2, m.size)
        assertEquals(1, m.count { it.startsWith("CHECK FIRST: ") })
        assertTrue(m.single { it.startsWith("CHECK FIRST: ") }.endsWith("Evidence: 0.6 (rule-only)"))
    }
}
