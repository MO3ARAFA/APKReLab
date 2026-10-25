package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.2.0: one-sentence fixes chosen by rule id + sink. */
class FixTemplates120Test {
    private fun f(rule: String, title: String = "t", detail: String = "") =
        Finding(Severity.HIGH, title, detail, "The rule's own advice.", "Lcom/x/A;", 1, 0, "CWE-1").also { it.ruleId = rule; it.scope = SecurityScanner.Scope.APP }

    private fun flow(title: String, sink: String) = f("taint-flow", title, "Data from Intent.getStringExtra() reaches $sink() in method A.b(). Found by the SSA data-flow engine.")

    @Test fun webViewUrl() {
        assertEquals("webview-url", FixTemplates.match(flow("Untrusted input is loaded into a WebView", "WebView.loadUrl"))!!.id)
        assertEquals("webview-url", FixTemplates.match(f("webview-intent-url"))!!.id)
    }

    @Test fun fileWriteButNotFileRead() {
        assertEquals("file-write", FixTemplates.match(flow("Untrusted input is used as a file path", "FileOutputStream.<init>"))!!.id)
        assertEquals("file-write", FixTemplates.match(f("zip-slip"))!!.id)
        assertNull(FixTemplates.match(flow("Untrusted input is used as a file path", "FileInputStream.<init>")))      // twin: a read is not the write template
    }

    @Test fun sqlArgs() {
        assertEquals("sql-args", FixTemplates.match(flow("Untrusted input reaches an SQL statement", "SQLiteDatabase.rawQuery"))!!.id)
        assertEquals("sql-args", FixTemplates.match(f("sql-concat"))!!.id)
        assertEquals("sql-args", FixTemplates.match(f("provider-sql-injection"))!!.id)
    }

    @Test fun trustManagerAndJsBridge() {
        assertTrue(FixTemplates.match(f("tls-trustmanager"))!!.sentence.contains("CertificatePinner"))
        assertEquals("js-bridge", FixTemplates.match(f("webview-js-interface"))!!.id)
        assertEquals("js-bridge", FixTemplates.match(f("webview-js-bridge-method"))!!.id)
    }

    @Test fun exportedComponentNamesThePackage() {
        val t = FixTemplates.match(f("manifest-exported-components"), "com.x")!!
        assertTrue(t.sentence, t.sentence.contains("android:permission=\"com.x.permission.<NAME>\"") && t.sentence.contains("queue_manifest_fix"))
    }

    @Test fun anUnknownRuleKeepsItsOwnFix() {
        assertNull(FixTemplates.match(f("weak-hash")))
        assertNull(FixTemplates.match(f("taint-flow", "Untrusted input is used as a file path", "no sink named here")))   // no sink in the detail: no template
    }

    @Test fun markdownShowsTheSentenceUnderTheFix() {
        val md = ReportBuilder.securitySection(listOf(flow("Untrusted input is used as a file path", "FileOutputStream.<init>"), f("weak-hash", "Weak hash")), 400, "com.x")
        assertTrue(md, md.contains("- Fix: The rule's own advice.\n- Suggested fix: Resolve the path against a fixed directory"))
        assertEquals(1, Regex("\n- Suggested fix:").findAll(md).count())                            // the unknown rule has none
    }

    @Test fun htmlShowsTheSentence() {
        val html = ReportBuilder.html("com.x", "", listOf(f("tls-trustmanager", "Trust all"), f("weak-hash", "Weak hash")), emptyList())
        assertTrue(html.contains("<b>Suggested fix:</b> Remove the TrustManager"))
        assertFalse(html.contains("API: android:permission"))
    }
}
