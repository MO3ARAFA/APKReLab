package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.2.0: findings that share a sink, an entry, a field or a class are linked with one suggested fix. */
class Correlation120Test {
    private fun f(cls: String, sink: String, src: String = "Intent.getStringExtra()", entry: String = "", sev: Severity = Severity.HIGH, title: String = "Untrusted input is used as a file path") =
        Finding(sev, title, "Data from $src reaches $sink() in method X.y(). Found by the SSA data-flow engine.", "fix", cls, 1, 0, "CWE-22").also {
            it.ruleId = "taint-flow"; it.scope = SecurityScanner.Scope.APP
            if (entry.isNotEmpty()) { it.reach = "YES"; it.chain = "Entry: $entry\nPath: a -> b" }
        }

    @Test fun sameSinkInOneClassLinks() {
        val cards = listOf(f("Lcom/x/Store;", "FileOutputStream.<init>"), f("Lcom/x/Store;", "FileOutputStream.<init>", "SharedPreferences.getString()"),
            f("Lcom/x/Store;", "FileOutputStream.<init>", "a ContentProvider method parameter"))
        val g = Correlation.groups(cards).single()
        assertEquals(listOf(0, 1, 2), g.cards)
        assertEquals("sink", g.kind)
        assertEquals("Related findings: #1, #2, #3. Suggested fix: validate the input at FileOutputStream.<init> in Store.", g.line { "#" + (it + 1) })
    }

    @Test fun sameEntryLinksAcrossClasses() {
        val cards = listOf(f("Lcom/x/A;", "WebView.loadUrl", entry = "com.x.MainActivity.onCreate"), f("Lcom/x/B;", "FileOutputStream.<init>", entry = "com.x.MainActivity.onCreate"),
            f("Lcom/x/C;", "SQLiteDatabase.rawQuery", entry = "com.x.MainActivity.onCreate"))
        val g = Correlation.groups(cards).single()
        assertEquals("entry", g.kind)
        assertTrue(g.fix(), g.fix() == "validate the Intent at com.x.MainActivity.onCreate")
    }

    @Test fun theEntryEdgeIsTheSwitchedPart() {
        val cards = listOf(f("Lcom/x/A;", "WebView.loadUrl", entry = "com.x.Main.onCreate"), f("Lcom/x/B;", "FileOutputStream.<init>", entry = "com.x.Main.onCreate"))
        Correlation.ENTRY_EDGE = false
        try { assertTrue(Correlation.groups(cards).isEmpty()) } finally { Correlation.ENTRY_EDGE = true }
        assertEquals(1, Correlation.groups(cards).size)
    }

    @Test fun unrelatedCardsStayApart() {
        val cards = listOf(f("Lcom/x/A;", "WebView.loadUrl", entry = "com.x.A.onCreate"), f("Lcom/x/B;", "FileOutputStream.<init>", entry = "com.x.B.onCreate"),
            f("Lcom/x/C;", "SQLiteDatabase.rawQuery"))
        assertTrue(Correlation.groups(cards).isEmpty())
    }

    @Test fun aSingleHighIsAloneAndLowCardsDoNotLink() {
        assertTrue(Correlation.groups(listOf(f("Lcom/x/A;", "FileOutputStream.<init>"))).isEmpty())
        // twin: the second card shares the class and sink but is LOW: no group of two MEDIUM-or-worse cards
        assertTrue(Correlation.groups(listOf(f("Lcom/x/A;", "FileOutputStream.<init>"), f("Lcom/x/A;", "FileOutputStream.<init>", sev = Severity.LOW))).isEmpty())
    }

    @Test fun rendersInMarkdownAndHtml() {
        val cards = listOf(f("Lcom/x/Store;", "FileOutputStream.<init>"), f("Lcom/x/Store;", "FileOutputStream.<init>", "SharedPreferences.getString()"), f("Lcom/x/Other;", "WebView.loadUrl", title = "Untrusted input is loaded into a WebView"))
        val md = ReportBuilder.securitySection(cards, 400, "com.x")
        assertEquals(2, Regex("Related findings: #1, #2\\.").findAll(md).count())
        val html = ReportBuilder.html("com.x", "", cards, emptyList())
        assertEquals(2, Regex("Related findings: #1, #2\\.").findAll(html).count())
    }
}
