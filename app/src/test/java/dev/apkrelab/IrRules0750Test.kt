package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.75.0: the Kotlin side of the IR rules (RuleContext.ir, ruleId / confidence copied from the hit) and the tapjacking layout rule. */
class IrRules0750Test {

    private fun ctx(text: String) = RuleContext("Lcom/example/A;", 0, text, "com.example")

    @Test fun broadcastRuleUsesTheIrAndKeepsItsId() {
        val t = """
            .class public Lcom/example/A;
            .super Landroid/app/Activity;
            .method public go()V
                .locals 3
                new-instance v0, Landroid/content/Intent;
                const-string v1, "com.example.Broadcast"
                invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
                invoke-virtual {p0, v0}, Lcom/example/A;->sendBroadcast(Landroid/content/Intent;)V
                return-void
            .end method
        """.trimIndent()
        val r = BroadcastUnprotectedSendRule.scan(ctx(t))
        assertEquals(1, r.size)
        assertEquals("broadcast-unprotected-send", r[0].ruleId)
        assertEquals("HIGH", r[0].confidence)
        // the 0.48 text rule needed an ".action." name or a sensitive word and missed this (Vuldroid EmailViewer)
        assertTrue(BroadcastUnprotectedSendRule.legacy(ctx(t)).isEmpty())
    }

    private fun layout(field: String, root: String = "") = """
        <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" $root>
        <EditText android:id="@id/password" $field />
        </LinearLayout>
    """.trimIndent()

    private fun tap(xml: String, apk: ApkFacts = ApkFacts.NONE): List<SecurityScanner.Finding> {
        val c = ResourceContext("res/layout/activity_login.xml", xml, apk = apk)
        return if (TapjackingLayoutRule.appliesTo(c)) TapjackingLayoutRule.scan(c) else emptyList()
    }

    @Test fun passwordFieldWithoutFilterIsMedium() {
        val r = tap(layout("android:inputType=\"0x81\""))
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, r[0].severity)
    }

    @Test fun filterOnTheRootProtectsTheWholeLayout() {
        assertTrue(tap(layout("android:inputType=\"0x81\"", "android:filterTouchesWhenObscured=\"true\"")).isEmpty())
    }

    @Test fun plainTextFieldIsNotAPasswordScreen() {
        assertTrue(tap(layout("android:inputType=\"0x1\"")).isEmpty())
    }

    @Test fun codeMitigationLowersAndMinSdk31MakesItInfo() {
        assertEquals(SecurityScanner.Severity.LOW, tap(layout("android:inputType=\"0x81\""), ApkFacts(23, setOf("setFilterTouchesWhenObscured")))[0].severity)
        assertEquals(SecurityScanner.Severity.INFO, tap(layout("android:inputType=\"0x81\""), ApkFacts(31, emptySet()))[0].severity)
    }

    @Test fun libraryLayoutsAreSkipped() {
        val c = ResourceContext("res/layout/mtrl_text_input.xml", layout("android:inputType=\"0x81\""))
        assertTrue(!TapjackingLayoutRule.appliesTo(c))
    }

    @Test fun minSdkIsReadInDecimalAndHex() {
        assertEquals(21, ApkFacts.minSdkOf("<uses-sdk android:minSdkVersion=\"21\"/>"))
        assertEquals(21, ApkFacts.minSdkOf("<uses-sdk android:minSdkVersion=\"0x15\"/>"))
    }

    @Test fun everyNewRuleHasAKnowledgeEntry() {
        assertTrue(RuleRegistry.audit().isEmpty())
    }

    // ---------------- 0.75.2

    private fun f(rule: String, title: String, sev: SecurityScanner.Severity, cls: Int = 3, file: String = "") =
        SecurityScanner.Finding(sev, title, "d", "r", if (cls >= 0) "Lcom/example/P;" else null, cls, 10, "CWE-1", file).also { it.ruleId = rule }

    @Test fun ssaRedirectionAbsorbsTheTextRuleOfTheSameClass() {
        val list = listOf(
            f("taint-flow", "Untrusted Intent is launched by this app (intent redirection)", SecurityScanner.Severity.HIGH),
            f("intent-redirection", "Possible intent redirection (an Intent from the extras is launched)", SecurityScanner.Severity.MEDIUM))
        val d = SecurityScanner.dedupe(list)
        assertEquals(1, d.size)
        assertEquals("taint-flow", d[0].ruleId)
        // another class keeps its own text finding
        assertEquals(2, SecurityScanner.dedupe(listOf(list[0], f("intent-redirection", "Possible intent redirection", SecurityScanner.Severity.MEDIUM, 4))).size)
    }

    @Test fun sqliteRuleAbsorbsTheAndroGoatSqliteCheck() {
        val d = SecurityScanner.dedupe(listOf(
            f("sqlite-unencrypted", "Sensitive data stored in plain SQLite", SecurityScanner.Severity.MEDIUM),
            f("androgoat-checks", "Sensitive value written to SQLite (plaintext)", SecurityScanner.Severity.MEDIUM)))
        assertEquals(listOf("sqlite-unencrypted"), d.map { it.ruleId })
    }

    @Test fun layoutFindingsAreGroupedIntoOneCard() {
        val t = "Password screen not protected against tapjacking"
        val list = listOf(
            f("tapjacking-sensitive-layout", t, SecurityScanner.Severity.MEDIUM, -1, "res/layout/a.xml"),
            f("tapjacking-sensitive-layout", t, SecurityScanner.Severity.MEDIUM, -1, "res/layout/b.xml"),
            f("tapjacking-sensitive-layout", t, SecurityScanner.Severity.MEDIUM, -1, "res/layout/c.xml"),
            f("res-nsc-cleartext", "Other", SecurityScanner.Severity.LOW, -1, "res/xml/n.xml"))
        val g = ResourceScanner.groupLayoutFindings(list)
        assertEquals(2, g.size)
        val card = g.first { it.title == t }
        assertEquals(3, card.count)
        assertTrue(card.detail.contains("res/layout/b.xml") && card.detail.contains("res/layout/c.xml"))
    }

    @Test fun fintechStorageTitleSaysCredentialForAPasswordKey() {
        val t = """
            .class public Lcom/example/A;
            .method public save(Landroid/content/SharedPreferences${'$'}Editor;Ljava/lang/String;)V
                .locals 2
                const-string v0, "password"
                invoke-interface {p1, v0, p2}, Landroid/content/SharedPreferences${'$'}Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences${'$'}Editor;
                return-void
            .end method
        """.trimIndent()
        val r = UnencryptedSensitiveStorageRule.scan(ctx(t))
        assertTrue(r.isNotEmpty())
        assertTrue(r.none { it.title.contains("financial") })
    }

    @Test fun androGoatSqlCheckReadsOnlyTheColumns() {
        assertEquals(null, AndroGoatChecks.sqlColumnPart("insert into note values ('a', 'my password')"))
        assertEquals(" user, note ", AndroGoatChecks.sqlColumnPart("insert into note ( user, note ) values ('admin', 'her password')"))
        assertTrue(AndroGoatChecks.sqlColumnPart("create table users (name text, password text)")!!.contains("password"))
    }
}
