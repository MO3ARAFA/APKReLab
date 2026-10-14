package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.81.0: fixes from real-app set 6 (AnkiDroid, Jellyfin) and the self-hosted / opt-in network configuration cards of sets 4-6. */
class SetSixFixes0810Test {

    private fun ctx(text: String, type: String = "Lcom/x/P;") = RuleContext(type, 0, text, "com.x")

    private fun provider(queryBody: String, insertBody: String) = """
        .class public Lcom/x/P;
        .super Landroid/content/ContentProvider;
        .method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
            .locals 2
            $queryBody
            const/4 v0, 0x0
            return-object v0
        .end method
        .method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
            .locals 2
            $insertBody
            const/4 v0, 0x0
            return-object v0
        .end method
        .method private checkAccess()V
            .locals 2
            const-string v0, "com.x.permission.RW"
            invoke-virtual {p0, v0}, Landroid/content/ContentProvider;->checkCallingPermission(Ljava/lang/String;)I
            return-void
        .end method
    """.trimIndent()

    private val direct = "const-string v0, \"com.x.permission.RW\"\n            invoke-virtual {p0, v0}, Landroid/content/ContentProvider;->enforceCallingPermission(Ljava/lang/String;Ljava/lang/String;)V"
    private val helper = "invoke-direct {p0}, Lcom/x/P;->checkAccess()V"

    @Test fun providerCheckedInEveryMethodGetsTheMarkerAndOneOpenMethodDoesNot() {
        assertEquals(1, ProviderCodePermissionRule.scan(ctx(provider(direct, helper))).size)
        assertTrue(ProviderCodePermissionRule.scan(ctx(provider(direct, "nop"))).isEmpty())   // insert is open: no lowering
    }

    @Test fun theManifestProviderCardIsLoweredOnlyForTheCheckedProvider() {
        val marker = ProviderCodePermissionRule.scan(ctx(provider(direct, helper)))[0].also { it.ruleId = "provider-code-permission" }
        val card = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Exported provider without a permission: com.x.P", "d", "r", cwe = "CWE-926")
            .also { it.ruleId = "manifest-exported-components" }
        val other = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Exported provider without a permission: com.x.Other", "d", "r", cwe = "CWE-926")
            .also { it.ruleId = "manifest-exported-components" }
        assertEquals(1, FindingPolish.applyProviderCodeChecks(listOf(marker, card, other)))
        assertEquals(SecurityScanner.Severity.LOW, card.severity)
        assertEquals(SecurityScanner.Severity.HIGH, other.severity)
        assertEquals(0, FindingPolish.applyProviderCodeChecks(listOf(marker, card, other)))   // idempotent
    }

    private fun net(url: String) = """
        .class public Lcom/x/Api;
        .method public call()V
            .locals 2
            new-instance v0, Ljava/net/URL;
            const-string v1, "$url"
            invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
            return-void
        .end method
    """.trimIndent()

    @Test fun cleartextConfigIsMediumAndGoesHighOnlyWithAPlainHttpUrlInTheAppsCode() {
        fun cfg() = SecurityScanner.Finding(SecurityScanner.Severity.MEDIUM, "Network Security Config: cleartext permitted", "d", "r", cwe = "CWE-319")
            .also { it.ruleId = "res-nsc-cleartext" }
        val c1 = cfg()
        assertEquals(0, FindingPolish.applyNetworkEvidence(listOf(c1)))
        assertEquals(SecurityScanner.Severity.MEDIUM, c1.severity)
        val use = CleartextUrlUsedRule.scan(ctx(net("http://api.broker.com/v1/login"), "Lcom/x/Api;"))
        assertEquals(1, use.size)
        use[0].ruleId = "cleartext-url-used"
        val c2 = cfg()
        assertEquals(1, FindingPolish.applyNetworkEvidence(listOf(c2) + use))
        assertEquals(SecurityScanner.Severity.HIGH, c2.severity)
        assertTrue(CleartextUrlUsedRule.scan(ctx(net("http://localhost:8080/x"), "Lcom/x/Api;")).isEmpty())
        assertTrue(CleartextUrlUsedRule.scan(ctx(net("http://schemas.android.com/apk/res/android"), "Lcom/x/Api;")).isEmpty())
    }

    @Test fun separateProcessCrashDialogLowersItsIntentFlowButMainProcessActivitiesDoNot() {
        val mc = ManifestContext("""
            <manifest package="com.x"><application>
            <activity android:name="org.acra.dialog.CrashReportDialog" android:process=":acra"/>
            <activity android:name=".Prefs"/>
            </application></manifest>
        """.trimIndent())
        val sp = FindingPolish.separateProcessActivities(mc)
        assertEquals(setOf("Lorg/acra/dialog/CrashReportDialog;"), sp)
        val acra = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Untrusted input is used as a file path",
            "Data from Intent.getSerializableExtra() (through field vm1.b (written in vm1.<init>(Lorg/acra/dialog/CrashReportDialog;Landroid/content/Intent;)V)) ...",
            "r", "Ljx2;", 1, 1, "CWE-22").also { it.ruleId = "taint-flow" }
        val prefs = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Untrusted input selects a class", "Data from Intent.getStringExtra() reaches Class.forName()",
            "r", "Lcom/x/Prefs;", 2, 1, "CWE-470").also { it.ruleId = "taint-flow" }
        assertEquals(1, FindingPolish.lowerSeparateProcessDialogs(listOf(acra, prefs), sp))
        assertEquals(SecurityScanner.Severity.MEDIUM, acra.severity)
        assertEquals(SecurityScanner.Severity.HIGH, prefs.severity)
    }

    @Test fun jsBridgeFollowsHelpersOfTheSameClass() {
        val t = """
            .class public Lcom/x/Bridge;
            .method public openUrl(Ljava/lang/String;)Z
                .locals 1
                .annotation runtime Landroid/webkit/JavascriptInterface;
                .end annotation
                invoke-direct {p0, p1}, Lcom/x/Bridge;->launch(Ljava/lang/String;)V
                const/4 v0, 0x1
                return v0
            .end method
            .method private launch(Ljava/lang/String;)V
                .locals 2
                new-instance v0, Landroid/content/Intent;
                invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
                return-void
            .end method
        """.trimIndent()
        val d = JsBridgeMethodRule.dangerousExposed(t)
        assertEquals(1, d.size)
        assertTrue(d[0].contains("via launch()"))
    }
}
