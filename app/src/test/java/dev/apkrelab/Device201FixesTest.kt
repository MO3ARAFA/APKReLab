package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.0.1: precision fixes found in the three device reports (WE Wallet, JustMarkets, Axis Pay 3.1.0). */
class Device201FixesTest {
    private fun cls(body: String) = ".class public Lcom/example/StartupActivity;\n.super Landroid/app/Activity;\n\n.method protected onCreate(Landroid/os/Bundle;)V\n    .registers 6\n$body\n.end method\n"
    private fun scan(body: String) = ExportedSensitiveActionRule.scan(RuleContext("Lcom/example/StartupActivity;", 0, cls(body), "com.example"))

    private val router = """
    invoke-virtual {p0}, Lcom/example/StartupActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "target"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Lcom/example/CashOutActivity;
    invoke-direct {v2}, Lcom/example/CashOutActivity;->CashOutActivity()V
    return-void"""

    @Test fun aNameOnlyMatchIsAMediumLeadNotHigh() {
        val f = scan(router)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity)
        assertTrue(f[0].detail, f[0].detail.contains("no value was traced"))
    }

    // twin: a caller check in between silences the rule as before
    @Test fun aCallerCheckBetweenStillSilencesIt() {
        assertEquals(0, scan(router.replace("    new-instance v2", "    invoke-virtual {p0}, Lcom/example/StartupActivity;->getCallingUid()I\n    new-instance v2")).size)
    }
}
