package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.0.0 step 2: rule fixes for in-scope misses of the real-CVE benchmark (tools/benchmark/cve), each with its negative twin. */
class CveBenchFixesTest {
    private fun cls(body: String) = ".class public Lcom/example/SettingsActivity;\n.super Landroid/app/Activity;\n\n.method protected onStart()V\n    .registers 5\n" + body + "\n.end method\n"
    private fun scan(body: String) = UriGrantViaResultRule.scan(RuleContext("Lcom/example/SettingsActivity;", 0, cls(body), "com.example"))

    // the shape of CVE-2021-41256 (Nextcloud News 0.9.9.62 SettingsActivity.onStart)
    private val reflected = """
    invoke-super {p0}, Landroid/app/Activity;->onStart()V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    .line 12
    move-result-object v0
    iget-object v1, p0, Lcom/example/SettingsActivity;->mPrefs:Landroid/content/SharedPreferences;
    const-string v2, "sp_feed_list_layout"
    const-string v3, "0"
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    const/4 v1, -0x1
    invoke-virtual {p0, v1, v0}, Landroid/app/Activity;->setResult(ILandroid/content/Intent;)V
    return-void"""

    @Test fun setResultOfTheIncomingIntentIsReported() {
        val f = scan(reflected)
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity)
        assertTrue(f[0].detail, f[0].detail.contains("getIntent()"))
    }

    @Test fun throughAMoveTheIncomingIntentIsStillReported() {
        assertEquals(1, scan(reflected.replace("invoke-virtual {p0, v1, v0}", "move-object v4, v0\n    invoke-virtual {p0, v1, v4}")).size)
    }

    // twin: the fixed release (0.9.9.63) returns its own Intent kept in a field
    @Test fun aResultIntentHeldInAFieldIsNotReported() {
        assertEquals(0, scan("""
    iget-object p1, p0, Lcom/example/SettingsActivity;->resultIntent:Landroid/content/Intent;
    const/4 v0, -0x1
    invoke-virtual {p0, v0, p1}, Landroid/app/Activity;->setResult(ILandroid/content/Intent;)V
    return-void""").size)
    }

    // twin: getIntent() is read, but the register is overwritten by a new Intent before setResult
    @Test fun aNewIntentInTheSameRegisterIsNotReported() {
        assertEquals(0, scan(reflected.replace("const/4 v1, -0x1", "new-instance v0, Landroid/content/Intent;\n    invoke-direct {v0}, Landroid/content/Intent;-><init>()V\n    const/4 v1, -0x1")).size)
    }

    // twin: a merge point between getIntent() and setResult(): the walk stops (straight-line code only)
    @Test fun aLabelInBetweenStopsTheWalk() {
        assertEquals(0, scan(reflected.replace("const/4 v1, -0x1", ":cond_0\n    const/4 v1, -0x1")).size)
    }
}
