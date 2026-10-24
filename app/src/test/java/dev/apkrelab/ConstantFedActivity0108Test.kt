package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.108.0: a HIGH Intent-extra flow in a NON-exported activity drops one level only when every writer of the extras it reads puts a fixed value. */
class ConstantFedActivity0108Test {
    private val reader = "Lcom/x/WebAct;"
    private fun readerText() = ".class public $reader\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n" +
        "    invoke-virtual {p0}, Lcom/x/WebAct;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"url\"\n" +
        "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n    return-void\n.end method\n"
    private fun writer(type: String, value: String) = ".class public $type\n.super Landroid/app/Activity;\n.method public open()V\n    .locals 4\n    new-instance v0, Landroid/content/Intent;\n" +
        "    const-string v1, \"url\"\n$value    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n    return-void\n.end method\n"
    private val constant = "    const-string v2, \"https://fixed.example/signup\"\n"
    private val forwarded = "    invoke-virtual {p0}, Lcom/x/Login;->getIntent()Landroid/content/Intent;\n    move-result-object v3\n    invoke-virtual {v3, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
    private fun card() = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Untrusted input is loaded into a WebView",
        "Data from Intent.getStringExtra() reaches WebView.loadUrl() in method onCreate().", "fix", reader, 0, 10, "CWE-79").also { it.ruleId = "taint-flow" }

    private fun run(vararg writers: String, internal: Set<String> = setOf(reader)): SecurityScanner.Finding {
        IntentExtras.clear(); IntentExtras.collect(reader, readerText())
        for ((i, w) in writers.withIndex()) IntentExtras.collect("Lcom/x/W$i;", writer("Lcom/x/W$i;", w))
        val f = card(); FindingPolish.lowerConstantFedActivities(listOf(f), internal); IntentExtras.clear(); return f
    }

    @Test fun everyWriterFixedLowersTheCard() {
        val f = run(constant)
        assertEquals(SecurityScanner.Severity.MEDIUM, f.severity); assertTrue(f.adjusted, f.adjusted.contains("puts a fixed value") && f.adjusted.contains("\"url\""))
    }

    @Test fun theTwinsKeepHigh() {
        assertEquals(SecurityScanner.Severity.HIGH, run(forwarded).severity)                              // a writer that forwards a caller's extra (OVAA shape)
        assertEquals(SecurityScanner.Severity.HIGH, run(constant, forwarded).severity)                    // one forwarding writer is enough
        assertEquals(SecurityScanner.Severity.HIGH, run().severity)                                       // no writer seen
        assertEquals(SecurityScanner.Severity.HIGH, run(constant, internal = emptySet()).severity)        // an exported activity
    }
}
