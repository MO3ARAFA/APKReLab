package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.78.0: JavaScript bridges are judged by what their exposed methods can do (real-app set 3: Kiwix, Markor). */
class SetThreeFixes0780Test {

    private fun ctx(text: String) = RuleContext("Lcom/example/F;", 0, text, "com.example")

    private fun fragment(bridgeReg: String, exposedBody: String) = """
        .class public Lcom/example/F;
        .super Ljava/lang/Object;
        .method public setup(Landroid/webkit/WebView;)V
            .locals 2
            new-instance v1, Lcom/example/Other;
            invoke-direct {v1}, Lcom/example/Other;-><init>()V
            const-string v0, "Android"
            invoke-virtual {p1, $bridgeReg, v0}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
            return-void
        .end method
        .method public callback(Ljava/lang/String;)V
            .locals 2
            .annotation runtime Landroid/webkit/JavascriptInterface;
            .end annotation
            $exposedBody
            return-void
        .end method
    """.trimIndent()

    private val toast = "const-string v0, \"toast\"\n            invoke-virtual {p1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z"
    private val write = "new-instance v0, Ljava/io/FileOutputStream;\n            invoke-direct {v0, p1}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V"

    @Test fun selfBridgeWithHarmlessMethodsIsMedium() {          // Markor DocumentEditAndViewFragment
        val r = WebviewJsInterfaceRule.scan(ctx(fragment("p0", toast)))
        assertEquals(SecurityScanner.Severity.MEDIUM, r[0].severity)
    }

    @Test fun selfBridgeThatWritesFilesIsHigh() {
        val r = WebviewJsInterfaceRule.scan(ctx(fragment("p0", write)))
        assertEquals(SecurityScanner.Severity.HIGH, r[0].severity)
        assertTrue(r[0].detail.contains("callback(): files"))
    }

    @Test fun bridgeInAnotherClassIsMediumAtTheCallSite() {
        assertEquals(SecurityScanner.Severity.MEDIUM, WebviewJsInterfaceRule.scan(ctx(fragment("v1", write)))[0].severity)
    }

    @Test fun theBridgeClassItselfReportsItsDangerousMethods() {
        assertEquals(1, JsBridgeMethodRule.scan(ctx(fragment("v1", write))).size)
        assertTrue(JsBridgeMethodRule.scan(ctx(fragment("v1", toast))).isEmpty())
    }
}
