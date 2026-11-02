package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 3.0.0: the scanner scanning itself reported cards for classes that only SPELL an API or a host name (rule tables, lambdas that test a signature string).
 * Each rule below now needs the instruction (invoke / sget / new-instance) or a real value shape. Every positive has a twin: the string alone gives no card.
 */
class SelfScanTighteningTest {
    private fun scan(rule: ScanRule, body: String, pkg: String = "com.x"): List<SecurityScanner.Finding> =
        rule.scan(RuleContext("Lcom/x/C;", 0, ".class public Lcom/x/C;\n.super Ljava/lang/Object;\n" + body, pkg))
    private fun m(code: String) = ".method public run(Ljava/lang/String;)V\n    .locals 6\n$code\n    return-void\n.end method\n"

    @Test fun shellExecNeedsAnInvokeNotAStringThatNamesIt() {
        val named = m("    const-string v0, \"Ljava/lang/Runtime;->exec(\"\n    invoke-virtual {p1, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z")
        assertTrue(scan(ShellExecRule, named).isEmpty())
        val real = m("    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;\n    move-result-object v0\n    invoke-virtual {v0, p1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;")
        assertEquals(1, scan(ShellExecRule, real).size)
    }

    @Test fun jacksonLaissezFaireNeedsTheTypeReferencedByAnInstruction() {
        val named = m("    const-string v0, \"LaissezFaireSubTypeValidator\"") + "\n# com/fasterxml/jackson/\n"
        assertTrue(scan(JacksonDefaultTypingRule, ".field x:Lcom/fasterxml/jackson/databind/ObjectMapper;\n" + named + m("    const-string v1, \"Lcom/fasterxml/jackson/databind/ObjectMapper;->activateDefaultTyping(\"")).isEmpty())
        val real = m("    new-instance v0, Lcom/fasterxml/jackson/databind/ObjectMapper;\n    sget-object v1, Lcom/fasterxml/jackson/databind/jsontype/impl/LaissezFaireSubTypeValidator;->instance:Lcom/fasterxml/jackson/databind/jsontype/impl/LaissezFaireSubTypeValidator;\n" +
            "    invoke-virtual {v0, v1}, Lcom/fasterxml/jackson/databind/ObjectMapper;->activateDefaultTyping(Lcom/fasterxml/jackson/databind/jsontype/PolymorphicTypeValidator;)Lcom/fasterxml/jackson/databind/ObjectMapper;")
        assertEquals(1, scan(JacksonDefaultTypingRule, real).size)
    }

    @Test fun weakHostValidationNeedsRealCalls() {
        val named = m("    const-string v0, \"Landroid/net/Uri;->getHost()\"\n    const-string v1, \"Ljava/lang/String;->startsWith(\"")
        assertTrue(scan(DeeplinkHostValidationRule, named).isEmpty())
        val real = m("    invoke-virtual {p1}, Landroid/net/Uri;->getHost()Ljava/lang/String;\n    move-result-object v0\n    const-string v1, \"example.com\"\n    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z")
        assertEquals(1, scan(DeeplinkHostValidationRule, real).size)
    }

    @Test fun aSignatureStringIsNotAHighEntropySecret() {
        fun cls(lit: String) = ".class public Lcom/x/C;\n.super Ljava/lang/Object;\n.method public run()V\n    .locals 2\n    const-string v0, \"$lit\"\n    const-string v1, \"api_token\"\n    return-void\n.end method\n"
        val sig = SecurityScanner.scanHighEntropyStrings("Lcom/x/C;", 0, cls("Lcom/facebook/Ab9;->xQ7pLz2(Lcom/foo/Bar;)V"))
        assertTrue(sig.toString(), sig.none { it.severity != SecurityScanner.Severity.INFO })
        for (code in listOf("Landroid/security/ConfirmationPrompt", "AccountManager.getPassword()", "(ILjava/lang/Object;)Ljava/lang/String;"))
            assertTrue(code, SecurityScanner.scanHighEntropyStrings("Lcom/x/C;", 0, cls(code)).none { it.severity != SecurityScanner.Severity.INFO })
        val secret = SecurityScanner.scanHighEntropyStrings("Lcom/x/C;", 0, cls("kJ8fP2xQ9zLm4Vb7Nc1RtYw6HsD3gAe5U0"))
        assertTrue(secret.any { it.severity != SecurityScanner.Severity.INFO })     // twin: a real random string near a credential name still reports
    }

    @Test fun aBareFirebaseHostNameIsNotADatabaseUrl() {
        assertFalse(Regex("[A-Za-z0-9][A-Za-z0-9-]{2,}(?:\\.[A-Za-z0-9-]+)?\\.(?:firebaseio\\.com|firebasedatabase\\.app)").containsMatchIn("firebaseio.com"))
        assertTrue(Regex("[A-Za-z0-9][A-Za-z0-9-]{2,}(?:\\.[A-Za-z0-9-]+)?\\.(?:firebaseio\\.com|firebasedatabase\\.app)").containsMatchIn("https://my-proj.firebaseio.com"))
    }
}
