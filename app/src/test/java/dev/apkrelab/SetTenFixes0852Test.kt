package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.85.2: the four false-positive families of set 10 (Feeder, Nextcloud Notes), each with its negative twin. */
class SetTenFixes0852Test {

    private fun ctx(type: String, text: String) = RuleContext(type, 0, text, "com.example.app")

    private fun literalClass(lit: String) =
        ".class public Lcom/example/app/Foo;\n.super Ljava/lang/Object;\n.method public static a()V\n    .locals 1\n    const-string v0, \"$lit\"\n    return-void\n.end method\n"

    private fun apiKeyTitles(lit: String) =
        AndroGoatChecks.scan("Lcom/example/app/Foo;", 0, literalClass(lit), "com.example.app").map { it.title }

    // 1. a placeholder key (Feeder: a Compose preview passes "sk-test_" + 40 X)
    @Test fun placeholderOpenAiKeyIsNotReported() {
        assertTrue(apiKeyTitles("sk-test_" + "X".repeat(40)).none { it.startsWith("OpenAI") })
    }
    @Test fun realLookingOpenAiKeyIsStillReported() {
        assertTrue(apiKeyTitles("sk-proj-Qm7Zt3Lp9Wv2Rn5Yb8Kc4Hd6Fs1Jg0Xa").any { it.startsWith("OpenAI") })
    }

    // 2. Jetpack Compose source-info strings (Nextcloud Notes CustomLinkKt)
    @Test fun composeSourceInfoIsNotASecret() {
        assertTrue(SecurityScanner.looksLikeName("CC(remember):CustomLink.kt#9igjgp"))
        assertTrue(SecurityScanner.looksLikeName("C100@3593L289,99@3555L551:CustomLink.kt#6zovcv"))   // no parenthesis: position list only
        assertTrue(SecurityScanner.looksLikeName("C(Column)N(modifier,verticalArrangement,horizontalAlignment,content)87@4443L61,88@4509L134:Column.kt#2w3rfo"))
        val text = ".class public Lcom/example/app/CustomLinkKt;\n.method public static a()V\n    .locals 2\n" +
            "    const-string v0, \"CC(remember):CustomLink.kt#9igjgp\"\n    const-string v1, \"token\"\n    return-void\n.end method\n"
        assertTrue(SecurityScanner.scanHighEntropyStrings("Lcom/example/app/CustomLinkKt;", 0, text).none { it.severity == SecurityScanner.Severity.HIGH })
    }
    @Test fun randomKeyShapedLikeComposeInfoIsNotWhitelisted() {
        assertFalse(SecurityScanner.looksLikeName("Xk9mQ2vLp7Rt4WzNb8YcHd6Fs1JgA0eU3"))
        assertFalse(SecurityScanner.looksLikeName("CC(Xk9mQ2vLp7Rt4WzNb8Yc):Hd6Fs1JgA0eU3Zq"))     // same start, no .kt#hash tail
    }

    // 3. a PHP class name with backslashes, as smali writes it (Nextcloud Notes Recipient.TOKEN_RECIPIENT_CLASS)
    @Test fun backslashClassNameIsNotASecret() {
        val v = "OC\\\\Core\\\\Sharing\\\\Recipient\\\\TokenShareRecipientType"   // two literal backslashes between segments, like the smali text
        assertTrue(SecurityScanner.looksLikeName(v))
        val text = ".class public Lcom/example/app/Recipient;\n.field public static final TOKEN_RECIPIENT_CLASS:Ljava/lang/String; = \"$v\"\n"
        assertTrue(SecretsSensitiveFieldsRule.scan(ctx("Lcom/example/app/Recipient;", text)).isEmpty())
    }
    @Test fun aSecretFieldStillFires() {
        val text = ".class public Lcom/example/app/Recipient;\n.field public static final API_TOKEN:Ljava/lang/String; = \"Xk9mQ2vLp7Rt4WzNb8YcHd6Fs1JgA0eU3\"\n"
        assertEquals(1, SecretsSensitiveFieldsRule.scan(ctx("Lcom/example/app/Recipient;", text)).size)
    }

    // 4. HTTP header names (ktor HttpHeaders.LockToken / AccessControlAllowCredentials)
    @Test fun headerNamesAreNotSecrets() {
        for (h in listOf("Access-Control-Allow-Credentials", "Lock-Token", "Proxy-Authorization", "Set-Cookie")) assertTrue(h, SecurityScanner.looksLikeName(h))
        for (name in listOf("LockToken", "AccessControlAllowCredentials")) {
            val v = if (name == "LockToken") "Lock-Token" else "Access-Control-Allow-Credentials"
            val text = ".class public Lcom/example/app/HttpHeaders;\n.field public static final $name:Ljava/lang/String; = \"$v\"\n"
            assertTrue(name, SecretsSensitiveFieldsRule.scan(ctx("Lcom/example/app/HttpHeaders;", text)).isEmpty())
        }
    }
    @Test fun consonantOnlyDashedKeyIsNotAHeaderName() {
        assertFalse(SecurityScanner.looksLikeName("Qzx-Prt-Vwk-Bnm"))            // no vowels: random, not words
        assertFalse(SecurityScanner.looksLikeName("Ab3-Cd4-Ef5-Gh6"))            // digits
    }

    // 5. io.ktor is a library
    @Test fun ktorIsLibraryScope() {
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lio/ktor/http/HttpHeaders;", "it.niedermann.owncloud.notes"))
        assertEquals(SecurityScanner.Scope.APP, SecurityScanner.scopeOf("Lit/niedermann/owncloud/notes/Foo;", "it.niedermann.owncloud.notes"))
    }
}
