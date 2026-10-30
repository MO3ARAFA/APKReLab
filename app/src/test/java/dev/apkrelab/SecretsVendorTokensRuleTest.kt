package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 0.89.0: the vendor-token rule on smali string constants, with a placeholder twin for every positive. */
class SecretsVendorTokensRuleTest {
    private fun load() { SecretFormats.load(listOf(File("src/main/assets/secret_formats.json"), File("app/src/main/assets/secret_formats.json")).first { it.exists() }.readText()) }

    private fun cls(token: String) = ".class public Lcom/x/K;\n.super Ljava/lang/Object;\n.method public static t()Ljava/lang/String;\n    .locals 1\n    const-string v0, \"$token\"\n    return-object v0\n.end method\n"

    private fun scan(token: String) = SecretsVendorTokensRule.scan(RuleContext("Lcom/x/K;", 0, cls(token), "com.x"))

    @Test fun aVendorTokenInAStringConstantIsHigh() {
        load()
        val f = scan("sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs")
        assertEquals(1, f.size)
        assertEquals(SecurityScanner.Severity.HIGH, f[0].severity)
        assertTrue(f[0].detail.contains("stripe-access-token"))
        assertFalse(f[0].detail.contains("OuEMLAlTW"))                       // the value is shown shortened, never in full
    }

    @Test fun aPrefixedTokenThatLooksLikeAnIdentifierIsStillAToken() {                          // a real api_org_ token was rejected by the identifier filter
        load()
        val f = scan("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")
        assertTrue(f.any { it.detail.contains("huggingface-organization-api-token") })
    }

    @Test fun placeholdersAndTemplatesAreNotReported() {                                         // negative twin
        load()
        assertTrue(scan("sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").isEmpty())
        assertTrue(scan("sk_test_your_stripe_key_goes_here_00000000").isEmpty())
        assertTrue(scan("sk-ant-api03-fakefakefakefakefakefakefakefakefakefake").isEmpty())
        assertTrue(scan("a perfectly ordinary sentence in a string constant").isEmpty())
        assertTrue(SecretFormats.looksLikePlaceholder("aaaaaaaaaaaaaaaa"))
        assertFalse(SecretFormats.looksLikePlaceholder("kQ3vN8zL1xW5cR9tY2bH7mD4"))
    }
}
