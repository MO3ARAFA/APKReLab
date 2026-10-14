package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.76.0: false positives found by the first real-app held-out run (andOTP, Password Store, Unstoppable). Each has a "still found" twin. */
class RealAppFixes0760Test {

    private fun ctx(text: String, type: String = "Lcom/example/A;") = RuleContext(type, 0, text, "com.example")

    @Test fun publicValuesAreNotSecretsButRandomKeysStillAre() {
        for (s in listOf("getApplicationContext(...)", "safeTransferFrom(address,address,uint256,bytes)", "balanceOf(address,uint256)",
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
                "index_TokenTransfer_transactionHash", "averagePrice7d_tokenQueryId", "sellTokenQuantityRemain_"))
            assertTrue(s, SecurityScanner.looksLikeName(s))
        for (s in listOf("q8Zr3LmXv0Tp9Wn2Ys7Kd4Hb_x", "sk_live_51HxQwErTy7u8I9o0PaSdFgHj",
                // a Solana SECRET key is 87-88 base58 chars: not an address
                "4Z7cXSyeFR8wNGMVXUE1TwtKn5D5Vu7FzEv69dokLv7KrQk7h6pu4LF8ZRR9yQBhc7uSM6RTTZtU1fmaxiNrxXrs"))
            assertFalse(s, SecurityScanner.looksLikeName(s))
    }

    private fun cipher(algo: String) = """
        .class public Lcom/example/A;
        .method public a()V
            .locals 1
            const-string v0, "$algo"
            invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
            return-void
        .end method
    """.trimIndent()

    @Test fun rsaEcbIsNotCalledEcbButAesEcbStillIs() {
        val rsa = CryptoCipherRule.scan(ctx(cipher("RSA/ECB/PKCS1Padding")))
        assertEquals(1, rsa.size)
        assertEquals(SecurityScanner.Severity.LOW, rsa[0].severity)
        assertTrue(rsa[0].title.startsWith("RSA with PKCS#1"))
        assertEquals(SecurityScanner.Severity.HIGH, CryptoCipherRule.scan(ctx(cipher("AES/ECB/PKCS5Padding")))[0].severity)
        assertTrue(CryptoCipherRule.scan(ctx(cipher("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"))).isEmpty())
    }

    private fun lit(s: String) = """
        .class public Lcom/example/A;
        .method public a()V
            .locals 1
            const-string v0, "$s"
            return-void
        .end method
    """.trimIndent()

    @Test fun pemHeaderOfAParserIsNotAKeyButAHeaderWithABodyIs() {
        assertTrue(SecretsKnownFormatsRule.scan(ctx(lit("-----BEGIN RSA PRIVATE KEY-----"))).isEmpty())
        val body = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
        assertEquals(1, SecretsKnownFormatsRule.scan(ctx(lit("-----BEGIN RSA PRIVATE KEY-----\\n$body"))).size)
    }

    @Test fun bip32AndSlip10SeedKeysAreSpecConstants() {
        fun hmac(k: String) = """
            .class public Lcom/example/A;
            .method public a([B)V
                .locals 3
                const-string v0, "$k"
                invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
                move-result-object v0
                new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
                const-string v2, "HmacSHA512"
                invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
                return-void
            .end method
        """.trimIndent()
        assertTrue(CryptoHardcodedKeyRule.scan(ctx(hmac("ed25519 seed"))).isEmpty())
        assertEquals(1, CryptoHardcodedKeyRule.scan(ctx(hmac("myS3cretK3y!2024"))).size)
    }

    private fun prefs(opens: Boolean) = """
        .class public Lcom/example/A;
        .method public save(Ljava/lang/String;)V
            .locals 3
            ${if (opens) "const-string v1, \"p\"\n            const/4 v2, 0x0\n            invoke-virtual {p0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;" else ""}
            iget-object v0, p0, Lcom/example/A;->proxyPrefs:Landroid/content/SharedPreferences${'$'}Editor;
            const-string v1, "proxy_password"
            invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences${'$'}Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences${'$'}Editor;
            return-void
        .end method
    """.trimIndent()

    @Test fun injectedPrefsAreALowLeadButPrefsOpenedHereStayHigh() {
        val inj = UnencryptedSensitiveStorageRule.scan(ctx(prefs(false)))
        assertEquals(SecurityScanner.Severity.LOW, inj[0].severity)
        assertEquals("LOW", inj[0].confidence)
        assertEquals(SecurityScanner.Severity.HIGH, UnencryptedSensitiveStorageRule.scan(ctx(prefs(true)))[0].severity)
    }

    @Test fun gitSshAndChainSdksAreLibraries() {
        for (t in listOf("Lorg/eclipse/jgit/util/FS;", "Lcom/jcraft/jsch/KeyPairRSA;", "Lcom/hierynomus/sshj/userauth/X;", "Lcom/solana/core/PublicKey;", "Lorg/stellar/sdk/SLIP10;"))
            assertEquals(t, SecurityScanner.Scope.LIB, SecurityScanner.scopeOf(t, "app.passwordstore"))
    }
}
