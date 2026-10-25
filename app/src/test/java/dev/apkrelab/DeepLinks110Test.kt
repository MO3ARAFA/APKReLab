package dev.apkrelab

import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.1.0: deep links one filter at a time (the shape of Axis Pay 3.0.1's MainActivity: two verified https filters, one unverified, ten custom-scheme hosts). */
class DeepLinks110Test {
    private fun web(host: String, verify: Boolean) = """
        <intent-filter${if (verify) " android:autoVerify=\"true\"" else ""}>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="https" android:host="$host"/>
        </intent-filter>"""

    private fun manifest(thirdVerified: Boolean) = """
        <manifest package="com.example.wallet"><application>
        <activity android:name=".MainActivity" android:exported="true" android:launchMode="2">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="wallet" android:host="resetPin"/>
                <data android:scheme="wallet" android:host="cards"/>
            </intent-filter>
            ${web("a.example.io", true)}
            ${web("b.example.ge", true)}
            ${web("c.example.link", thirdVerified)}
        </activity>
        <activity android:name=".Other" android:exported="true">
            <intent-filter><action android:name="android.intent.action.SEND"/><data android:mimeType="text/plain"/></intent-filter>
        </activity>
        </application></manifest>
    """.trimIndent()

    @Test fun eachFilterIsJudgedOnItsOwn() {
        val links = DeepLinks.parse(manifest(false), "com.example.wallet")
        assertEquals(4, links.size)                                                            // the SEND filter is no link
        assertEquals(listOf("https://c.example.link"), links.filter { it.unverifiedWeb }.flatMap { it.uris })
        assertEquals(listOf("wallet://resetPin", "wallet://cards"), links[0].uris)
        assertTrue(links.all { it.launchMode == "singleTask" && it.activity == "com.example.wallet.MainActivity" })
        // twin: all three verified
        assertTrue(DeepLinks.parse(manifest(true), "com.example.wallet").none { it.unverifiedWeb })
    }

    @Test fun theRuleSeesTheUnverifiedFilterNextToVerifiedOnes() {
        val card = ManifestDeepLinksRule.scan(ManifestContext(manifest(false))).single { it.title.contains("MainActivity") }
        assertEquals(Severity.LOW, card.severity)
        assertTrue(card.detail, card.detail.contains("c.example.link"))
        assertFalse(card.detail, card.detail.contains("a.example.io,"))
        // twin: every web filter verified -> no autoVerify complaint (the custom scheme has hosts: INFO)
        val ok = ManifestDeepLinksRule.scan(ManifestContext(manifest(true))).single { it.title.contains("MainActivity") }
        assertEquals(Severity.INFO, ok.severity)
        assertFalse(ok.detail.contains("No android:autoVerify"))
    }

    @Test fun launchModesFromTheBinaryManifest() {
        assertEquals("standard", DeepLinks.launchMode(null))
        assertEquals("singleTop", DeepLinks.launchMode("1"))
        assertEquals("singleInstance", DeepLinks.launchMode("3"))
        assertEquals("singleTask", DeepLinks.launchMode("singleTask"))
    }

    private val handler = """
        .class public Lcom/example/wallet/MainActivity;
        .super Landroid/app/Activity;
        .method public onNewIntent(Landroid/content/Intent;)V
            .locals 4
            invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
            move-result-object v0
            const-string v1, "amount"
            invoke-virtual {v0, v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v2
            const-string v1, "to"
            invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v2
            const-string v3, "unused"
            invoke-virtual {p0}, Lcom/example/wallet/MainActivity;->key()Ljava/lang/String;
            move-result-object v3
            invoke-virtual {v0, v3}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
            return-void
        .end method
    """.trimIndent()

    @Test fun theParametersReadAsConstants() {
        val p = DeepLinks.paramsRead(handler)
        assertEquals(setOf("amount"), p["query"])                      // twin: the computed key (overwritten "unused") is not listed
        assertEquals(setOf("to"), p["extra"])
        val md = DeepLinks.section(DeepLinks.parse(manifest(false), "com.example.wallet")) { p }
        assertTrue(md, md.contains("1 web filter(s) without android:autoVerify"))
        assertTrue(md, md.contains("query: amount; extras: to"))
        assertTrue(DeepLinks.brief(DeepLinks.parse(manifest(false), "com.example.wallet")).contains("UNVERIFIED web link https://c.example.link"))
    }
}
