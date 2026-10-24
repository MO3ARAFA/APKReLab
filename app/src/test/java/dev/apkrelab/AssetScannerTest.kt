package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 0.103.0: the assets/ folder (React Native bundles, web apps, configs). Every positive has a negative twin. */
class AssetScannerTest {
    private val token = "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"
    private fun load() { SecretFormats.load(listOf(File("src/main/assets/secret_formats.json"), File("app/src/main/assets/secret_formats.json")).first { it.exists() }.readText()) }
    private fun apk(entries: Map<String, ByteArray>): ZipFile {
        val dir = File.createTempFile("assets", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        val f = File(dir, "a.apk"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }
    private fun scan(entries: Map<String, String>): List<SecurityScanner.Finding> { load(); return AssetScanner.scan(apk(entries.mapValues { it.value.toByteArray() })).findings }
    private fun ids(f: List<SecurityScanner.Finding>) = f.map { it.ruleId }

    @Test fun aTokenInAReactNativeBundleOrAnEnvFileIsHighAndPlaceholdersAreNot() {
        val f = scan(mapOf("assets/index.android.bundle" to "var a=1;__d(function(){var cfg={stripe:\"$token\"}});", "assets/flutter_assets/.env" to "STRIPE_KEY=$token\n"))
        assertEquals(2, f.count { it.ruleId == "assets-secrets" }); assertTrue(f.all { it.severity != SecurityScanner.Severity.INFO || it.ruleId == "assets-coverage" })
        assertFalse(f.any { it.detail.contains("OuEMLAlTW") })                                              // the value is never printed in full
        val fake = token.dropLast(7) + "example"                                                          // matches the format, but is a placeholder: only the filter keeps it out
        assertTrue(SecretFormats.scan(fake).isNotEmpty() && SecretFormats.looksLikePlaceholder(fake))
        assertTrue(scan(mapOf("assets/index.android.bundle" to "var s=\"$fake\";")).none { it.ruleId == "assets-secrets" })
        // twins: a placeholder, an ordinary sentence, and a media file that happens to contain the bytes
        assertTrue(scan(mapOf("assets/index.android.bundle" to "var s=\"sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\"; var t=\"a perfectly ordinary sentence in a string\";")).none { it.ruleId == "assets-secrets" })
        assertTrue(scan(mapOf("assets/logo.png" to "\"$token\"")).none { it.ruleId == "assets-secrets" })     // not a text extension: skipped
        assertTrue(scan(mapOf("assets/LICENSE.txt" to "key=\"$token\"")).none { it.ruleId == "assets-secrets" })  // licence files are skipped
    }

    @Test fun aPrivateKeyAndFirebaseAndCleartextHosts() {
        val body = "A".repeat(64)
        val f = scan(mapOf("assets/cert.pem" to "-----BEGIN PRIVATE KEY-----\n$body\n-----END PRIVATE KEY-----",
            "assets/www/app.js" to "var db=\"https://shop-prod-1a2b3.firebaseio.com\"; var api=\"http://api.shop-pay.net/v1/pay\"; var bare=\"http://www.shop-pay.net\"; // see http://docs.shop-pay.net/guide/x\n var d=\"http://www.w3.org/1999/xhtml\"; var l=\"http://192.168.1.5/x\";"))
        assertTrue("assets-private-key" in ids(f)); assertTrue("assets-firebase-db" in ids(f))
        val clear = f.first { it.ruleId == "assets-cleartext-url" }
        assertTrue(clear.detail.contains("api.shop-pay.net")); assertFalse(clear.detail.contains("w3.org")); assertFalse(clear.detail.contains("192.168"))
        assertFalse(clear.detail.contains("www.shop-pay.net")); assertFalse(clear.detail.contains("docs.shop-pay.net"))   // a bare host and a URL inside a code comment are not endpoints   // schema and private hosts are left out
        // twins: a placeholder Firebase project, an https host, a PEM header without a body
        val g = scan(mapOf("assets/a.json" to "{\"u\":\"https://your-project.firebaseio.com\",\"v\":\"https://api.shop-pay.net/v1\",\"k\":\"-----BEGIN PRIVATE KEY-----\"}"))
        assertTrue(g.none { it.ruleId in setOf("assets-firebase-db", "assets-cleartext-url", "assets-private-key") })
        // twins: the same endpoint in an HTML page or a text file is a link / documentation, not a connection
        assertTrue(scan(mapOf("assets/page.html" to "<a href=\"http://api.shop-pay.net/v1/pay\">x</a>", "assets/readme.txt" to "\"http://api.shop-pay.net/v1/pay\"")).none { it.ruleId == "assets-cleartext-url" })
        assertTrue(scan(mapOf("assets/lang.js" to "/**\n * <a href=\"http://docs.shop-pay.net/Reference\">ref</a>\n */\n// var u = \"http://old.shop-pay.net/v1/x\";\nvar ok = 1;")).none { it.ruleId == "assets-cleartext-url" })   // links in comments
        assertTrue(scan(mapOf("assets/lang.js" to "// key\nvar t = \"$token\";")).any { it.ruleId == "assets-secrets" })
        assertTrue(scan(mapOf("assets/app.properties" to "base=http://api.shop-pay.net/v1/pay")).any { it.ruleId == "assets-cleartext-url" })
    }

    @Test fun hermesBytecodeIsReportedAsNotScannedAndNeverReadAsText() {
        val hbc = byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F, 96, 0, 0, 0) + "\"$token\"".toByteArray()
        load()
        val f = AssetScanner.scan(apk(mapOf("assets/index.android.bundle" to hbc))).findings
        assertEquals(listOf("assets-hermes"), ids(f).filter { it.startsWith("assets-h") }); assertTrue(f.first { it.ruleId == "assets-hermes" }.title.contains("NOT scanned"))
        assertTrue(f.none { it.ruleId == "assets-secrets" })
        assertEquals(96, AssetScanner.hermesVersion(hbc)); assertNull(AssetScanner.hermesVersion("var a = 1; // plain js bundle".toByteArray()))     // twin
    }

    @Test fun cordovaWildcardsAreReportedAndSpecificOriginsAreNot() {
        val bad = scan(mapOf("assets/www/config.xml" to "<widget><access origin=\"*\" /><allow-navigation href=\"*\" /></widget>", "assets/www/cordova.js" to "// cordova"))
        assertTrue("assets-cordova-access-wildcard" in ids(bad)); assertTrue("assets-cordova-navigation-wildcard" in ids(bad)); assertTrue("assets-coverage" in ids(bad))
        val ok = scan(mapOf("assets/www/config.xml" to "<widget><access origin=\"https://api.shop-pay.net\" /><allow-navigation href=\"https://*.shop-pay.net/*\" /></widget>"))
        assertTrue(ok.none { it.ruleId.startsWith("assets-cordova") })                                      // twin
    }

    @Test fun capsAndAnApkWithoutAssets() {
        assertTrue(scan(mapOf("classes.dex" to "x")).isEmpty())                                             // nothing under assets/: no card, no coverage line
        val big = "var x=\"$token\";" + " ".repeat(3_100_000)
        assertTrue(scan(mapOf("assets/big.js" to big)).none { it.ruleId == "assets-secrets" })              // over the size cap: skipped, not half-read
    }
}
