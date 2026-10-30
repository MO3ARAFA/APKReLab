package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 0.104.1: the agent's search_assets tool (assets/ text files and a Hermes string table). */
class AssetSearchTest {
    private fun apk(entries: Map<String, ByteArray>): ZipFile {
        val dir = File.createTempFile("asearch", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        val f = File(dir, "a.apk"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }

    /** A minimal valid Hermes v96 file holding [strings] (ASCII), the layout of HermesStringsTest. */
    private fun hbc(strings: List<String>): ByteArray {
        val storage = strings.joinToString("").toByteArray(Charsets.ISO_8859_1)
        val smallAt = 132; val storageAt = smallAt + 4 * strings.size; val total = storageAt + storage.size + 20
        val bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        bb.put(byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F)); bb.putInt(96)
        bb.position(32); bb.putInt(total); bb.putInt(0); bb.putInt(0); bb.putInt(1); bb.putInt(0); bb.putInt(strings.size); bb.putInt(0); bb.putInt(storage.size)
        bb.position(smallAt); var off = 0
        for (s in strings) { bb.putInt((off shl 1) or (s.length shl 24)); off += s.length }
        bb.position(storageAt); bb.put(storage)
        return bb.array()
    }

    @Test fun findsTextInWebAssetsConfigsAndAHermesStringTableWithFileAndLine() {
        val z = apk(mapOf(
            "assets/www/js/app.js" to "var a = 1;\nfetch('https://api.shop-pay.net/v2/transfer', {method:'POST'});\n".toByteArray(),
            "assets/config.properties" to "endpoint=https://api.shop-pay.net/v1\n".toByteArray(),
            "assets/index.android.bundle" to hbc(listOf("createElement", "https://api.shop-pay.net/graphql", "Bearer ")),
            "assets/LICENSE.txt" to "see https://api.shop-pay.net/license".toByteArray(),        // licence files are skipped, as in the scan
            "assets/logo.png" to "api.shop-pay.net".toByteArray()))                               // not a text asset
        val r = AssetScanner.search(z, "API.SHOP-PAY.NET", 25)                                      // case-insensitive
        assertTrue(r, r.contains("assets/www/js/app.js:2:")); assertTrue(r.contains("assets/config.properties:1:"))
        assertTrue(r.contains("assets/index.android.bundle [Hermes string #1]: https://api.shop-pay.net/graphql")); assertTrue(r.contains("1 Hermes string table"))
        assertFalse(r.contains("LICENSE")); assertFalse(r.contains("logo.png"))
        assertTrue(r.startsWith("search_assets \"API.SHOP-PAY.NET\": 3 hit(s)"))
    }

    @Test fun limitsAndNothingFound() {
        val many = (1..20).joinToString("\n") { "token$it = abc" }
        val z = apk(mapOf("assets/a.env" to many.toByteArray(), "assets/b.env" to many.toByteArray()))
        val r = AssetScanner.search(z, "token", 7)
        assertEquals(7, r.lines().size - 1); assertTrue(r.contains("stopped at 7"))
        assertEquals(5, r.lines().count { it.startsWith("assets/a.env") })                          // at most 5 hits per file
        assertTrue(AssetScanner.search(z, "nowhere-to-be-found", 10).contains("Nothing under assets/"))
        assertTrue(AssetScanner.search(z, "ab", 10).startsWith("error:"))                            // too short a query
        assertTrue(AssetScanner.search(z, "token3", 10).contains("assets/a.env:3:"))                 // the line number of a later line
    }

    @Test fun theToolIsRegisteredReadOnly() {
        val t = Tools.all.first { it.name == "search_assets" }
        assertFalse(t.asks); assertTrue(Tools.systemPrompt(false, "").contains("search_assets"))
    }
}
