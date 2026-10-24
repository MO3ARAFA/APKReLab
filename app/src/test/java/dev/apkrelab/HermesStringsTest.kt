package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Random
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * 0.104.0: the string table of a Hermes bytecode file. The builder below writes a file by the layout of Hermes' own BytecodeFileFormat.h (version 96: 128-byte header, function headers,
 * string kinds, identifier hashes, small string table, overflow table, string storage, 20-byte footer). The reader was also run on three real bundles (React Native apps from F-Droid):
 * all three parsed, 7,406 / 23,517 / 23,964 strings, over 99.9% printable.
 */
class HermesStringsTest {
    private val token = "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"

    /** (text, stored as UTF-16). Functions are not needed for the string table, so the function table is empty. */
    private fun hbc(strings: List<Pair<String, Boolean>>, version: Int = 96, fileLengthDelta: Int = 0, storageExtra: Int = 0, tail: Int = 0): ByteArray {
        val storage = java.io.ByteArrayOutputStream()
        class E(val utf16: Boolean, val off: Int, val len: Int)
        val es = strings.map { (s, u) -> val b = if (u) s.toByteArray(Charsets.UTF_16LE) else s.toByteArray(Charsets.ISO_8859_1); val e = E(u, storage.size(), s.length); storage.write(b); e }
        val overflow = es.filter { it.len >= 255 }
        fun al(x: Int) = (x + 3) and 3.inv()
        var off = al(128); off = al(off + 4)                       // no functions; one string-kind entry
        val smallAt = off; off = al(off + 4 * es.size)
        val overflowAt = off; off = al(off + 8 * overflow.size)
        val storageAt = off; val total = storageAt + storage.size() + storageExtra + tail + 20     // tail = the function bytecode that follows the strings
        val bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        bb.put(byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F)); bb.putInt(version)
        bb.position(32); bb.putInt(total + fileLengthDelta); bb.putInt(0); bb.putInt(0)          // fileLength, globalCodeIndex, functionCount
        bb.putInt(1); bb.putInt(0); bb.putInt(es.size); bb.putInt(overflow.size); bb.putInt(storage.size() + storageExtra)   // kinds, identifiers, strings, overflow, storage
        bb.position(smallAt)
        var oi = 0
        for (e in es) {
            val big = e.len >= 255
            val word = (if (e.utf16) 1 else 0) or ((if (big) oi else e.off) shl 1) or ((if (big) 255 else e.len) shl 24)
            bb.putInt(word)
            if (big) oi++
        }
        bb.position(overflowAt)
        for (e in overflow) { bb.putInt(e.off); bb.putInt(e.len) }
        bb.position(storageAt); bb.put(storage.toByteArray())
        return bb.array()
    }

    @Test fun asciiUtf16AndOverflowStringsAreReadInOrder() {
        val long = "x".repeat(300) + "END"
        val file = hbc(listOf("alpha" to false, "Привет мир" to true, long to false, "http://api.shop-pay.net/v1/pay" to false, "" to false))
        val r = HermesStrings.read(file)!!
        assertEquals(96, r.version); assertEquals(5, r.total)
        assertEquals(listOf("alpha", "Привет мир", long.take(2000), "http://api.shop-pay.net/v1/pay", ""), r.strings)
        assertEquals(96, HermesStrings.version(file)); assertNull(HermesStrings.version("var a = 1; // plain js".toByteArray()))
        assertEquals(2, HermesStrings.read(file, max = 2)!!.strings.size)                                  // the cap
        assertEquals(10, HermesStrings.read(hbc(listOf(("y".repeat(40)) to false)), maxLen = 10)!!.strings[0].length)   // a long string is cut
    }

    @Test fun anythingNotSelfConsistentIsRefusedAndNothingThrows() {
        val good = hbc(listOf("alpha" to false, "beta" to false))
        assertTrue(HermesStrings.read(good) != null)
        assertNull(HermesStrings.read(hbc(listOf("alpha" to false), version = 94)))                         // a layout this reader does not know
        assertNull(HermesStrings.read(hbc(listOf("alpha" to false), fileLengthDelta = 4)))                  // the header's length is not the file's
        assertNull(HermesStrings.read(good.copyOf(good.size - 30)))                                          // truncated
        val bigStorage = good.copyOf(); ByteBuffer.wrap(bigStorage).order(ByteOrder.LITTLE_ENDIAN).putInt(60, 1 shl 20)
        assertNull(HermesStrings.read(bigStorage))                                                          // the header's storage size runs past the end of the file
        val manyStrings = good.copyOf(); ByteBuffer.wrap(manyStrings).order(ByteOrder.LITTLE_ENDIAN).putInt(52, 100000)
        assertNull(HermesStrings.read(manyStrings))                                                         // more strings than the file can hold
        val badEntry = good.copyOf(); ByteBuffer.wrap(badEntry).order(ByteOrder.LITTLE_ENDIAN).putInt(132, (200 shl 24) or (7 shl 1))   // length 200 at offset 7: past the storage
        assertNull(HermesStrings.read(badEntry))
        assertNull(HermesStrings.read(ByteArray(0))); assertNull(HermesStrings.read(ByteArray(300)))
        val rnd = Random(104)                                                                                // 3,000 corrupted copies: refused or read, never an exception
        repeat(3000) {
            val m = good.copyOf(); repeat(1 + rnd.nextInt(4)) { m[rnd.nextInt(m.size)] = rnd.nextInt(256).toByte() }
            val r = HermesStrings.read(m)
            if (r != null) assertTrue(r.strings.size <= r.total)
        }
    }

    // ---------------- through the asset scanner ----------------
    private fun apk(entries: Map<String, ByteArray>): ZipFile {
        val dir = File.createTempFile("hbc", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        val f = File(dir, "a.apk"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }
    private fun scan(file: ByteArray): List<SecurityScanner.Finding> {
        SecretFormats.load(listOf(File("src/main/assets/secret_formats.json"), File("app/src/main/assets/secret_formats.json")).first { it.exists() }.readText())
        return AssetScanner.scan(apk(mapOf("assets/index.android.bundle" to file))).findings
    }

    @Test fun aSecretAnEndpointAndAFirebaseUrlInTheStringTableAreFoundAndTheCardSaysWhatWasNotRead() {
        val f = scan(hbc(listOf(token to false, "http://api.shop-pay.net/v1/pay" to false, "https://shop-prod-1a2b3.firebaseio.com" to false, "createElement" to false)))
        assertEquals(1, f.count { it.ruleId == "assets-secrets" }); assertFalse(f.any { it.detail.contains("OuEMLAlTW") })
        assertTrue(f.any { it.ruleId == "assets-cleartext-url" && it.detail.contains("api.shop-pay.net") }); assertTrue(f.any { it.ruleId == "assets-firebase-db" })
        val card = f.first { it.ruleId == "assets-hermes" }
        assertTrue(card.title.contains("string table was scanned")); assertTrue(card.detail.contains("NOT analysed"))
    }

    @Test fun placeholdersNoiseAndUnreadableFilesGiveNothing() {
        val fake = token.dropLast(7) + "example"
        val clean = scan(hbc(listOf(fake to false, "http://www.w3.org/2000/svg" to false, "https://your-project.firebaseio.com" to false, "http://localhost" to false, "createElement" to false)))
        assertTrue(clean.none { it.ruleId in setOf("assets-secrets", "assets-cleartext-url", "assets-firebase-db") })      // twin of the positive test
        val old = scan(hbc(listOf(token to false), version = 94))                                               // a layout this reader does not know: said, not guessed
        assertTrue(old.none { it.ruleId == "assets-secrets" }); assertTrue(old.first { it.ruleId == "assets-hermes" }.let { it.title.contains("NOT scanned") && it.detail.contains("version 94") })
        val broken = scan(hbc(listOf(token to false), fileLengthDelta = 8))
        assertTrue(broken.none { it.ruleId == "assets-secrets" }); assertTrue(broken.first { it.ruleId == "assets-hermes" }.detail.contains("not self-consistent"))
    }

    // 0.104.1: a production bundle is often over the 10 MB cap; its strings come before the function bytecode, so only that prefix is read
    @Test fun aHermesBundleOverTheSizeCapIsReadUpToItsStringStorage() {
        val big = hbc(listOf("createElement" to false, token to false), tail = 10_500_000)
        val need = HermesStrings.prefixNeeded(big.copyOf(128), big.size.toLong())!!
        assertTrue(need < 1000)                                                                             // the strings end a few hundred bytes into a 10.5 MB file
        assertEquals(listOf("createElement", token), HermesStrings.read(big.copyOf(need.toInt()), big.size.toLong())!!.strings)
        assertNull(HermesStrings.read(big.copyOf(need.toInt() - 1), big.size.toLong()))                    // one byte short of the storage: refused
        assertNull(HermesStrings.prefixNeeded(big.copyOf(128), big.size.toLong() + 1))                      // the header's length must be the entry's
        val f = scan(big)
        assertEquals(1, f.count { it.ruleId == "assets-secrets" }); assertTrue(f.first { it.ruleId == "assets-hermes" }.title.contains("string table was scanned"))
        // twin: a PLAIN text bundle over the cap is still skipped (it would have to be read whole)
        val plain = ("var t=\"$token\";" + " ".repeat(10_500_000)).toByteArray()
        assertTrue(scan(plain).none { it.ruleId == "assets-secrets" || it.ruleId == "assets-hermes" })
    }
}
