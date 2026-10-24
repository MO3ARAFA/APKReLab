package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** 0.103.2: the SCA inventory of one APK is built locally and published once (a scan of another APK, or a report exported half-way, must not see a half-built or mixed list). */
class LibraryInventoryTest {
    private fun lib(g: String, a: String, v: String, src: String = "pom.properties") = DetectedLib(g, a, v, "x", src)
    private fun keys(l: List<DetectedLib>) = l.map { it.group + ":" + it.artifact + ":" + it.version }

    @Test fun mergeKeepsTheExactVersionAndAddsTheVersionlessRows() {
        val base = listOf(lib("com.squareup.okhttp3", "okhttp", "4.2.2"), lib("org.bouncycastle", "bcprov-jdk18on", "1.78"))
        val extra = listOf(lib("com.squareup.okhttp3", "okhttp", "?", "package path"), lib("com.google.code.gson", "gson", "?", "package path"), lib("org.bouncycastle", "bcprov-jdk15on", "?", "package path"))
        assertEquals(listOf("com.squareup.okhttp3:okhttp:4.2.2", "org.bouncycastle:bcprov-jdk18on:1.78", "com.google.code.gson:gson:?"), keys(LibraryScanner.merge(base, extra)))
        assertEquals(keys(base), keys(LibraryScanner.merge(base, emptyList())))                          // nothing to add: the same list
        assertEquals(1, keys(LibraryScanner.merge(emptyList(), listOf(lib("a", "b", "?"), lib("a", "b", "?")))).size)   // twin: a repeated row is added once
    }

    @Test fun theLocalMergeEqualsTheOldStepByStepMergeOfTheSharedInventory() {
        val exact = listOf(lib("com.squareup.okhttp3", "okhttp", "4.2.2"))
        val probed = listOf(lib("com.google.code.gson", "gson", "2.8.8", "code constant"))
        val path = listOf(lib("com.google.code.gson", "gson", "?", "package path"), lib("com.bumptech.glide", "glide", "?", "package path"))
        val saved = LibraryScanner.inventory
        try {
            LibraryScanner.inventory = exact
            LibraryScanner.mergeInventory(probed); LibraryScanner.mergeInventory(path)
            assertEquals(keys(LibraryScanner.inventory), keys(LibraryScanner.merge(LibraryScanner.merge(exact, probed), path)))
            assertEquals(listOf("com.squareup.okhttp3:okhttp:4.2.2", "com.google.code.gson:gson:2.8.8", "com.bumptech.glide:glide:?"), keys(LibraryScanner.inventory))
        } finally { LibraryScanner.inventory = saved }
    }

    @Test fun scanningLocallyDoesNotTouchTheSharedInventoryAndScanApkPublishesIt() {
        val dir = File.createTempFile("inv", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        val apk = File(dir, "a.apk").also { it.deleteOnExit() }
        ZipOutputStream(apk.outputStream()).use { z -> z.putNextEntry(ZipEntry("META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties")); z.write("groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.2.2\n".toByteArray()); z.closeEntry() }
        val saved = LibraryScanner.inventory
        try {
            val marker = listOf(lib("other", "app", "1.0"))
            LibraryScanner.inventory = marker
            val (libs, res) = LibraryScanner.scanApkLocal(apk)
            assertEquals(listOf("com.squareup.okhttp3:okhttp:4.2.2"), keys(libs)); assertTrue(res.stats.contains("libraries 1"))
            assertEquals(keys(marker), keys(LibraryScanner.inventory))                                      // another APK's list is untouched by a local scan
            LibraryScanner.scanApk(apk)
            assertEquals(listOf("com.squareup.okhttp3:okhttp:4.2.2"), keys(LibraryScanner.inventory))       // the published scan replaces it
        } finally { LibraryScanner.inventory = saved }
    }
}
