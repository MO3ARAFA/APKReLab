package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 0.99.0: split APKs (the native libraries of a Play Store app live in split_config.<abi>.apk) and Flutter's libapp.so. */
class SplitApksTest {
    private fun zip(name: String, entries: Map<String, ByteArray>): File {
        val dir = File.createTempFile("splits", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        val f = File(dir, name); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return f
    }
    private val manifest = "<manifest package=\"com.x\"><uses-sdk android:minSdkVersion=\"24\" android:targetSdkVersion=\"35\"/></manifest>"
    private fun scan(base: File): List<SecurityScanner.Finding> = ZipFile(base).use { NativeScanner.scan(it, manifest) }

    private fun guarded(body: () -> Unit) { try { body() } finally { NativeScanner.extraArchives = emptyList() } }   // the splits are a global of the scanner: never leak them into another test

    @Test fun theLibrariesOfASplitAreScannedAsIfTheyWereInTheBase(): Unit = guarded {
        val base = zip("base.apk", mapOf("classes.dex" to ByteArray(8), "AndroidManifest.xml" to ByteArray(8)))
        val split = zip("split_config.arm64_v8a.apk", mapOf("AndroidManifest.xml" to ByteArray(8), "lib/arm64-v8a/libpayments.so" to ElfTestBuilder.build(stackExec = true)))
        assertTrue(scan(base).isEmpty())                                                                  // the base alone: nothing to read
        NativeScanner.extraArchives = listOf(split)
        val f = scan(base)
        val hardening = f.filter { it.ruleId == "native-hardening" }
        assertEquals(1, hardening.size); assertEquals(SecurityScanner.Severity.MEDIUM, hardening[0].severity); assertTrue(hardening[0].detail.contains("libpayments.so"))
        assertTrue(f.first { it.ruleId == "native-coverage" }.detail.contains("came from split archives (split_config.arm64_v8a.apk)"))
        NativeScanner.extraArchives = emptyList()
        assertTrue(scan(base).isEmpty())                                                                  // twin: the splits are not remembered once cleared
    }

    @Test fun oneAbiPerLibraryAcrossTheBaseAndTheSplits(): Unit = guarded {
        val base = zip("base.apk", mapOf("lib/armeabi-v7a/libnative-lib.so" to ElfTestBuilder.build(is64 = false, textrel = true)))
        val split = zip("split_config.arm64_v8a.apk", mapOf("lib/arm64-v8a/libnative-lib.so" to ElfTestBuilder.build()))
        NativeScanner.extraArchives = listOf(split)
        val f = scan(base)
        assertTrue(f.none { it.ruleId == "native-hardening" })                                           // the arm64 copy wins: the 32-bit text relocations are not reported
        assertTrue(f.first { it.ruleId == "native-coverage" }.title.contains("1 ELF"))
    }

    @Test fun flutterAppSnapshotEndpointsAreListedAndCleartextOnesFlagged(): Unit = guarded {
        val app = ElfTestBuilder.build(rodata = listOf("https://api.pay-example.net/v1/login", "http://legacy.pay-example.net/health", "https://dart.dev/guides", "see https://github.com/x/y for details"))
        val base = zip("base.apk", mapOf("classes.dex" to ByteArray(8)))
        NativeScanner.extraArchives = listOf(zip("split_config.arm64_v8a.apk", mapOf("lib/arm64-v8a/libapp.so" to app, "lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build())))
        val f = scan(base)
        val info = f.single { it.ruleId == "native-flutter" }
        assertTrue(info.detail, info.detail.contains("api.pay-example.net") && info.detail.contains("legacy.pay-example.net"))
        assertFalse(info.detail.contains("dart.dev")); assertFalse(info.detail.contains("github.com"))      // package noise is dropped
        assertTrue(info.detail.contains("split_config.arm64_v8a.apk"))
        val clear = f.single { it.ruleId == "native-flutter-cleartext" }
        assertTrue(clear.detail.contains("legacy.pay-example.net")); assertFalse(clear.detail.contains("api.pay-example.net"))
        // twin: https only -> no cleartext card; no libapp.so -> no Flutter card
        NativeScanner.extraArchives = listOf(zip("split_config.arm64_v8a.apk", mapOf("lib/arm64-v8a/libapp.so" to ElfTestBuilder.build(rodata = listOf("https://api.pay-example.net/v1/login")))))
        assertTrue(scan(base).none { it.ruleId == "native-flutter-cleartext" })
        NativeScanner.extraArchives = listOf(zip("split_config.arm64_v8a.apk", mapOf("lib/arm64-v8a/libother.so" to ElfTestBuilder.build())))
        assertTrue(scan(base).none { it.ruleId == "native-flutter" })
    }

    @Test fun aBundleIsRecognisedAndItsApksExtractedWithSafeNames() {
        val apk = zip("a.apk", mapOf("classes.dex" to ByteArray(4), "AndroidManifest.xml" to ByteArray(4)))
        val bundle = zip("app.apks", mapOf("base-master.apk" to apk.readBytes(), "splits/split_config.arm64_v8a.apk" to ByteArray(10), "../../evil.apk" to ByteArray(3), "toc.pb" to ByteArray(2)))
        assertTrue(SplitApks.isBundle(bundle)); assertFalse(SplitApks.isBundle(apk))                        // twin: a real APK has a manifest and a DEX
        val dir = File(bundle.parentFile, "out")
        val files = SplitApks.extractApks(bundle, dir)
        assertEquals(3, files.size); assertTrue(files.all { it.parentFile == dir })                          // flat: nothing escaped through "../"
        assertTrue(files.any { it.name == "split_config.arm64_v8a.apk" })
    }

    @Test fun theBaseIsTheFileThatIsNotASplit() {
        val dir = File.createTempFile("pp1", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }
        fun mk(name: String, entries: Map<String, ByteArray>) = File(dir, name).also { f -> ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } } }
        val base = mk("base.apk", mapOf("classes.dex" to ByteArray(2000), "AndroidManifest.xml" to ByteArray(9000)))
        val byName = mk("split_config.xxhdpi.apk", mapOf("resources.arsc" to ByteArray(10)))
        val byShape = mk("arm64.apk", mapOf("AndroidManifest.xml" to ByteArray(300), "lib/arm64-v8a/libapp.so" to ByteArray(10)))     // no DEX, tiny manifest, libraries: a config split whatever its name
        val (b, splits) = SplitApks.partition(listOf(byName, byShape, base))
        assertEquals("base.apk", b!!.name); assertEquals(setOf("split_config.xxhdpi.apk", "arm64.apk"), splits.map { it.name }.toSet())
        assertFalse(SplitApks.isSplit(base))
        assertNotNull(SplitApks.partition(listOf(base)).first)
    }

    // ---- 0.102.0: the "Installed apps" picker copies sourceDir + splitSourceDirs into workspaces/p1 ----
    private fun tmp() = File.createTempFile("inst", "").also { it.delete(); it.mkdirs(); it.deleteOnExit() }

    @Test fun anInstalledAppIsCopiedAsOriginalApkPlusSplits(): Unit = guarded {
        val src = tmp()
        val base = zip("base.apk", mapOf("classes.dex" to ByteArray(8), "AndroidManifest.xml" to ByteArray(8)))
        val arm = zip("split_config.arm64_v8a.apk", mapOf("AndroidManifest.xml" to ByteArray(8), "lib/arm64-v8a/libapp.so" to ElfTestBuilder.build(stackExec = true)))
        val ws = File(tmp(), "workspaces/p1"); ws.mkdirs(); File(ws, "stale.txt").writeText("old project")
        val r = SplitApks.copyInstalled(base.path, listOf(arm.path), ws)
        assertEquals("original.apk", r.original.name); assertTrue(r.original.readBytes().contentEquals(base.readBytes()))
        assertEquals(listOf("split_config.arm64_v8a.apk"), r.splits.map { it.name }); assertEquals(File(ws, "splits"), r.splits[0].parentFile)
        assertFalse(File(ws, "stale.txt").exists())                                                        // the previous project is gone
        // the result is what analyzeFile reads: the native scanner finds the library of the split through the copied folder
        NativeScanner.extraArchives = File(ws, "splits").listFiles()!!.filter { it.name.endsWith(".apk") }
        val f = ZipFile(r.original).use { NativeScanner.scan(it, manifest) }
        assertTrue(f.any { it.ruleId == "native-hardening" && it.detail.contains("libapp.so") })
        assertTrue(src.exists())
    }

    @Test fun anInstalledAppWithoutSplitsOrWithAnUnreadableSplitStillWorks() {
        val base = zip("base.apk", mapOf("classes.dex" to ByteArray(8), "AndroidManifest.xml" to ByteArray(8)))
        val ws = File(tmp(), "p1")
        val none = SplitApks.copyInstalled(base.path, null, ws)                                            // twin of the first test: a plain app, splitSourceDirs == null
        assertTrue(none.splits.isEmpty()); assertTrue(none.skipped.isEmpty()); assertTrue(none.original.exists())
        val bad = SplitApks.copyInstalled(base.path, listOf(File(tmp(), "gone.apk").path), ws)
        assertTrue(bad.splits.isEmpty()); assertEquals(listOf("gone.apk"), bad.skipped); assertTrue(bad.original.exists())   // skipped and reported, not fatal
    }

    @Test fun twoSplitsWithTheSameFileNameKeepBothCopies() {
        val a = zip("split_config.en.apk", mapOf("resources.arsc" to ByteArray(3))); val b = zip("split_config.en.apk", mapOf("resources.arsc" to ByteArray(5)))
        val base = zip("base.apk", mapOf("classes.dex" to ByteArray(8)))
        val r = SplitApks.copyInstalled(base.path, listOf(a.path, b.path), File(tmp(), "p1"))
        assertEquals(2, r.splits.size); assertEquals(2, r.splits.map { it.name.lowercase() }.toSet().size)
    }
}
