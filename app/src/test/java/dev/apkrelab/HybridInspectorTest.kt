package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 2.0.0 pillar 3a: the Flutter payload inventory (strings and files only), its report section, and the native-app twin. */
class HybridInspectorTest {

    private fun loadFormats() { SecretFormats.load(listOf(File("src/main/assets/secret_formats.json"), File("app/src/main/assets/secret_formats.json")).first { it.exists() }.readText()) }

    private fun zip(entries: Map<String, ByteArray>): ZipFile {
        val f = File.createTempFile("hybrid", ".apk"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }

    private val token = "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"
    private val libApp = ElfTestBuilder.build(rodata = listOf(
        "https://api.example-pay.net/v2/login", "https://api.example-pay.net/v2/transfer?id=1", "https://cdn.example-pay.net/img",
        "https://dart.dev/guides/libraries", token))
    private val env = "API_BASE=https://gateway.example-pay.net/api\nAUTH_URL=https://auth.example-pay.net/oauth/token\nDEBUG=false\n".toByteArray()

    private fun flutter(extra: Map<String, ByteArray> = emptyMap()) = zip(mapOf(
        "classes.dex" to ByteArray(8),
        "lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build(),
        "lib/arm64-v8a/libapp.so" to libApp,
        "assets/flutter_assets/.env" to env,
        "assets/flutter_assets/AssetManifest.json" to "{\"assets/logo.png\":[\"assets/logo.png\"]}".toByteArray(),
        "assets/flutter_assets/assets/logo.png" to ByteArray(16)) + extra)

    @Test fun aFlutterApkIsDetected() {
        assertEquals(HybridInspector.HybridKind.FLUTTER, HybridInspector.inspect(flutter(), emptyList()).kind)
    }

    @Test fun fiveEndpointsThreeFromTheSnapshotTwoFromTheEnvFile() {
        loadFormats()
        val r = HybridInspector.inspect(flutter(), emptyList())
        assertEquals(r.endpoints.toString(), 5, r.endpoints.size)
        assertTrue(r.endpoints.contains("https://api.example-pay.net/v2/transfer"))                   // the query is dropped
        assertTrue(r.endpoints.contains("https://gateway.example-pay.net/api") && r.endpoints.contains("https://auth.example-pay.net/oauth/token"))
        assertFalse("package / documentation hosts are noise", r.hosts.contains("dart.dev"))
        assertEquals(setOf("api.example-pay.net", "cdn.example-pay.net", "gateway.example-pay.net", "auth.example-pay.net"), r.hosts.toSet())
    }

    @Test fun oneSecretCountedItsValueNeverKeptOrPrinted() {
        loadFormats()
        val r = HybridInspector.inspect(flutter(), emptyList())
        assertEquals(1, r.secretCount)
        assertEquals(listOf("lib/arm64-v8a/libapp.so"), r.secretWhere)
        val md = HybridInspector.markdown(r); val html = HybridInspector.html(r)
        assertFalse(md.contains(token)); assertFalse(html.contains(token)); assertFalse(md.contains(token.take(12)))
        // twin: a placeholder that MATCHES the format (only the placeholder filter keeps it out) is not counted
        assertTrue(SecretFormats.scan(token.dropLast(7) + "example").isNotEmpty())
        val ph = HybridInspector.inspect(flutter(mapOf("lib/arm64-v8a/libapp.so" to ElfTestBuilder.build(rodata = listOf(token.dropLast(7) + "example"))) ), emptyList())
        assertEquals(0, ph.secretCount)
    }

    @Test fun theEnvFileIsListedAndAnAssetIsNot() {
        val r = HybridInspector.inspect(flutter(mapOf("assets/flutter_assets/config.prod.yaml" to "url: https://x.example-pay.net\n".toByteArray(),
            "assets/flutter_assets/app.yaml" to "a: 1\n".toByteArray(), "assets/flutter_assets/secrets.json" to "{}".toByteArray())), emptyList())
        assertEquals(listOf("assets/flutter_assets/.env", "assets/flutter_assets/app.yaml", "assets/flutter_assets/config.prod.yaml", "assets/flutter_assets/secrets.json"), r.configFiles)
        assertFalse(r.configFiles.any { it.endsWith("AssetManifest.json") || it.endsWith("logo.png") })
    }

    @Test fun theReportSectionListsHostsConfigAndCount() {
        loadFormats()
        val md = HybridInspector.markdown(HybridInspector.inspect(flutter(), emptyList()))
        assertTrue(md, md.startsWith("## Hybrid framework analysis"))
        assertTrue(md.contains("The Dart code itself is not analysed"))
        assertTrue(md.contains("Endpoints: 5 URL(s) on 4 host(s): api.example-pay.net"))
        assertTrue(md.contains("`assets/flutter_assets/.env`"))
        assertTrue(md.contains("Strings in a known credential format: 1"))
        assertTrue(HybridInspector.html(HybridInspector.inspect(flutter(), emptyList())).contains("<details><summary>Every host and endpoint</summary>"))
    }

    @Test fun theHostLineStopsAtTwenty() {
        val many = (1..25).map { "https://h$it.example-pay.net/x" }
        val r = HybridInspector.inspect(flutter(mapOf("lib/arm64-v8a/libapp.so" to ElfTestBuilder.build(rodata = many))), emptyList())
        val md = HybridInspector.markdown(r)
        assertTrue(md.contains("h20.example-pay.net, … (7 more in the HTML report)"))                 // 25 + the 2 env hosts = 27 hosts, 20 printed
        assertFalse(md.substringBefore("more in the HTML").contains("h21.example-pay.net"))
    }

    @Test fun oneAbiIsReadTheOthersCounted() {
        val v7 = mapOf("lib/armeabi-v7a/libapp.so" to ElfTestBuilder.build(is64 = false, rodata = listOf("https://other-abi.example-pay.net/x")),
            "lib/armeabi-v7a/libflutter.so" to ElfTestBuilder.build(is64 = false))
        val r = HybridInspector.inspect(zip(v7 + mapOf("lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build(), "lib/arm64-v8a/libapp.so" to libApp,
            "assets/flutter_assets/.env" to env)), emptyList())                                      // the 32-bit copy comes FIRST in the archive
        assertEquals(2, r.libAppCount)
        assertEquals("lib/arm64-v8a/libapp.so", r.libAppRead)
        assertFalse(r.hosts.contains("other-abi.example-pay.net"))
    }

    @Test fun theSnapshotInASplitIsRead() {                                           // Axis Pay ships libapp.so in split_config.arm64_v8a.apk
        val base = zip(mapOf("classes.dex" to ByteArray(8), "assets/flutter_assets/.env" to env))
        val splitFile = File.createTempFile("split_config.arm64_v8a", ".apk").also { it.deleteOnExit() }
        ZipOutputStream(splitFile.outputStream()).use { z ->
            for ((n, b) in mapOf("lib/arm64-v8a/libapp.so" to libApp, "lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build())) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
        }
        assertEquals(HybridInspector.HybridKind.NONE, HybridInspector.inspect(base, emptyList()).kind)             // the base alone has no snapshot
        val r = HybridInspector.inspect(base, listOf(splitFile))
        assertEquals(HybridInspector.HybridKind.FLUTTER, r.kind)
        assertEquals(5, r.endpoints.size)
    }

    // ---- twins: what is NOT a Flutter payload ----
    @Test fun aNativeApkIsNoneAndHasNoSection() {                                    // K-9's shape: dex + native libraries of its own, no Flutter
        val k9 = zip(mapOf("classes.dex" to ByteArray(8), "lib/arm64-v8a/libsqlcipher.so" to ElfTestBuilder.build(), "assets/fonts/x.ttf" to ByteArray(4)))
        val r = HybridInspector.inspect(k9, emptyList())
        assertEquals(HybridInspector.HybridKind.NONE, r.kind)
        assertEquals("", HybridInspector.markdown(r)); assertEquals("", HybridInspector.html(r)); assertEquals("", HybridInspector.summaryLine(r))
    }

    @Test fun eachOfTheThreeMarkersIsRequired() {
        val all = listOf("lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so", "assets/flutter_assets/AssetManifest.json")
        assertEquals(HybridInspector.HybridKind.FLUTTER, HybridInspector.detect(all))
        for (missing in all) assertEquals(missing, HybridInspector.HybridKind.NONE, HybridInspector.detect(all - missing))
    }

    @Test fun theNativeFlutterCardSaysTheSectionListsThePayload() {
        val f = NativeScanner.scan(flutter(), null).single { it.ruleId == "native-flutter" }
        assertTrue(f.detail.startsWith("The Dart code itself is not analysed; the report's Hybrid framework analysis section lists what the payload ships."))
    }

    @Test fun theSameSecretInTwoPlacesIsOneSecretInTwoPlaces() {
        loadFormats()
        val r = HybridInspector.inspect(flutter(mapOf("assets/flutter_assets/.env" to (String(env) + "STRIPE=" + token + "\n").toByteArray())), emptyList())
        assertEquals(1, r.secretCount)
        assertEquals(listOf("lib/arm64-v8a/libapp.so"), r.secretWhere)                    // counted where it was first seen
    }
}
