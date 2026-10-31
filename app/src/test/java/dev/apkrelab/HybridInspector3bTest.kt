package dev.apkrelab

import dev.apkrelab.HybridInspector.HybridKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** 2.0.0 pillar 3b: React Native and Cordova / Capacitor payloads, mixed payloads, audit_brief lines and the Verdict's NOT SEEN clause. */
class HybridInspector3bTest {

    private fun loadFormats() { SecretFormats.load(listOf(File("src/main/assets/secret_formats.json"), File("app/src/main/assets/secret_formats.json")).first { it.exists() }.readText()) }

    private fun zip(entries: Map<String, ByteArray>): ZipFile {
        val f = File.createTempFile("hybrid3b", ".apk"); f.deleteOnExit()
        ZipOutputStream(f.outputStream()).use { z -> for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() } }
        return ZipFile(f)
    }

    private val token = "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"
    private val rnStrings = listOf("https://api.rn-example.org/v1/accounts", "https://media.rn-example.org/avatar", token,
        "https://www.w3.org/2000/svg", "https://github.com/facebook/react-native/issues")    // the last two are in NativeScanner.noiseHosts

    /** A Hermes v96 bundle whose string table holds [strings] (the same layout HermesStringsTest builds; HermesStrings itself is not changed). */
    private fun hbc(strings: List<String>, version: Int = 96): ByteArray {
        val storage = ByteArrayOutputStream()
        val offs = strings.map { s -> val o = storage.size(); storage.write(s.toByteArray(Charsets.ISO_8859_1)); o to s.length }
        fun al(x: Int) = (x + 3) and 3.inv()
        var off = al(128); off = al(off + 4)
        val smallAt = off; off = al(off + 4 * strings.size)
        val storageAt = al(off)
        val total = storageAt + storage.size() + 20
        val bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        bb.put(byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F)); bb.putInt(version)
        bb.position(32); bb.putInt(total); bb.putInt(0); bb.putInt(0)
        bb.putInt(1); bb.putInt(0); bb.putInt(strings.size); bb.putInt(0); bb.putInt(storage.size())
        bb.position(smallAt)
        for ((o, len) in offs) bb.putInt((o shl 1) or (len shl 24))
        bb.position(storageAt); bb.put(storage.toByteArray())
        return bb.array()
    }

    private fun rn(bundle: ByteArray, lib: String = "lib/arm64-v8a/libhermes.so") = zip(mapOf("classes.dex" to ByteArray(8), lib to ElfTestBuilder.build(),
        "assets/index.android.bundle" to bundle))

    // ---------------- React Native ----------------
    @Test fun aHermesBundleGoesThroughHermesStrings() {
        loadFormats()
        val r = HybridInspector.inspect(rn(hbc(rnStrings)), emptyList())
        assertEquals(HybridKind.REACT_NATIVE, r.kind)
        val s = r.section(HybridKind.REACT_NATIVE)!!
        assertEquals(setOf("https://api.rn-example.org/v1/accounts", "https://media.rn-example.org/avatar"), s.endpoints.toSet())   // the two noise hosts are dropped
        assertEquals(1, s.secretCount)
        assertTrue(s.source, s.source.startsWith("index.android.bundle (Hermes bytecode v96, 5 strings read)"))
        val md = HybridInspector.markdown(r)
        assertTrue(md.contains("### React Native") && md.contains("The JavaScript code itself is not analysed"))
        assertFalse(md.contains(token)); assertFalse(HybridInspector.html(r).contains(token))
    }

    @Test fun anUnsupportedHermesVersionIsNamedNotGuessed() {
        val s = HybridInspector.inspect(rn(hbc(rnStrings, version = 95)), emptyList()).section(HybridKind.REACT_NATIVE)!!
        assertEquals(0, s.endpoints.size)
        assertTrue(s.source.contains("string table not read"))
    }

    @Test fun aPlainJsBundleIsReadAsTextIncludingALongMinifiedLine() {
        loadFormats()
        val js = "var a=1;".repeat(400) + "fetch(\"https://api.rn-example.org/v1/accounts\");var k=\"" + token + "\";" + "var b=2;".repeat(400) + "\nimg=\"https://media.rn-example.org/avatar\"\n"
        val s = HybridInspector.inspect(rn(js.toByteArray()), emptyList()).section(HybridKind.REACT_NATIVE)!!
        assertEquals(2, s.endpoints.size)
        assertEquals(1, s.secretCount)                                                   // found inside a 6,400-char line
        assertEquals("index.android.bundle (plain JavaScript, read as text)", s.source)
    }

    @Test fun aSecretAcrossAWindowBoundaryIsFoundThanksToTheOverlap() {
        loadFormats()
        val js = "x".repeat(1750) + "\"" + token + "\"" + "y".repeat(3000) + "\n"           // the value starts 50 chars before the first 1,800-char window ends
        assertEquals(1, HybridInspector.inspect(rn(js.toByteArray()), emptyList()).section(HybridKind.REACT_NATIVE)!!.secretCount)
    }

    @Test fun libreactnativejniIsAMarkerToo() {
        assertEquals(HybridKind.REACT_NATIVE, HybridInspector.inspect(rn(hbc(rnStrings), lib = "lib/arm64-v8a/libreactnativejni.so"), emptyList()).kind)
    }

    @Test fun twinsABundleWithoutTheEngineOrTheEngineWithoutABundleIsNotReactNative() {
        assertEquals(HybridKind.NONE, HybridInspector.inspect(zip(mapOf("assets/index.android.bundle" to hbc(rnStrings))), emptyList()).kind)
        assertEquals(HybridKind.NONE, HybridInspector.inspect(zip(mapOf("lib/arm64-v8a/libhermes.so" to ElfTestBuilder.build())), emptyList()).kind)
    }

    // ---------------- Cordova / Capacitor ----------------
    private val configXmlText = "<?xml version='1.0'?><widget id=\"x\"><access origin=\"https://api.cordova-example.org\" /><allow-navigation href=\"https://pay.cordova-example.org/*\" /></widget>"
    private val capacitor = """{"appId":"x","server":{"hostname":"app.local","androidScheme":"https","cleartext":false,"allowNavigation":["*.cordova-example.org"]}}"""

    private fun cordova(configXml: ByteArray?, capacitorJson: String? = capacitor, root: String = "assets/www/") = zip(LinkedHashMap<String, ByteArray>().apply {
        put("classes.dex", ByteArray(8))
        put(root + "index.html", "<html><script src=\"app.js\"></script></html>".toByteArray())
        put(root + "app.js", ("const key = \"" + token + "\";\nfetch('https://api.cordova-example.org/items');\n").toByteArray())
        if (configXml != null) put("res/xml/config.xml", configXml)
        if (capacitorJson != null) put("assets/capacitor.config.json", capacitorJson.toByteArray())
    })

    @Test fun aCordovaAppListsItsNamedOriginsCapacitorSettingsAndSecrets() {
        loadFormats()
        val r = HybridInspector.inspect(cordova(configXmlText.toByteArray()), emptyList())
        assertEquals(HybridKind.CORDOVA, r.kind)
        val s = r.section(HybridKind.CORDOVA)!!
        assertEquals(listOf("https://api.cordova-example.org", "https://pay.cordova-example.org/*"), s.namedOrigins)
        assertEquals(1, s.secretCount)
        assertEquals(listOf("server.hostname=app.local", "server.androidScheme=https", "server.cleartext=false", "server.allowNavigation=*.cordova-example.org"), s.settings)
        assertEquals("assets/www", s.source)
        val md = HybridInspector.markdown(r)
        assertTrue(md.contains("### Cordova / Capacitor") && md.contains("- Named origins (config.xml): `https://api.cordova-example.org`"))
        assertFalse(md.contains(token))
    }

    @Test fun theCompiledConfigXmlOfARealApkIsDecoded() {                            // in an APK res/xml/config.xml is binary XML
        val bin = AxmlTestBuilder.widget(listOf("access" to ("origin" to "https://api.cordova-example.org"), "allow-navigation" to ("href" to "*")))
        val s = HybridInspector.inspect(cordova(bin, capacitorJson = null), emptyList()).section(HybridKind.CORDOVA)!!
        assertEquals(listOf("https://api.cordova-example.org"), s.namedOrigins)
        assertTrue("the wildcard is noted, not listed", s.wildcardOrigin)
        assertTrue(HybridInspector.markdown(HybridInspector.inspect(cordova(bin, capacitorJson = null), emptyList())).contains("origin \"*\" is present"))
    }

    @Test fun capacitorAloneAndAssetsPublicAreCordovaToo() {
        val s = HybridInspector.inspect(cordova(null, root = "assets/public/"), emptyList()).section(HybridKind.CORDOVA)!!
        assertEquals("assets/public", s.source)
        assertEquals(0, s.namedOrigins.size)
    }

    @Test fun twinsAWebRootWithoutAConfigAndAnotherConfigXmlAreNotCordova() {
        assertEquals(HybridKind.NONE, HybridInspector.inspect(cordova(null, capacitorJson = null), emptyList()).kind)
        assertEquals(HybridKind.NONE, HybridInspector.inspect(zip(mapOf("res/xml/config.xml" to configXmlText.toByteArray(),
            "assets/capacitor.config.json" to capacitor.toByteArray())), emptyList()).kind)                // a config without a web root
        // an app's own res/xml/config.xml that is not Cordova's <widget>: detected by name, but nothing is read from it
        val s = HybridInspector.inspect(cordova("<preferences><access origin=\"https://not-cordova.example\"/></preferences>".toByteArray(), capacitorJson = null), emptyList())
            .section(HybridKind.CORDOVA)!!
        assertEquals(0, s.namedOrigins.size)
    }

    // ---------------- mixed and native ----------------
    private fun mixed() = zip(mapOf("lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build(), "lib/arm64-v8a/libapp.so" to ElfTestBuilder.build(rodata = listOf("https://dart-api.mixed-example.org/x")),
        "assets/flutter_assets/AssetManifest.json" to "{}".toByteArray(), "lib/arm64-v8a/libhermes.so" to ElfTestBuilder.build(), "assets/index.android.bundle" to hbc(rnStrings)))

    @Test fun aMixedPayloadListsBothInOrder() {
        val r = HybridInspector.inspect(mixed(), emptyList())
        assertEquals(listOf(HybridKind.FLUTTER, HybridKind.REACT_NATIVE), r.kinds)
        assertEquals(HybridKind.FLUTTER, r.kind)                                         // 3a callers see the first one
        val md = HybridInspector.markdown(r)
        assertTrue(md.contains("### Flutter") && md.contains("### React Native") && md.contains("The Dart and JavaScript code itself is not analysed"))
        assertTrue(md.indexOf("### Flutter") < md.indexOf("### React Native"))
        val ns = Verdict.build(emptyList(), emptyList(), Verdict.Coverage(deepScan = true, classesScanned = 10, hybridKinds = r.kinds)).notSeen
        assertTrue(ns, ns.startsWith("Dart code (Flutter libapp.so): strings read, code not analysed; JavaScript (React Native bundle): strings read, code not analysed"))
        assertEquals(listOf(HybridKind.FLUTTER, HybridKind.REACT_NATIVE, HybridKind.CORDOVA),
            HybridInspector.detectAll(listOf("assets/www/index.html", "assets/capacitor.config.json", "assets/index.android.bundle", "lib/x86/libhermes.so",
                "lib/x86/libapp.so", "lib/x86/libflutter.so", "assets/flutter_assets/a")))  // deterministic order whatever the archive order
    }

    @Test fun aNativeAppHasNoSectionNoBriefLineAndNoHybridClause() {                // K-9's shape
        val r = HybridInspector.inspect(zip(mapOf("classes.dex" to ByteArray(8), "lib/arm64-v8a/libsqlcipher.so" to ElfTestBuilder.build())), emptyList())
        assertEquals(HybridKind.NONE, r.kind); assertTrue(r.kinds.isEmpty())
        assertEquals("", HybridInspector.markdown(r)); assertTrue(HybridInspector.briefLines(r).isEmpty())
        val ns = Verdict.build(emptyList(), emptyList(), Verdict.Coverage(deepScan = true, classesScanned = 10, hybridKinds = r.kinds)).notSeen
        assertFalse(ns, ns.contains("Dart") || ns.contains("JavaScript"))
        assertTrue(ns.startsWith("native: "))
    }

    // ---------------- audit_brief and the Verdict ----------------
    @Test fun oneBriefLinePerFramework() {
        loadFormats()
        val fl = HybridInspector.briefLines(HybridInspector.inspect(zip(mapOf("lib/arm64-v8a/libflutter.so" to ElfTestBuilder.build(),
            "lib/arm64-v8a/libapp.so" to ElfTestBuilder.build(rodata = listOf("https://a.example-pay.net/1", "https://b.example-pay.net/2", token)),
            "assets/flutter_assets/.env" to "X=https://c.example-pay.net/3\n".toByteArray())), emptyList()))
        assertEquals(listOf("Flutter: libapp.so, 3 endpoints, 1 secret, 1 config file"), fl)
        assertEquals(listOf("React Native: index.android.bundle, 2 endpoints, 1 secret"), HybridInspector.briefLines(HybridInspector.inspect(rn(hbc(rnStrings)), emptyList())))
        assertEquals(listOf("Cordova: assets/www, 2 named origins, 1 secret"), HybridInspector.briefLines(HybridInspector.inspect(cordova(configXmlText.toByteArray()), emptyList())))
        assertEquals(2, HybridInspector.briefLines(HybridInspector.inspect(mixed(), emptyList())).size)
    }

    @Test fun theNotSeenClausePerKind() {
        fun ns(vararg k: HybridKind) = Verdict.build(emptyList(), emptyList(), Verdict.Coverage(deepScan = true, classesScanned = 10, hybridKinds = k.toList())).notSeen
        assertTrue(ns(HybridKind.FLUTTER).startsWith("Dart code (Flutter libapp.so): strings read, code not analysed; native: "))
        assertTrue(ns(HybridKind.REACT_NATIVE).startsWith("JavaScript (React Native bundle): strings read, code not analysed; native: "))
        assertTrue(ns(HybridKind.CORDOVA).startsWith("JavaScript (Cordova / Capacitor www): strings read, code not analysed; native: "))
        // the detected kinds replace the 1.2.0 card-based wording even when the cards are there
        fun info(rule: String, title: String) = SecurityScanner.Finding(SecurityScanner.Severity.INFO, title, "d", "r").also { it.ruleId = rule }
        val all = listOf(info("native-flutter", "Flutter app: the Dart code is compiled into libapp.so and is NOT analysed"))
        val withKinds = Verdict.build(emptyList(), emptyList(), Verdict.Coverage(deepScan = true, classesScanned = 10, hybridKinds = listOf(HybridKind.FLUTTER)), "", all).notSeen
        assertFalse(withKinds, withKinds.contains("strings scanned, the code itself not analysed"))
        assertEquals(1, Regex("Dart code").findAll(withKinds).count())
    }
}

/** A minimal binary XML (AXML) document: <widget> with child elements, each with one plain attribute (no namespace); the helpers of AxmlStrippedNamesTest, copied. */
object AxmlTestBuilder {
    fun widget(children: List<Pair<String, Pair<String, String>>>): ByteArray {
        val strings = ArrayList<String>(); fun idx(s: String): Int { val i = strings.indexOf(s); if (i >= 0) return i; strings.add(s); return strings.size - 1 }
        val w = idx("widget")
        val body = ByteArrayOutputStream()
        val els = children.map { (tag, kv) -> Triple(idx(tag), idx(kv.first), idx(kv.second)) }
        body.write(startEl(w, emptyList()))
        for ((t, n, v) in els) { body.write(startEl(t, listOf(attr(-1, n, v)))); body.write(endEl(t)) }
        body.write(endEl(w))
        val all = pool(strings) + body.toByteArray()
        return ByteBuffer.allocate(8 + all.size).order(ByteOrder.LITTLE_ENDIAN).putShort(0x0003).putShort(8).putInt(8 + all.size).put(all).array()
    }

    private fun le(v: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
    private fun le16(v: Int) = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort()).array()
    private fun chunk(type: Int, header: Int, body: ByteArray): ByteArray {
        val o = ByteArrayOutputStream(); o.write(le16(type)); o.write(le16(header)); o.write(le(8 + body.size)); o.write(body); return o.toByteArray()
    }
    private fun pool(strings: List<String>): ByteArray {
        val data = ByteArrayOutputStream(); val offs = ArrayList<Int>()
        for (s in strings) { offs.add(data.size()); data.write(le16(s.length)); for (c in s) data.write(le16(c.code)); data.write(le16(0)) }
        while (data.size() % 4 != 0) data.write(0)
        val head = ByteArrayOutputStream()
        head.write(le(strings.size)); head.write(le(0)); head.write(le(0)); head.write(le(28 + 4 * strings.size)); head.write(le(0))
        val offBytes = ByteArrayOutputStream().also { o -> for (x in offs) o.write(le(x)) }.toByteArray()
        return chunk(0x0001, 28, head.toByteArray() + offBytes + data.toByteArray())
    }
    private fun endEl(name: Int) = chunk(0x0103, 16, le(1) + le(-1) + le(-1) + le(name))
    private fun startEl(name: Int, attrs: List<ByteArray>): ByteArray {
        val head = le(1) + le(-1)
        val ext = le(-1) + le(name) + le16(20) + le16(20) + le16(attrs.size) + le16(0) + le16(0) + le16(0)
        val o = ByteArrayOutputStream(); for (a in attrs) o.write(a)
        return chunk(0x0102, 16, head + ext + o.toByteArray())
    }
    private fun attr(ns: Int, name: Int, str: Int): ByteArray = le(ns) + le(name) + le(str) + le16(8) + byteArrayOf(0, 0x03) + le(str)
}
