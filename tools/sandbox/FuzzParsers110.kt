// 1.1.0: corruption fuzz of the 1.1.0 parsers (ElfAnalyzer JNI names, DeepLinks, ManifestDeepLinksRule, NativeBridge, DynamicReceivers, PathFlow, VersionProbes.registrarVersion).
// Byte flips / truncation of real .so files and binary manifests, line deletion / truncation / duplication of real smali; counts exceptions that escape and calls over 5 s.
// Build: kotlinc -Xfriend-paths=<kout> -cp <kout>:<ir classes> FuzzParsers110.kt -d out ; run: java -cp out:<kout>:<ir>:kotlin-stdlib.jar:json.jar FZKt <apks...> <decoded dirs...>
// Result 1.1.0 (34 + 5 APKs, Axis Pay 3.0.1, K-9, Paperless): calls 16080 escaped 0 over-5s 0
import dev.apkrelab.*
import java.util.Random
fun main(a: Array<String>) {
    val rnd = Random(110); var calls = 0; val escaped = HashMap<String, Int>(); var slow = 0
    fun run(tag: String, f: () -> Unit) { calls++; val t0 = System.nanoTime(); try { f() } catch (t: Throwable) { escaped.merge(tag + ":" + t.javaClass.simpleName, 1, Int::plus) }; if (System.nanoTime() - t0 > 5_000_000_000L) slow++ }
    fun mangle(b: ByteArray): ByteArray { val c = if (rnd.nextInt(4) == 0) b.copyOf(rnd.nextInt(b.size + 1)) else b.copyOf(); for (k in 0 until 1 + rnd.nextInt(64)) if (c.isNotEmpty()) c[rnd.nextInt(c.size)] = rnd.nextInt(256).toByte(); return c }
    // native libraries and manifests of the APKs
    val apks = a.filter { it.endsWith(".apk") }
    for (apk in apks) java.util.zip.ZipFile(apk).use { z ->
        val sos = z.entries().toList().filter { it.name.startsWith("lib/") && it.name.endsWith(".so") && it.size < 8_000_000 }.take(2).map { e -> z.getInputStream(e).readBytes() }
        val man = z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()
        for (k in 0 until 30) {
            for (so in sos) { val m = mangle(so); run("elf") { ElfAnalyzer.parse(m)?.let { i -> NativeBridge.libs = listOf(NativeBridge.LibFacts("x.so", i.jniExports.toHashSet(), i.jniOnLoad, i.dangerous)); NativeBridge.bindings() } } }
            val mm = mangle(man)
            run("deeplinks") { val x = Axml.decode(mm) ?: return@run; DeepLinks.parse(x, "p"); ManifestDeepLinksRule.scan(ManifestContext(x)); for (c in Regex("<activity[^>]*>(.*?)</activity>", RegexOption.DOT_MATCHES_ALL).findAll(x)) DeepLinks.unverifiedWebHosts(c.groupValues[1]) }
        }
    }
    // smali texts: mangled lines
    val texts = a.filter { !it.endsWith(".apk") }.flatMap { d -> java.io.File(d).walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.filter { f -> f.length() < 200_000 }.toList().shuffled(rnd).take(150) }.map { it.readText() }
    for (t in texts) for (k in 0 until 6) {
        val lines = t.lines().toMutableList()
        for (j in 0 until 1 + rnd.nextInt(8)) if (lines.isNotEmpty()) { val i = rnd.nextInt(lines.size); when (rnd.nextInt(3)) { 0 -> lines.removeAt(i); 1 -> lines[i] = lines[i].take(rnd.nextInt(lines[i].length + 1)); else -> lines.add(i, lines[rnd.nextInt(lines.size)]) } }
        val m = lines.joinToString("\n")
        run("nativebridge") { NativeBridge.observe("Lx;", m) }
        run("dynrecv") { DynamicReceivers.observe(m) }
        run("pathflow") { PathFlow.reachesPath(m, maxOf(0, m.indexOf("invoke")), "Ljava/util/zip/ZipEntry;->getName(") }
        run("versionprobe") { VersionProbes.registrarVersion(m, "fire-core") }
        run("params") { DeepLinks.paramsRead(m) }
    }
    println("calls $calls escaped " + (if (escaped.isEmpty()) "0" else escaped.toString()) + " over-5s $slow")
}
