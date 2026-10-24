import dev.apkrelab.*
import java.io.File
import java.util.zip.ZipFile

/**
 * The defense posture of a decoded app. usage: PostureApps <apps dir> <app> ...   (reads <apps dir>/dec_<app>/smali*, the APK for the manifest package)
 * prints: app<TAB>signal<TAB>classes in app code<TAB>classes only in libraries<TAB>first app class<TAB>renamed classes of unknown origin, then an OBF line.
 */
fun main(a: Array<String>) {
    for (name in a.drop(1)) {
        val dec = File(a[0], "dec_$name"); val apk = File(a[0], "$name.apk")
        val manifest = ZipFile(apk).use { z -> Axml.decode(z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()) } ?: ""
        val mpkg = Regex("package=\"([^\"]+)\"").find(manifest)?.groupValues?.get(1) ?: ""
        val texts = ArrayList<Pair<String, String>>()
        val re = Regex("^\\.class[^\\n]* (L[^;]+;)", RegexOption.MULTILINE)
        dec.walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.forEach { f -> val t = f.readText(); re.find(t)?.groupValues?.get(1)?.let { texts.add(it to t) } }
        val pkg = SecurityScanner.codePackage(texts.map { it.first }, mpkg)
        PostureScanner.clear()
        for ((t, x) in texts) PostureScanner.observe(t, x, pkg)
        for (r in PostureScanner.rows()) println("$name\t${r.sig.id}\t${r.app.size}\t${r.lib.size}\t${r.app.firstOrNull() ?: r.obf.firstOrNull() ?: "-"}\t${r.obf.size}")
        println("$name\tOBF\t${PostureScanner.obfuscationLine()}")
    }
}
