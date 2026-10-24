import dev.apkrelab.*
import java.io.File
import java.util.zip.ZipFile

/** NativeScanner on real APKs with each APK's own target SDK (read from its manifest). usage: NativeApps <secret_formats.json> <apk> ...  prints one line per finding */
fun main(a: Array<String>) {
    SecretFormats.load(File(a[0]).readText())
    for (p in a.drop(1)) {
        val t0 = System.currentTimeMillis()
        val fs = ZipFile(p).use { z -> NativeScanner.scan(z, Axml.decode(z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes())) }
        val sec = (System.currentTimeMillis() - t0) / 1000.0
        if (fs.isEmpty()) { println(File(p).name + "\t-\t-\t(no native libraries)\t$sec"); continue }
        for (f in fs) println(File(p).name + "\t" + f.ruleId + "\t" + f.severity.label + "\t" + f.title + "\t" + sec + "\t" + f.detail.take(400).replace("\n", " "))
    }
}
