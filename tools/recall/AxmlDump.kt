import dev.apkrelab.Axml
import java.util.zip.ZipFile
/** Recall kit: the APK's manifest as the scanner decodes it (text), to be edited and passed with -Dmanifest. */
fun main(a: Array<String>) {
    val m = ZipFile(a[0]).use { z -> Axml.decode(z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()) } ?: error("no manifest")
    java.io.File(a[1]).writeText(m)
}
