import dev.apkrelab.SecretFormats
import java.io.File

/** Runs the vendor token formats over files of strings (one per line; tools/secrets/dexstrings.py makes them from an APK). usage: ScanStrings <secret_formats.json> <strings file> ... ; prints: file<TAB>rule<TAB>secret */
fun main(a: Array<String>) {
    SecretFormats.load(File(a[0]).readText())
    for (p in a.drop(1)) {
        val name = File(p).name.removeSuffix(".txt")
        File(p).forEachLine { l -> for (h in SecretFormats.scan(l)) println(name + "\t" + h.ruleId + "\t" + h.secret.take(90)) }
    }
}
