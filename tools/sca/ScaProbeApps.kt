import dev.apkrelab.*
import java.io.File

/**
 * The 0.88.0 inventory on real APKs: exact versions + code-constant probes + package-path rest. usage: ScaProbeApps <vulns.json> <types dir> <apps dir> <app> [<app> ...]
 * (the class text of a probe class is read from <apps dir>/dec_<app>/smali*\/<type>.smali, i.e. from an apktool decode). Prints a line per library:
 * app, coordinate, version, source, and the advisories that match.
 */
fun main(a: Array<String>) {
    LibraryScanner.loadDbText(File(a[0]).readText())
    for (name in a.drop(3)) {
        val apk = File(a[2], "$name.apk")
        val dec = File(a[2], "dec_$name")
        LibraryScanner.scanApk(apk)
        val typesList = File(a[1], "$name.txt").readLines().filter { it.isNotEmpty() }
        val types = typesList.toHashSet()
        val pathLibs = ScaScanner.scanPackages(typesList)
        fun textOf(t: String): String? {
            val rel = t.removePrefix("L").removeSuffix(";") + ".smali"
            return dec.listFiles { f -> f.isDirectory && f.name.startsWith("smali") }?.map { File(it, rel) }?.firstOrNull { it.exists() }?.readText()
        }
        val probed = if (dec.exists()) VersionProbes.resolve(types, pathLibs, ::textOf) else emptyList()
        LibraryScanner.mergeInventory(probed)
        val merged = LibraryScanner.mergeInventory(pathLibs)
        for (l in merged) {
            val ms = if (l.version == "?") emptyList() else LibraryScanner.matches(l)
            println("$name\t${l.group}:${l.artifact}\t${l.version}\t${l.source}\t" + ms.joinToString(",") { it.id.substringBefore(" /") + "[" + it.severity.name[0] + "]" })
        }
    }
}
