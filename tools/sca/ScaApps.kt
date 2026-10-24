import dev.apkrelab.DetectedLib
import dev.apkrelab.LibraryScanner
import java.io.File

/**
 * SCA on real APKs, with and without the generated database: prints, per APK, the libraries with a KNOWN version that the matcher flags, and the number of
 * libraries whose version is unknown. usage: ScaApps <vulns.json | none> <apk> [<apk> ...]   ("none" = the built-in hand-checked list only)
 */
fun main(a: Array<String>) {
    if (a[0] != "none") LibraryScanner.loadDbText(File(a[0]).readText()) else println("db: built-in")
    for (path in a.drop(1)) {
        val apk = File(path)
        val res = LibraryScanner.scanApk(apk)
        val libs = LibraryScanner.inventory
        val unknown = libs.count { it.version == "?" }
        val flagged = libs.filter { it.version != "?" }.map { it to LibraryScanner.matches(it) }.filter { it.second.isNotEmpty() }
        println("${apk.name}: libs=${libs.size} unknownVersion=$unknown flagged=${flagged.size}")
        for ((l, ms) in flagged) println("   ${l.group}:${l.artifact} ${l.version} -> ${ms.size}: " + ms.map { it.id.substringBefore(" /") + "[" + it.severity.name[0] + "]" }.take(4).joinToString(","))
    }
}
