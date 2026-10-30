import dev.apkrelab.*
import java.io.File

/**
 * The library inventory of real APKs as the app builds it: exact versions (LibraryScanner.scanApk) merged with package-path detections (ScaScanner.scanPackages over
 * the class type list). usage: ScaInventory <vulns.json> <types dir> <apk> [<apk> ...]; prints one line per library: apk, coordinate, version, source.
 */
fun main(a: Array<String>) {
    LibraryScanner.loadDbText(File(a[0]).readText())
    for (path in a.drop(2)) {
        val apk = File(path); val name = apk.name.removeSuffix(".apk")
        LibraryScanner.scanApk(apk)
        val types = File(a[1], "$name.txt").readLines().filter { it.isNotEmpty() }
        val merged = LibraryScanner.mergeInventory(ScaScanner.scanPackages(types))
        for (l in merged) println("$name\t${l.group}:${l.artifact}\t${l.version}\t${l.source}")
    }
}
