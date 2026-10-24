import dev.apkrelab.DetectedLib
import dev.apkrelab.LibraryScanner
import java.io.File

/** SCA oracle driver: reads "group:artifact<TAB>version" lines, prints the ids of the advisories the app's matcher reports (compare with oracle.py, which uses the raw advisory data). */
fun main(a: Array<String>) {
    LibraryScanner.loadDbText(File(a[0]).readText())
    File(a[1]).forEachLine { line ->
        val (c, v) = line.split('\t')
        val (g, art) = c.split(':', limit = 2)
        val ids = LibraryScanner.matches(DetectedLib(g, art, v, "t", "version file")).flatMap { it.id.split(" / ") }.filter { it.startsWith("GHSA-") }.sorted()
        println(c + "\t" + v + "\t" + ids.joinToString(","))
    }
}
