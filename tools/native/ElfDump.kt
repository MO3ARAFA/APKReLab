import dev.apkrelab.ElfAnalyzer
import java.io.File

/** One TSV line per ELF file: the fields compared with readelf by oracle.py. usage: ElfDump <file> ... */
fun main(a: Array<String>) {
    for (p in a) {
        val e = ElfAnalyzer.parse(File(p).readBytes())
        if (e == null) { println(File(p).name + "\tNOT-ELF"); continue }
        println(listOf(File(p).name, if (e.is64) "64" else "32", e.type, e.gnuStack, e.stackExecutable, e.relroSegment, e.bindNow, e.textrel, e.soname ?: "-", e.needed.sorted().joinToString(","),
            e.dynsymCount, e.imports.map { it.substringBefore('@') }.sorted().joinToString(","), e.exports, "0x" + java.lang.Long.toHexString(e.minLoadAlign), e.rpath ?: "-", e.runpath ?: "-").joinToString("\t"))
    }
}
