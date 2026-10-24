import dev.apkrelab.SecurityScanner
import java.io.File

/** Recall kit: the code package the scanner itself chooses for a decoded app (SecurityScanner.codePackage), so injected classes land where app code lives. */
fun main(a: Array<String>) {
    val types = ArrayList<String>()
    val re = Regex("^\\.class[^\\n]* (L[^;]+;)", RegexOption.MULTILINE)
    File(a[0]).walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.forEach { f ->
        val head = f.bufferedReader().use { r -> val sb = StringBuilder(); var n = 0; var l = r.readLine(); while (l != null && n++ < 6) { sb.append(l).append('\n'); l = r.readLine() }; sb.toString() }
        re.find(head)?.groupValues?.get(1)?.let { types.add(it) }
    }
    println(SecurityScanner.codePackage(types, a[1]))
}
