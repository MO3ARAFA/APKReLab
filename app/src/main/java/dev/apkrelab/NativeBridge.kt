package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap

/**
 * 1.1.0: which native library implements each `native` method the DEX code declares.
 *
 * Two bindings exist. Static: the library exports the JNI name `Java_<class>_<method>` (or `..__<params>` for an overload), read from its `.dynsym` (ElfAnalyzer).
 * Dynamic: the library registers the method itself with RegisterNatives, normally from `JNI_OnLoad`; the export table then has no name for it, and the library is the one the declaring
 * class (or, failing that, the app) loads with `System.loadLibrary("x")` and that exports JNI_OnLoad. A dynamic binding is a statement about the candidates, not proof of which function
 * implements the method (that needs the library's code).
 *
 * Measured on the decoded corpus (tools/sandbox/PERF.md 1.1.0) before it was built. Feeding untrusted input into a native method was measured too and NOT made a finding:
 * one site in 16 apps, and that one reads the app's own APK entries (a protector's integrity check).
 */
object NativeBridge {
    class Decl(val classType: String, val name: String, val desc: String)
    class LibFacts(val name: String, val jniExports: Set<String>, val jniOnLoad: Boolean, val dangerous: List<String>)
    enum class Kind { STATIC, DYNAMIC, DYNAMIC_CANDIDATES, NO_LIBRARY }
    class Binding(val decl: Decl, val kind: Kind, val libs: List<String>)

    private val decls = ConcurrentHashMap<String, Decl>()                     // classType->name+desc
    private val loads = ConcurrentHashMap<String, MutableSet<String>>()       // classType -> library names given to System.loadLibrary ("foo" = libfoo.so)
    @Volatile var libs: List<LibFacts> = emptyList()

    fun clear() { decls.clear(); loads.clear() }
    fun clearApk() { libs = emptyList() }

    private val nativeRe = Regex("^\\.method [^\\n]*\\bnative\\b[^\\n]*?([A-Za-z0-9_$<>]+)(\\([^)]*\\)\\S+)\\s*$", RegexOption.MULTILINE)
    private val loadRe = Regex("const-string(?:/jumbo)? ([vp]\\d+), \"([^\"]+)\"\\s*\\n(?:\\s*(?:\\.line \\d+)?\\s*\\n)*\\s*invoke-static \\{\\1\\}, (?:Ljava/lang/System;->loadLibrary\\(|Lcom/facebook/soloader/SoLoader;->loadLibrary\\(Ljava/lang/String;\\))")

    /** Called with the text of every class of the full scan; thread-safe and cheap for classes without `native` / loadLibrary. */
    fun observe(classType: String, text: String) {
        if (text.contains(" native ")) for (m in nativeRe.findAll(text)) decls[classType + "->" + m.groupValues[1] + m.groupValues[2]] = Decl(classType, m.groupValues[1], m.groupValues[2])
        if (text.contains("->loadLibrary(")) for (m in loadRe.findAll(text)) loads.getOrPut(classType) { ConcurrentHashMap.newKeySet() }.add(m.groupValues[2])
    }

    fun useLibs(list: List<NativeScanner.Lib>) {
        libs = list.map { LibFacts(it.name, it.info.jniExports.toHashSet(), it.info.jniOnLoad, it.info.dangerous) }
    }

    /** JNI name mangling (JNI specification, "Resolving Native Method Names"). */
    fun mangle(s: String): String {
        val sb = StringBuilder()
        for (c in s) when {
            c == '/' || c == '.' -> sb.append('_')
            c == '_' -> sb.append("_1")
            c == ';' -> sb.append("_2")
            c == '[' -> sb.append("_3")
            c.code in 0x30..0x39 || c.code in 0x41..0x5a || c.code in 0x61..0x7a -> sb.append(c)
            else -> sb.append("_0").append(String.format("%04x", c.code))
        }
        return sb.toString()
    }

    fun shortName(d: Decl) = "Java_" + mangle(d.classType.removePrefix("L").removeSuffix(";")) + "_" + mangle(d.name)
    fun longName(d: Decl) = shortName(d) + "__" + mangle(d.desc.substringAfter('(').substringBefore(')'))

    /** The binding of every declared native method, given the libraries [libs] and the loadLibrary calls seen. */
    fun bindings(libs: List<LibFacts> = this.libs): List<Binding> {
        return decls.values.sortedBy { it.classType + it.name }.map { d ->
            val s = shortName(d); val l = longName(d)
            val static = libs.filter { s in it.jniExports || l in it.jniExports }.map { it.name }
            when {
                static.isNotEmpty() -> Binding(d, Kind.STATIC, static)
                libs.isEmpty() -> Binding(d, Kind.NO_LIBRARY, emptyList())
                else -> {
                    val own = loads[d.classType].orEmpty().map { "lib$it.so" }.filter { n -> libs.any { it.name == n && it.jniOnLoad } }
                    if (own.isNotEmpty()) Binding(d, Kind.DYNAMIC, own)
                    else Binding(d, Kind.DYNAMIC_CANDIDATES, libs.filter { it.jniOnLoad }.map { it.name }.sorted())      // the class loads nothing itself: any library with JNI_OnLoad
                }
            }
        }
    }

    private fun label(b: Binding): String = when (b.kind) {
        Kind.STATIC -> "exported by " + b.libs.joinToString(", ") + " (static JNI name)"
        Kind.DYNAMIC -> "registered at run time by " + b.libs.joinToString(", ") + " (loaded by this class with System.loadLibrary; JNI_OnLoad)"
        Kind.DYNAMIC_CANDIDATES -> if (b.libs.isEmpty()) "no library exports its JNI name and none has JNI_OnLoad" else "not exported by name: registered at run time by one of " + b.libs.take(5).joinToString(", ") + (if (b.libs.size > 5) " (+" + (b.libs.size - 5) + ")" else "") + " (JNI_OnLoad; this class does not load a library itself)"
        Kind.NO_LIBRARY -> "no native library in the archives read (it may be in a split APK that was not imported)"
    }

    /** Report section: counts, then the app's own (non-library) native methods with their library and the unsafe C functions that library imports. */
    fun section(appPkg: String): String {
        val bs = bindings()
        if (bs.isEmpty()) return ""
        val sb = StringBuilder("## Native methods (Java <-> .so)\n\n")
        sb.append(bs.size).append(" native method(s) declared in the DEX code: ").append(bs.count { it.kind == Kind.STATIC }).append(" bound by an exported JNI name, ")
            .append(bs.count { it.kind == Kind.DYNAMIC || it.kind == Kind.DYNAMIC_CANDIDATES }).append(" registered at run time (RegisterNatives), ")
            .append(bs.count { it.kind == Kind.NO_LIBRARY }).append(" without a library in the archives read.\n\n")
        val app = bs.filter { SecurityScanner.scopeOf(it.decl.classType, appPkg) != SecurityScanner.Scope.LIB }
        if (app.isNotEmpty()) {
            sb.append("| Native method (outside known libraries) | Implemented in | Unsafe C functions the library imports |\n|---|---|---|\n")
            for (b in app.take(40)) {
                val unsafe = b.libs.flatMap { n -> libs.firstOrNull { it.name == n }?.dangerous.orEmpty() }.distinct()
                sb.append("| `").append(b.decl.classType.removePrefix("L").removeSuffix(";").replace('/', '.')).append('.').append(b.decl.name).append(b.decl.desc.substringBefore(')')).append(")` | ")
                    .append(label(b)).append(" | ").append(if (unsafe.isEmpty()) "-" else unsafe.joinToString(", ")).append(" |\n")
            }
            if (app.size > 40) sb.append("\n... ").append(app.size - 40).append(" more.\n")
        }
        sb.append("\nA native method is code the Java analysis cannot follow: what it does with its arguments is only known from the library itself.\n\n")
        return sb.toString()
    }

    /** One line per native method of [classType] (for classify_class); empty when it declares none. */
    fun forClass(classType: String): String = bindings().filter { it.decl.classType == classType }.joinToString("\n") { "native " + it.decl.name + it.decl.desc + ": " + label(it) }

    /** One line for audit_brief. */
    fun brief(appPkg: String): String {
        val app = bindings().filter { SecurityScanner.scopeOf(it.decl.classType, appPkg) != SecurityScanner.Scope.LIB }
        if (app.isEmpty()) return ""
        return "\nNATIVE BRIDGE (" + app.size + " native methods outside known libraries): " + app.take(6).joinToString("; ") {
            it.decl.classType.removePrefix("L").removeSuffix(";").replace('/', '.') + "." + it.decl.name + " -> " + label(it)
        } + (if (app.size > 6) "; ..." else "") + "\n"
    }
}
