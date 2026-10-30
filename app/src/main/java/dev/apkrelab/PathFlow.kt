package dev.apkrelab

import dev.apkrelab.ir.Insn
import dev.apkrelab.ir.MethodIr
import dev.apkrelab.ir.SmaliParser
import dev.apkrelab.ir.SsaForm

/**
 * 1.1.0: inside ONE method, does the value an API returns (an archive entry's name) reach a file path, or is it only listed, compared or used as a key?
 *
 * The 0.35.0 Zip Slip rule reported any method that both reads ZipEntry.getName() and constructs a File anywhere. APKReLab's own self-scan showed the cost: a method
 * that only lists entry names, a zip-to-zip copy writing to its caller's output file, and a name reduced to a bare file name were all HIGH. The value is followed on
 * the method's SSA form through moves, casts and text operations (String, StringBuilder, CharSequence, Kotlin's text functions); it stops at the basename sanitizers
 * (File.getName, substringAfterLast with a constant '/') and at anything else (a map key, a Pair, a list). Reported only when it is an argument of a File /
 * FileOutputStream / FileWriter / RandomAccessFile constructor or of Paths.get, or when it is the receiver-less path of a Kotlin File.resolve.
 */
object PathFlow {
    private val pathSinks = listOf("Ljava/io/File;-><init>", "Ljava/io/FileOutputStream;-><init>", "Ljava/io/FileWriter;-><init>", "Ljava/io/RandomAccessFile;-><init>",
        "Ljava/nio/file/Paths;->get", "Lkotlin/io/FilesKt__UtilsKt;->resolve", "Lkotlin/io/FilesKt;->resolve")
    private val textOwners = listOf("Ljava/lang/String;", "Ljava/lang/StringBuilder;", "Ljava/lang/CharSequence;", "Ljava/lang/StringBuffer;", "Lkotlin/text/StringsKt")

    /**
     * true = a value returned by [source] (an owner->name prefix) in the method that holds char offset [at] of [text] (a call inside it) reaches a path constructor unsanitized;
     * false = it never does; null = could not tell (no parse, no such call): the caller keeps its old rule.
     */
    fun reachesPath(text: String, at: Int, source: String): Boolean? = try {
        val c = SmaliParser.parse(text)
        val m = c.methods.lastOrNull { it.startOffset <= at }
        if (m == null || m.insns.isEmpty()) null else reaches(m, source)
    } catch (_: Throwable) { null }

    private fun reaches(m: MethodIr, source: String): Boolean? {
        val ssa = SsaForm.build(m)
        val users = HashMap<SsaForm.Value, MutableList<Insn>>()
        for (insn in m.insns) for (u in ssa.usesOf(insn)) if (u != null) users.getOrPut(u) { ArrayList() }.add(insn)
        val phiUsers = HashMap<SsaForm.Value, MutableList<SsaForm.Value>>()
        for (ps in ssa.phis) for (p in ps) for (o in p.operands) if (o != null && p.result != null) phiUsers.getOrPut(o) { ArrayList() }.add(p.result)
        val work = ArrayDeque<SsaForm.Value>(); val seen = HashSet<SsaForm.Value>()
        var anySource = false
        for (insn in m.insns) if (insn.kind == Insn.Kind.INVOKE && insn.ref.startsWith(source) && insn.hasResult) {
            anySource = true
            for (d in ssa.defsOf(insn)) if (d != null && seen.add(d)) work.add(d)
        }
        if (!anySource) return null
        while (work.isNotEmpty()) {
            val v = work.removeFirst()
            phiUsers[v]?.forEach { if (seen.add(it)) work.add(it) }
            for (insn in users[v].orEmpty()) {
                when (insn.kind) {
                    Insn.Kind.MOVE, Insn.Kind.CHECK_CAST -> ssa.defsOf(insn).forEach { if (it != null && seen.add(it)) work.add(it) }
                    Insn.Kind.INVOKE -> {
                        val ref = insn.ref
                        if (pathSinks.any { ref.startsWith(it) }) {
                            val us = ssa.usesOf(insn)
                            // a File(parent, child) built FROM a tainted File is a path too; a constructor's receiver itself is not an argument
                            val isCtor = ref.contains("-><init>")
                            if (!isCtor || (us.isNotEmpty() && us[0] !== v)) return true
                            continue
                        }
                        if (sanitizes(m, ssa, insn)) continue
                        if (textOwners.any { ref.startsWith(it) } || ref.startsWith("Ljava/lang/String;->valueOf")) {
                            ssa.defsOf(insn).forEach { if (it != null && seen.add(it)) work.add(it) }
                            // StringBuilder.append(tainted) taints the builder the receiver register holds
                            val us = ssa.usesOf(insn)
                            if (ref.startsWith("Ljava/lang/StringBuilder;->append") && us.isNotEmpty() && us[0] !== v && seen.add(us[0])) work.add(us[0])
                        }
                    }
                    else -> {}
                }
            }
        }
        return false
    }

    /** File.getName(), or substringAfterLast with a constant '/' (Kotlin `name.substringAfterLast('/')`): a bare file name, no directory part left. */
    private fun sanitizes(m: MethodIr, ssa: SsaForm, insn: Insn): Boolean {
        val ref = insn.ref
        if (ref.startsWith("Ljava/io/File;->getName(")) return true
        if (ref.startsWith("Lkotlin/text/StringsKt") && ref.contains("->substringAfterLast")) {
            val us = ssa.usesOf(insn)
            if (us.size > 1) {
                val d = us[1]?.def
                if (d != null && d.kind == Insn.Kind.CONST) {
                    val lit = d.ref.trim()
                    return lit == "0x2f" || lit == "47" || lit == "\"/\""
                }
            }
        }
        return false
    }
}
