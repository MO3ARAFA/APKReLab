package dev.apkrelab

/**
 * 0.102.0: deterministic guards that replace an AI verdict on two recurring false-positive shapes (the AI had judged both "false positive" on a protected fintech app; a rule should say
 * so by itself, with its reasoning in the card):
 *  1. `Cipher.getInstance("AES/ECB/NoPadding")` whose only use is `doFinal` on ONE fresh, never written 16-byte array = AES of the all-zero block: the primitive inside AES-CMAC / CBC-MAC
 *     (subkey derivation L = E_K(0^128)). ECB's weakness is about repeating plaintext blocks; a single constant block has none.
 *  2. `Runtime.exec` / `ProcessBuilder(String...)` whose every argument is a constant: a literal, or the result of a constant-indexed static `(I)Ljava/lang/String;` lookup (the string-table
 *     decryptor of a protector). There is nothing an attacker can inject into; typical of root / emulator checks (`su`, `which su`, `getprop`).
 * Both work on the smali of ONE method, backwards from the use, and answer "unknown" (= keep the original severity) on anything they do not fully understand: a label between the
 * definition and the use, another reader of the array, an argument computed in any other way. Nothing here guesses.
 */
object ConstantArgGuards {
    private val frameworkPrefixes = listOf("Ljava/", "Ljavax/", "Landroid/", "Lkotlin/", "Ldalvik/")
    private val invokeRe = Regex("""^invoke-(static|virtual|direct|interface|super)(?:/range)?\s+\{([^}]*)\},\s*(L[^;]+;)->([^(]+)\(([^)]*)\)(\S+)""")
    private val constNumRe = Regex("""^const(?:/4|/16|/high16)?\s+([vp]\d+),\s*(-?0x[0-9a-fA-F]+)""")
    private val noWrite = listOf("invoke", "return", "if-", "iput", "sput", "aput", "goto", "throw", "monitor", "fill-array", "nop", ".")

    /** The trimmed instruction lines of the method that contains [offset] of [text] (directives and blank lines kept; they are skipped by the readers). */
    fun methodAround(text: String, offset: Int): List<String> {
        val s = methodStart(text, offset)
        val e = text.indexOf("\n.end method", offset).let { if (it < 0) text.length else it }
        return text.substring(s, maxOf(s, e)).split('\n').map { it.trim() }
    }

    private fun methodStart(text: String, offset: Int): Int = text.lastIndexOf("\n.method ", offset).let { if (it < 0) 0 else it + 1 }

    private fun isReal(l: String) = l.isNotEmpty() && !l.startsWith(".") && !l.startsWith("#")
    private fun isLabel(l: String) = l.startsWith(":")

    private fun regsOf(list: String): List<String> {
        val t = list.trim()
        if (t.isEmpty()) return emptyList()
        if (t.contains("..")) {
            val (a, b) = t.split("..").map { it.trim() }
            val n0 = a.drop(1).toIntOrNull() ?: return emptyList(); val n1 = b.drop(1).toIntOrNull() ?: return emptyList()
            return (n0..n1).map { a.take(1) + it }
        }
        return t.split(',').map { it.trim() }
    }

    /** Parameter descriptors of a method signature: "I", "Ljava/lang/String;", "[B", ... */
    private fun params(desc: String): List<String> {
        val out = ArrayList<String>(); var i = 0
        while (i < desc.length) {
            val st = i
            while (i < desc.length && desc[i] == '[') i++
            if (i < desc.length && desc[i] == 'L') i = desc.indexOf(';', i).let { if (it < 0) desc.length else it }
            i++
            out.add(desc.substring(st, minOf(i, desc.length)))
        }
        return out
    }

    private fun writesReg(l: String, reg: String): Boolean {
        if (!isReal(l) || isLabel(l)) return false
        if (noWrite.any { l.startsWith(it) }) return false
        val parts = l.split(Regex("\\s+"), limit = 3)
        return parts.size >= 2 && parts[1].removeSuffix(",") == reg
    }

    /** Index of the nearest instruction BEFORE [use] that writes [reg]; null when a label (another path may arrive) or the method start comes first. */
    private fun defIndex(lines: List<String>, use: Int, reg: String): Int? {
        var i = use - 1
        while (i >= 0) {
            val l = lines[i]
            if (isLabel(l) || l.startsWith(".method")) return null
            if (writesReg(l, reg)) return i
            i--
        }
        return null
    }

    private fun prevReal(lines: List<String>, idx: Int): Int? {
        var i = idx - 1
        while (i >= 0) { if (isReal(lines[i])) return i; if (lines[i].startsWith(".method")) return null; i-- }
        return null
    }

    private fun intConst(lines: List<String>, use: Int, reg: String): Long? {
        val d = defIndex(lines, use, reg) ?: return null
        val m = constNumRe.find(lines[d]) ?: return null
        return try { java.lang.Long.decode(m.groupValues[2]) } catch (_: Throwable) { null }
    }

    /** Whether the String held in [reg] just before line [use] is a constant: a literal, a copy of one, or a constant-indexed static (I)String lookup of a non-framework class. */
    fun isConstString(lines: List<String>, use: Int, reg: String): Boolean {
        val d = defIndex(lines, use, reg) ?: return false
        val l = lines[d]
        if (l.startsWith("const-string")) return true
        if (l.startsWith("move-object")) { val src = l.split(Regex("\\s+"), limit = 3).getOrNull(2)?.trim() ?: return false; return isConstString(lines, d, src) }
        if (l.startsWith("move-result-object")) {
            val p = prevReal(lines, d) ?: return false
            val m = invokeRe.find(lines[p]) ?: return false
            if (m.groupValues[1] != "static" || m.groupValues[6] != "Ljava/lang/String;" || m.groupValues[5] != "I") return false
            if (frameworkPrefixes.any { m.groupValues[3].startsWith(it) }) return false
            val arg = regsOf(m.groupValues[2]).singleOrNull() ?: return false
            return intConst(lines, p, arg) != null
        }
        return false
    }

    /** Whether [reg] just before line [use] holds a String[] whose every element is constant (new-array + aput-object of constants, or filled-new-array), left alone in between. */
    fun isConstStringArray(lines: List<String>, use: Int, reg: String): Boolean {
        val d = defIndex(lines, use, reg) ?: return false
        val l = lines[d]
        if (l.startsWith("move-result-object")) {
            val p = prevReal(lines, d) ?: return false
            val pl = lines[p]
            if (!pl.startsWith("filled-new-array") || !pl.contains("[Ljava/lang/String;")) return false
            val regs = regsOf(pl.substringAfter('{').substringBefore('}'))
            return regs.isNotEmpty() && regs.all { isConstString(lines, p, it) }
        }
        if (!l.startsWith("new-array") || !l.trimEnd().endsWith("[Ljava/lang/String;")) return false
        for (i in d + 1 until use) {
            val x = lines[i]
            if (isLabel(x) || !isReal(x)) { if (isLabel(x)) return false; continue }
            if (x.startsWith("aput-object")) {
                val ops = x.removePrefix("aput-object").split(',').map { it.trim() }
                if (ops.getOrNull(1) == reg) { if (!isConstString(lines, i, ops[0])) return false; continue }
            }
            if (Regex("\\b" + reg + "\\b").containsMatchIn(x.substringAfter(' '))) return false   // the array is read or handed on before the call: not provably constant
        }
        return true
    }

    private fun isNull(lines: List<String>, use: Int, reg: String): Boolean {
        val d = defIndex(lines, use, reg) ?: return false
        val m = constNumRe.find(lines[d]) ?: return false
        return m.groupValues[2] == "0x0"
    }

    /** Result for one call site: true = every argument that can carry a command is constant, false = something else (or something not understood). */
    private fun sitePurelyConstant(lines: List<String>, idx: Int): Boolean {
        val m = invokeRe.find(lines[idx]) ?: return false
        val owner = m.groupValues[3]; val name = m.groupValues[4]
        val isExec = owner == "Ljava/lang/Runtime;" && name == "exec"
        val isPb = owner == "Ljava/lang/ProcessBuilder;" && name == "<init>"
        if (!isExec && !isPb) return false
        val regs = regsOf(m.groupValues[2]).toMutableList()
        val ps = params(m.groupValues[5])
        regs.removeAt(0)                                  // the receiver (Runtime / the ProcessBuilder being constructed)
        var r = 0
        for ((k, p) in ps.withIndex()) {
            val reg = regs.getOrNull(r) ?: return false
            r += if (p == "J" || p == "D") 2 else 1
            val ok = when (p) {
                "Ljava/lang/String;" -> isConstString(lines, idx, reg)
                "[Ljava/lang/String;" -> isConstStringArray(lines, idx, reg) || (k > 0 && isNull(lines, idx, reg))
                "Ljava/io/File;" -> true                  // the working directory is not the command
                else -> false                             // a List, a char sequence ...: not understood
            }
            if (!ok) return false
        }
        return ps.isNotEmpty()
    }

    /** (call sites of Runtime.exec / ProcessBuilder(String...) in the class, how many of them have only constant arguments). */
    fun shellSites(text: String): Pair<Int, Int> {
        var total = 0; var constant = 0
        var from = 0
        val needles = listOf("Ljava/lang/Runtime;->exec(", "Ljava/lang/ProcessBuilder;-><init>(")
        while (true) {
            val hit = needles.map { text.indexOf(it, from) }.filter { it >= 0 }.minOrNull() ?: break
            from = hit + 1
            val lines = methodAround(text, hit)
            val ms = methodStart(text, hit)
            val idx = text.substring(ms, hit).count { it == '\n' }          // the line of THIS call (the same call text can occur twice in a method)
            if (idx >= lines.size || !invokeRe.containsMatchIn(lines[idx])) continue
            total++
            if (sitePurelyConstant(lines, idx)) constant++
        }
        return total to constant
    }

    /** The posture signal: some Runtime.exec / ProcessBuilder call of the class has only constant arguments. */
    fun hasConstantShell(text: String): Boolean {
        if (!text.contains("Ljava/lang/Runtime;->exec(") && !text.contains("Ljava/lang/ProcessBuilder;-><init>(")) return false
        return shellSites(text).second > 0
    }

    /**
     * True when every use of a Cipher in the method that contains [offset] is `doFinal([B)` on a fresh 16-byte array that nothing else reads or writes: AES of the zero block.
     * Only meaningful for "AES/ECB/NoPadding"; the caller checks the transformation.
     */
    fun isZeroBlockOnly(text: String, offset: Int): Boolean {
        val lines = methodAround(text, offset)
        var finals = 0
        for ((i, l) in lines.withIndex()) {
            if (!l.startsWith("invoke")) continue
            if (l.contains("Ljavax/crypto/Cipher;->update(") || l.contains("Ljavax/crypto/Cipher;->updateAAD(") || l.contains("Ljavax/crypto/CipherOutputStream;") || l.contains("Ljavax/crypto/CipherInputStream;")) return false
            if (!l.contains("Ljavax/crypto/Cipher;->doFinal(")) continue
            val m = invokeRe.find(l) ?: return false
            if (m.groupValues[5] != "[B") return false                      // doFinal(byte[], int, int) and friends: not the one-block form
            val regs = regsOf(m.groupValues[2])
            val arr = regs.getOrNull(1) ?: return false
            if (!isFreshZeroBlock(lines, i, arr)) return false
            finals++
        }
        return finals > 0
    }

    private fun isFreshZeroBlock(lines: List<String>, use: Int, reg: String): Boolean {
        val d = defIndex(lines, use, reg) ?: return false
        val m = Regex("""^new-array\s+([vp]\d+),\s*([vp]\d+),\s*\[B$""").find(lines[d]) ?: return false
        if (m.groupValues[1] != reg) return false
        if (intConst(lines, d, m.groupValues[2]) != 16L) return false
        val rx = Regex("\\b" + reg + "\\b")
        for (i in d + 1 until use) {
            val x = lines[i]
            if (isLabel(x)) return false
            if (!isReal(x)) continue
            if (rx.containsMatchIn(x.substringAfter(' '))) return false     // the array is written, copied or handed to something before the doFinal
        }
        return true
    }
}
