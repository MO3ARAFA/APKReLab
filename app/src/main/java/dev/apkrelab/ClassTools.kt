package dev.apkrelab

/**
 * 0.106.0: two deterministic agent tools over ONE class text (no AI in the answer, no device needed; MainActivity supplies the texts, the assembler and the last scan's facts).
 *  - [verifyEdit]: is a proposed smali edit valid, and what does it change for the scanner? The rule findings and the single-class SSA flows of the original and of the edit are compared:
 *    "removed" is what the patch fixes, "added" is what it breaks. Only this class is analysed: a flow that needs another class is not seen (said in the answer).
 *  - [classify]: what an obfuscated class probably is: the SDK the last Deep scan attributed it to (SdkAttribution), signs of R8 class merging, and the packages its code names.
 */
object ClassTools {
    private val discriminator = Regex("^\\.field [^\\n]*\\bsynthetic\\b[^\\n]*:[BSI]$", RegexOption.MULTILINE)
    private val typeRef = Regex("L[A-Za-z0-9_$/]+;")

    /** [assemble] returns null when the text assembles, else the assembler's error; null [assemble] = not available (the answer says so). */
    fun verifyEdit(type: String, original: String, modified: String, appPkg: String, entries: Collection<String>, assemble: ((String) -> String?)?): String {
        val sb = StringBuilder()
        val header = Regex("^\\.class[^\\n]*?(L[^;\\s]+;)", RegexOption.MULTILINE).find(modified)?.groupValues?.get(1)
        if (header == null) return "INVALID: the edit has no .class line."
        if (header != type) return "INVALID: the edit declares $header, not $type (a class cannot be renamed by an edit)."
        val opens = Regex("^\\s*\\.method ", RegexOption.MULTILINE).findAll(modified).count()
        val closes = Regex("^\\s*\\.end method", RegexOption.MULTILINE).findAll(modified).count()
        if (opens != closes) return "INVALID: $opens .method lines but $closes .end method lines."
        val asm = try { assemble?.invoke(modified) } catch (t: Throwable) { "assembler failed: " + (t.message ?: t.javaClass.simpleName) }
        if (assemble != null && asm != null) return "INVALID: the smali assembler rejects the edit:\n" + asm.take(1500)
        sb.append(if (assemble == null) "Structure OK (the assembler was not available: run build to be sure).\n" else "VALID: the edit assembles.\n")
        val before = keys(type, original, appPkg, entries); val after = keys(type, modified, appPkg, entries)
        val removed = before.keys - after.keys; val added = after.keys - before.keys; val kept = before.keys.intersect(after.keys)
        sb.append("Findings of this class: ${before.size} before, ${after.size} after.\n")
        sb.append("Removed by the edit (${removed.size}):\n"); for (k in removed) sb.append("  - ").append(before.getValue(k)).append('\n')
        sb.append("NEW with the edit (${added.size}):\n"); for (k in added) sb.append("  + ").append(after.getValue(k)).append('\n')
        sb.append("Unchanged (${kept.size}):\n"); for (k in kept.take(20)) sb.append("  = ").append(after.getValue(k)).append('\n')
        sb.append("Only this class was analysed (its rules and its own data flows); a flow through other classes is checked by a new Deep scan after build.")
        return sb.toString()
    }

    /** rule|title -> "[SEV] title (rule)" for the rule findings and the single-class SSA flows of one class text. */
    private fun keys(type: String, text: String, appPkg: String, entries: Collection<String>): LinkedHashMap<String, String> {
        val out = LinkedHashMap<String, String>()
        for (f in SecurityScanner.scanSmali(type, 0, text, appPkg)) out[f.ruleId + "|" + f.title] = "[${f.severity}] ${f.title} (${f.ruleId})"
        try {
            val c = dev.apkrelab.ir.SmaliParser.parse(text)
            for (it in dev.apkrelab.ir.SsaBridge.newFlows(listOf(c), entries.ifEmpty { listOf(type) }, emptyList()))
                out["ssa|" + it.title + "|" + it.method] = "[${it.sev}] ${it.title} (SSA flow in ${it.method.substringAfter("->").substringBefore('(')})"
        } catch (_: Throwable) { }
        return out
    }

    /** [family] = the SDK the last Deep scan attributed this class to (null = none or not scanned); [scanned] = whether a Deep scan ran. */
    fun classify(type: String, text: String, appPkg: String, family: String?, scanned: Boolean): String {
        val sb = StringBuilder()
        val root = type.indexOf('/') < 0
        val sup = Regex("^\\.super (L[^;\\s]+;)", RegexOption.MULTILINE).find(text)?.groupValues?.get(1) ?: "?"
        val ifaces = Regex("^\\.implements (L[^;\\s]+;)", RegexOption.MULTILINE).findAll(text).map { it.groupValues[1] }.toList()
        val methods = Regex("^\\.method ([^\\n]*)$", RegexOption.MULTILINE).findAll(text).map { it.groupValues[1] }.toList()
        val statics = methods.count { it.contains(" static ") || it.startsWith("static ") }
        val instFields = Regex("^\\.field (?![^\\n]*\\bstatic\\b)", RegexOption.MULTILINE).findAll(text).count()
        sb.append("${type.removePrefix("L").removeSuffix(";").replace('/', '.')}: extends ${sup.removePrefix("L").removeSuffix(";")}")
        if (ifaces.isNotEmpty()) sb.append(", implements ").append(ifaces.joinToString(", ") { it.removePrefix("L").removeSuffix(";") })
        sb.append("; ${methods.size} methods (${statics} static), $instFields instance fields, ${text.count { it == '\n' }} lines.\n")
        sb.append(if (root) "Renamed by R8 into the root package (no package name left).\n" else "")
        // R8 merging
        val disc = discriminator.find(text)?.value
        if (disc != null) sb.append("R8 HORIZONTAL MERGE: ${disc.trim()} is a class-id field (a constructor switch picks which original class an object is): several classes share this one, their fields (often Object-typed) are shared too. A data flow through such a field can join unrelated code.\n")
        if (statics >= SdkAttribution.STATIC_HOLDER_MIN && instFields == 0 && statics == methods.size) sb.append("R8 STATIC MERGE likely: $statics static methods and no instance state: unrelated static helpers (possibly from several libraries and the app) can live in one such class.\n")
        // attribution
        when {
            family != null -> sb.append("SDK: the last Deep scan attributed it to $family (the only classes naming it belong to that library); its findings are shown with the libraries.\n")
            !scanned -> sb.append("SDK attribution: not known yet (run scan_security with mode deep; it compares who names every renamed class).\n")
            root -> sb.append("SDK attribution: none (named by the app, by several libraries, by unattributed renamed classes, or merged): it may be the app's own code.\n")
        }
        // what its code names
        val appPrefix = appPkg.split('.').let { if (it.size >= 2) "L" + it[0] + "/" + it[1] + "/" else "L$appPkg/" }
        val fams = HashMap<String, Int>(); var app = 0; var renamed = 0
        for (m in typeRef.findAll(text)) {
            val t = m.value
            if (t == type) continue
            if (appPkg.isNotEmpty() && t.startsWith(appPrefix)) { app++; continue }
            if (t.indexOf('/') < 0) { renamed++; continue }
            if (t.startsWith("Ljava/") || t.startsWith("Ljavax/") || t.startsWith("Landroid/") || t.startsWith("Lkotlin/") || t.startsWith("Ldalvik/")) continue
            SdkAttribution.family(t)?.let { fams[it] = (fams[it] ?: 0) + 1 }
        }
        val top = fams.entries.sortedByDescending { it.value }.take(5)
        sb.append("Its code names: ")
        sb.append(if (top.isEmpty()) "no library package" else top.joinToString(", ") { "${it.key} (${it.value})" })
        sb.append("; the app's package ${app}x; renamed classes ${renamed}x.")
        if (app > 0) sb.append(" Naming the app's own package is strong evidence of app code (or of a merge with it).")
        return sb.toString()
    }
}
