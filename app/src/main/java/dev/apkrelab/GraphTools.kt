package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding

/**
 * 0.103.0: what the AI agent can ask the scanner's own graph, as plain text, with no AI in the answer: who calls a method (the reverse call index the Deep scan built), what a
 * method calls (its invoke instructions), and how one finding got its reach / data path (the entry chain and the SSA source -> sink path the scan already computed).
 * All functions are pure (smali text and index in, text out) so they are tested without a device; MainActivity only resolves class names and feeds the text.
 *
 * Honest limits, printed in the answers: the reverse index is keyed by a hash of "Lcls;->name(desc)ret" (a collision is possible and not checked), it holds direct invoke
 * edges plus a few synthetic ones (component launches), not the virtual-dispatch targets the SSA engine resolves; callees are the textual invokes of the method.
 */
object GraphTools {
    /** "name(desc)ret" signatures of the methods called [name] in the class text (a [name] that already holds "(" must match the whole signature). */
    fun signatures(text: String, name: String): List<String> {
        val out = ArrayList<String>()
        val n = name.trim()
        if (n.isEmpty()) return out
        for (ln in text.lineSequence()) {
            val t = ln.trim()
            if (!t.startsWith(".method ")) continue
            val sig = t.substringAfterLast(' ')
            if (if (n.contains('(')) sig == n else sig.startsWith("$n(")) out.add(sig)
        }
        return out
    }

    /** The "name(desc)ret" of the method of [classType] whose key hash is [hash] (what the call index stores for a caller), or null. */
    fun methodByHash(classType: String, text: String, hash: Int): String? {
        for (ln in text.lineSequence()) {
            val t = ln.trim()
            if (!t.startsWith(".method ")) continue
            val sig = t.substringAfterLast(' ')
            if ((classType + "->" + sig).hashCode() == hash) return sig
        }
        return null
    }

    class Callee(val target: String, val kind: String, var count: Int) {
        val owner: String get() = target.substringBefore("->")
        val name: String get() = target.substringAfter("->")
    }

    /** The invokes inside the method [sig] of the class text, one entry per distinct target (with a count), in order of first appearance. */
    fun callees(text: String, sig: String): List<Callee> {
        val out = LinkedHashMap<String, Callee>()
        var inM = false
        for (ln in text.lineSequence()) {
            val t = ln.trim()
            if (!inM) { if (t.startsWith(".method ") && t.substringAfterLast(' ') == sig) inM = true; continue }
            if (t.startsWith(".end method")) break
            if (!t.startsWith("invoke-")) continue
            val i = t.indexOf("}, ")
            if (i < 0) continue
            val target = t.substring(i + 3).trim()
            val kind = t.substringBefore(' ').removePrefix("invoke-").substringBefore('/')
            val c = out[target]
            if (c == null) out[target] = Callee(target, kind, 1) else c.count++
        }
        return out.values.toList()
    }

    private fun short(type: String) = type.removePrefix("L").removeSuffix(";").replace('/', '.')

    private fun isFramework(owner: String) = listOf("Landroid/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/", "Ldalvik/", "Landroidx/").any { owner.startsWith(it) }

    /** The answer of the `callees` tool. [isApp] tells a type of the app's own classes from framework / library calls. */
    fun renderCallees(classType: String, sig: String, list: List<Callee>, isApp: (String) -> Boolean, limit: Int): String {
        if (list.isEmpty()) return "${short(classType)}.$sig makes no invoke calls (or it is abstract / native)."
        val app = list.filter { isApp(it.owner) }
        val fw = list.filter { !isApp(it.owner) && isFramework(it.owner) }
        val lib = list.filter { !isApp(it.owner) && !isFramework(it.owner) }
        val sb = StringBuilder("${short(classType)}.$sig calls ${list.size} distinct method(s): ${app.size} in the app, ${lib.size} in libraries, ${fw.size} in the framework.\n")
        fun section(title: String, l: List<Callee>) {
            if (l.isEmpty()) return
            sb.append(title).append('\n')
            for (c in l.take(limit)) sb.append("  ").append(short(c.owner)).append('.').append(c.name).append("  [").append(c.kind).append(if (c.count > 1) " x${c.count}" else "").append("]\n")
            if (l.size > limit) sb.append("  ... ").append(l.size - limit).append(" more\n")
        }
        section("App code:", app); section("Libraries:", lib); section("Framework:", fw)
        return sb.toString().trimEnd()
    }

    /**
     * The answer of the `callers` tool: [callerRefs] come from CallIndex.callersOf(hash of "Lcls;->sig"); [describe] turns one reference (class index in the high 32 bits, method
     * hash in the low 32) into "pkg.Class.method(desc)" or null.
     */
    fun renderCallers(classType: String, sig: String, callerRefs: List<Long>, describe: (Long) -> String?, limit: Int): String {
        val refs = callerRefs.distinct()
        val names = refs.take(limit).mapNotNull { describe(it) }.distinct().sorted()
        if (names.isEmpty()) return "No caller of ${short(classType)}.$sig was found in the call index built by the Deep scan. It may be called only through an interface / virtual dispatch (the index holds direct invoke edges), reflection, the framework (a lifecycle method, a click handler) or a manifest entry; use `entry_points` for the exported components."
        val sb = StringBuilder("${refs.size} calling method(s) of ${short(classType)}.$sig (direct invokes seen by the Deep scan)" + (if (refs.size > limit) ", the first $limit shown" else "") + ":\n")
        for (n in names) sb.append("  ").append(n).append('\n')
        return sb.toString().trimEnd()
    }

    /** The answer of the `flow_path` tool for one finding: where it is, how it is reached, and the data path the SSA engine found. [no] = its number in the findings list. */
    fun flowPath(f: Finding, no: Int, method: String?): String = flowPath(f, "#$no", method)

    /** [card] = the card number as the report and get_findings print it ("#12", "#L3"). */
    fun flowPath(f: Finding, card: String, method: String?): String {
        val sb = StringBuilder("Finding $card [${f.severity.label}] ${f.title}\n")
        sb.append("Where: ").append(f.location).append(if (method != null) " in $method" else "").append('\n')
        if (f.ruleId.isNotEmpty()) sb.append("Rule: ").append(f.ruleId).append(if (f.confidence.isNotEmpty()) " (confidence " + f.confidence + ")" else "").append('\n')
        if (f.adjusted.isNotEmpty()) sb.append("Severity adjusted: ").append(f.adjusted).append('\n')
        if (f.dataPath.isNotEmpty()) {
            sb.append("Data path (SSA taint, source -> sink): ").append(f.dataPath).append('\n')
            if (f.sourceMethod.isNotEmpty()) sb.append("Source value first held in: ").append(f.sourceMethod).append('\n')
        } else sb.append("Data path: none recorded (this finding comes from a pattern rule, not from a taint flow).\n")
        sb.append("Reachability: ").append(when (f.reach) {
            "YES" -> "reachable from an exported component\n" + f.chain
            "YES~" -> "approximately reachable (class-level path)\n" + f.chain
            "NO" -> "no path from an exported component was found (the call graph is partial for big apps and does not model every framework callback)"
            else -> "not traced yet (run scan_security with mode deep)"
        }).append('\n')
        if (f.verdict.isNotEmpty()) sb.append("AI verdict: ").append(f.verdict).append(' ').append(f.verdictNote.take(160)).append('\n')
        return sb.toString().trimEnd()
    }

    /**
     * 1.1.0: the card number of position [i] (0-based) of the agent's list: the first [reported] entries are the report's cards in the report's order ("#12" is card 12 of
     * the exported report), the others (library code, INFO) are "#L1", "#L2" ...
     */
    fun cardLabel(i: Int, reported: Int): String = if (i < reported) "#${i + 1}" else "#L${i - reported + 1}"

    /**
     * The finding for a tool argument: a card number ("12", "#12", "#L3", see [cardLabel]), or a part of the title / location. Returns the 1-based position in [list].
     * [reported] = how many leading entries carry report numbers (all of them by default).
     */
    fun pick(list: List<Finding>, query: String, reported: Int = list.size): Pair<Int, Finding>? {
        val q = query.trim()
        if (q.isEmpty()) return null
        val num = q.removePrefix("#")
        if (num.startsWith("L") || num.startsWith("l")) num.substring(1).toIntOrNull()?.let { n -> val i = reported + n - 1; return if (n >= 1 && i < list.size) (i + 1) to list[i] else null }
        num.toIntOrNull()?.let { n -> return if (n in 1..minOf(reported, list.size)) n to list[n - 1] else null }
        val low = q.lowercase()
        val i = list.indexOfFirst { it.title.lowercase().contains(low) || it.location.lowercase().contains(low) }
        return if (i < 0) null else (i + 1) to list[i]
    }
}
