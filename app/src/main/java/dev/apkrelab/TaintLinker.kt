package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * 0.49.0: cross-class taint (phase 3 of the scan-engine upgrade).
 *
 * The per-class engine ([TaintEngine.scan]) stops at the class border. This file adds a second, cheap stage:
 *  1. STAGE A (while every class is scanned, in the worker threads): [TaintEngine.summarize] runs the same register-level
 *     analysis once more with SYMBOLIC taints and writes a small summary per method ([XMethod]):
 *       - hits    : a symbolic value reaches a sink. Label "@P<n>" = the method's parameter slot n, "@R<callee>" = the
 *                   value RETURNED by a call to <callee>;
 *       - edges   : a tainted register (symbolic or a REAL source such as Intent.getData()) is passed to a call of the app's
 *                   own code (callee key + parameter slot);
 *       - rets    : labels that reach return-object (a real source, a parameter, or another callee's result).
 *  2. STAGE B ([TaintLinker.link], once, after all workers finished): no class text is read again. Summaries are chained:
 *       - direction 1: a REAL source goes into callee parameter n; the callee (or callees of callees, depth [MAX_DEPTH])
 *         sends parameter n to a sink  -> finding at the sink method;
 *       - direction 2: a sink in method M receives the result of callee C and C (transitively) returns a REAL source.
 *     Findings carry the rule id `taint-xclass`, use the same titles / CWEs as `taint-flow` and are absorbed by a
 *     `taint-flow` finding of the same class and title (SecurityScanner.dedupe), so nothing is reported twice.
 *
 * Limits (kept honest in the finding text): calls are matched by the exact owner class written in the invoke, so virtual
 * dispatch to a subclass / interface implementation, reflection, lambdas, fields of OTHER classes and data stored in
 * collections between calls are not followed; there is no path sensitivity. Confidence is never higher than MEDIUM.
 */
internal class XHit(
    val label: String, val api: String, val title: String, val sev: SecurityScanner.Severity, val cwe: String,
    val what: String, val fix: String, val inherent: String, val off: Int, val line: Int, val validation: Boolean
)

internal class XEdge(val label: String, val level: Int, val calleeKey: String, val calleeSlot: Int)

internal class XMethod(val classType: String, val clsIndex: Int, val key: String, val name: String) {
    val hits = ArrayList<XHit>()
    val edges = ArrayList<XEdge>()
    val rets = HashMap<String, Int>()
    val edgeKeys = HashSet<String>()
    fun isEmpty(): Boolean = hits.isEmpty() && edges.isEmpty() && rets.isEmpty()
}

/** Collects the summaries of ONE class during [TaintEngine.summarize]. */
internal class XRecorder(val classType: String, val clsIndex: Int, val text: String) {
    val methods = ArrayList<XMethod>()
    private var cur: XMethod? = null

    fun begin(key: String, name: String) {
        cur = XMethod(classType, clsIndex, classType + "->" + key, name)
    }

    fun end() {
        val c = cur
        cur = null
        if (c != null && !c.isEmpty()) methods.add(c)
    }

    fun edge(label: String, level: Int, calleeKey: String, slot: Int) {
        val c = cur ?: return
        if (c.edges.size >= 64) return
        if (c.edgeKeys.add(label + "|" + calleeKey + "|" + slot)) c.edges.add(XEdge(label, level, calleeKey, slot))
    }

    fun ret(label: String, level: Int) {
        val c = cur ?: return
        val old = c.rets[label]
        if (old == null || old < level) c.rets[label] = level
    }

    fun hit(label: String, api: String, title: String, sev: SecurityScanner.Severity, cwe: String, what: String, fix: String,
            inherent: String, off: Int, validation: Boolean) {
        val c = cur ?: return
        if (c.hits.size >= 16) return
        c.hits.add(XHit(label, api, title, sev, cwe, what, fix, inherent, off, SecurityScanner.lineNo(text, off), validation))
    }
}

internal class TaintLinker(private val appPkg: String) {

    private val methods = ConcurrentHashMap<String, XMethod>()
    private val edgeCount = AtomicInteger(0)

    private class Chain(val hit: XHit, val sinkM: XMethod, val path: List<XMethod>)

    /** Called by the worker threads (thread-safe). */
    fun add(list: List<XMethod>) {
        for (x in list) {
            if (edgeCount.get() > MAX_EDGES) x.edges.clear()
            edgeCount.addAndGet(x.edges.size)
            methods[x.key] = x
        }
    }

    private fun labelIs(label: String, want: String): Boolean = label == want || label.startsWith("$want ")

    private fun argOf(label: String): String = label.substring(2).substringBefore(' ')

    private fun chase(key: String, slot: Int, depth: Int, path: List<XMethod>, visited: HashSet<String>, out: MutableList<Chain>) {
        if (depth >= MAX_DEPTH || out.size >= 4) return
        val callee = methods[key] ?: return
        if (!visited.add(key + "#" + slot)) return
        val p = path + callee
        val want = "@P$slot"
        for (h in callee.hits) if (labelIs(h.label, want)) out.add(Chain(h, callee, p))
        for (e in callee.edges) if (labelIs(e.label, want)) chase(e.calleeKey, e.calleeSlot, depth + 1, p, visited, out)
    }

    /** The REAL source (label, level) that the method [key] returns, directly or through the result of another app method. */
    private fun retSource(key: String, depth: Int, visited: HashSet<String>): Pair<String, Int>? {
        if (depth > MAX_DEPTH || !visited.add(key)) return null
        val m = methods[key] ?: return null
        for ((lab, lv) in m.rets) if (!lab.startsWith("@")) return Pair(lab, lv)
        for (lab in m.rets.keys) {
            if (!lab.startsWith("@R")) continue
            val r = retSource(argOf(lab), depth + 1, visited)
            if (r != null) return r
        }
        return null
    }

    private fun shortName(x: XMethod): String =
        x.classType.removePrefix("L").removeSuffix(";").substringAfterLast('/').replace('$', '.') + "." + x.name + "()"

    private fun lowerOne(s: SecurityScanner.Severity): SecurityScanner.Severity {
        val next = minOf(SecurityScanner.Severity.INFO.rank, s.rank + 1)
        return SecurityScanner.Severity.values().first { it.rank == next }
    }

    private fun emit(out: MutableList<SecurityScanner.Finding>, seen: HashSet<String>, h: XHit, sm: XMethod,
                     srcLabel: String, srcLevel: Int, path: List<XMethod>) {
        val k = sm.clsIndex.toString() + "|" + h.off + "|" + h.title
        if (!seen.add(k)) return
        var conf = if (srcLevel >= 2 && path.size <= 3) "MEDIUM" else "LOW"
        if (h.inherent == "MEDIUM" || h.validation) conf = "LOW"
        var sev = h.sev
        if (conf == "LOW") sev = lowerOne(sev)
        val sb = StringBuilder()
        sb.append("Data from ").append(srcLabel).append(" in ").append(shortName(path.first()))
            .append(" crosses ").append(path.size - 1).append(" method call(s) between classes (")
            .append(path.joinToString(" -> ") { shortName(it) }).append(") and reaches ").append(h.api)
            .append("() in ").append(shortName(sm)).append(": ").append(h.what)
            .append(". Each hop is a per-method summary: calls are matched by the class named in the invoke (virtual / interface dispatch, lambdas, reflection and fields of other classes are not followed) and no sanitizer was seen on the way.")
        if (srcLabel.startsWith("Intent.")) sb.append(" An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.")
        if (h.validation) sb.append(" The sink method also contains validation-like calls (startsWith, matches, getHost, canonical path ...): verify that they really restrict this value.")
        sb.append("  (around line ").append(h.line).append(")")
        val f = SecurityScanner.Finding(sev, h.title, sb.toString(), h.fix, sm.classType, sm.clsIndex, h.off, h.cwe)
        f.ruleId = "taint-xclass"
        f.confidence = conf
        f.scope = SecurityScanner.scopeOf(sm.classType, appPkg)
        out.addAll(FindingPolish.apply(listOf(f), sm.classType))
    }

    /** Stage B. Call once, after every class has been summarised. Returns findings with rule id `taint-xclass`. */
    fun link(): List<SecurityScanner.Finding> {
        val out = ArrayList<SecurityScanner.Finding>()
        val seen = HashSet<String>()
        val all = methods.values.sortedWith(compareBy<XMethod>({ it.clsIndex }, { it.key }))
        for (xm in all) {
            if (out.size >= MAX_FINDINGS) break
            // direction 1: a real source leaves this method through a call, a callee chain sends it to a sink
            for (e in xm.edges) {
                if (e.label.startsWith("@") || e.label.startsWith("SharedPreferences.")) continue
                val found = ArrayList<Chain>()
                chase(e.calleeKey, e.calleeSlot, 0, listOf(xm), HashSet(), found)
                for (c in found) emit(out, seen, c.hit, c.sinkM, e.label, e.level, c.path)
            }
            // direction 2: this method sends the RESULT of a call to a sink and that call returns a real source
            for (h in xm.hits) {
                if (!h.label.startsWith("@R")) continue
                val ck = argOf(h.label)
                val rs = retSource(ck, 0, HashSet()) ?: continue
                if (rs.first.startsWith("SharedPreferences.")) continue
                val callee = methods[ck] ?: continue
                emit(out, seen, h, xm, rs.first, rs.second, listOf(callee, xm))
            }
        }
        return out
    }

    companion object {
        const val MAX_DEPTH = 4
        const val MAX_FINDINGS = 60
        const val MAX_EDGES = 150_000
    }
}
