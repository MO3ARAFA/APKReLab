package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Scope
import dev.apkrelab.SecurityScanner.Severity
import org.json.JSONArray
import org.json.JSONObject

/**
 * 0.71.0: Before / After compare. A [Snapshot] is a small, stable copy of a scan result; [diff] tells what an edit (a fix, a rebuild,
 * a new app version) changed: which findings are gone, which are new, which got worse or better.
 *
 * Rules that keep the comparison honest:
 *  - Only what a scan itself decides is compared: rule, title, location, severity, confidence, count. The AI verdict is NOT used
 *    (not stable between runs, same reason as FindingScore) and a finding the AI called FP is still a finding here.
 *  - INFO and library findings are left out, like the report does ([ReportBuilder.reportable]).
 *  - A finding is identified by rule + title + location (never the char offset `at`, it moves with every edit).
 *  - If a finding has the same rule and location but a different title (the title carries a value that changed), it is matched as
 *    "changed", not as one fixed + one new.
 *  - "Fixed" means "the scanner no longer reports it". It is not a proof that the weakness is gone (see [Diff.note]).
 * Pure Kotlin + org.json: no Android classes, so it runs in the sandbox tests.
 */
object ScanCompare {

    const val FORMAT = 1

    class Entry(
        val key: String,
        val ruleId: String,
        val title: String,
        val location: String,
        val severity: String,      // Severity.label
        val confidence: String,
        val cwe: String,
        val count: Int,
        val score: Int
    ) {
        val rank: Int get() = rankOf(severity)
    }

    class Snapshot(val pkg: String, val version: String, val label: String, val savedAt: Long, val entries: List<Entry>) {
        val totalScore: Int get() = entries.sumOf { it.score }
    }

    enum class Status { FIXED, NEW, WORSE, BETTER, CHANGED, SAME }

    class Change(val status: Status, val before: Entry?, val after: Entry?) {
        val title: String get() = (after ?: before)!!.title
        val location: String get() = (after ?: before)!!.location
    }

    class Diff(val before: Snapshot, val after: Snapshot, val changes: List<Change>) {
        fun of(s: Status): List<Change> = changes.filter { it.status == s }
        val fixed: List<Change> get() = of(Status.FIXED)
        val added: List<Change> get() = of(Status.NEW)
        val worse: List<Change> get() = of(Status.WORSE)
        val better: List<Change> get() = of(Status.BETTER)
        val same: List<Change> get() = of(Status.SAME)
        val scoreDelta: Int get() = after.totalScore - before.totalScore

        /** IMPROVED / REGRESSED / NO CHANGE. A new or worse finding decides it, a pure refactor with the same findings is NO CHANGE. */
        val verdict: String get() = when {
            added.isNotEmpty() || worse.isNotEmpty() -> if (scoreDelta > 0 || fixed.isEmpty()) "REGRESSED" else "MIXED"
            fixed.isNotEmpty() || better.isNotEmpty() -> "IMPROVED"
            else -> "NO CHANGE"
        }

        val note: String =
            "\"Fixed\" means the scanner no longer reports the finding. It does not prove the weakness is gone: a rewrite can hide the " +
                "pattern from a heuristic scan. Open the changed code and check it."

        fun summary(): String =
            "${fixed.size} fixed, ${added.size} new, ${worse.size} worse, ${better.size} better, ${same.size} unchanged " +
                "(priority total ${before.totalScore} -> ${after.totalScore}, ${if (scoreDelta > 0) "+" else ""}$scoreDelta)"
    }

    fun rankOf(label: String): Int = Severity.values().firstOrNull { it.label == label }?.rank ?: Severity.INFO.rank

    /** Findings that count for a comparison: not INFO, not library code. Same filter as the report. */
    fun comparable(all: List<Finding>): List<Finding> =
        all.filter { it.severity != Severity.INFO && it.scope != Scope.LIB }

    fun keyOf(f: Finding): String = f.ruleId + "|" + f.title + "|" + f.location

    fun snapshot(pkg: String, version: String, label: String, savedAt: Long, all: List<Finding>): Snapshot {
        // same key twice (two findings of one rule in one class): keep the worst severity and add the counts
        val byKey = LinkedHashMap<String, Entry>()
        for (f in comparable(all)) {
            val k = keyOf(f)
            val score = FindingScore.of(f).value
            val conf = FindingPolish.confidenceOf(f)
            val old = byKey[k]
            byKey[k] = if (old == null) Entry(k, f.ruleId, f.title, f.location, f.severity.label, conf, f.cwe, f.count, score)
            else Entry(
                k, f.ruleId, f.title, f.location,
                if (f.severity.rank < old.rank) f.severity.label else old.severity,
                if (score > old.score) conf else old.confidence,
                old.cwe.ifEmpty { f.cwe }, old.count + f.count, maxOf(old.score, score)
            )
        }
        return Snapshot(pkg, version, label, savedAt, byKey.values.toList())
    }

    fun diff(before: Snapshot, after: Snapshot): Diff {
        val out = ArrayList<Change>()
        val afterLeft = LinkedHashMap<String, Entry>().apply { after.entries.forEach { put(it.key, it) } }
        val beforeOnly = ArrayList<Entry>()

        for (b in before.entries) {
            val a = afterLeft.remove(b.key)
            if (a == null) beforeOnly.add(b) else out.add(Change(classify(b, a), b, a))
        }
        // second pass: same rule + same location, different title = the same weakness with a changed detail
        val iter = beforeOnly.iterator()
        while (iter.hasNext()) {
            val b = iter.next()
            if (b.ruleId.isEmpty()) continue
            val cand = afterLeft.values.firstOrNull { it.ruleId == b.ruleId && it.location == b.location && it.cwe == b.cwe }
            if (cand != null) {
                afterLeft.remove(cand.key)
                out.add(Change(if (classify(b, cand) == Status.SAME) Status.CHANGED else classify(b, cand), b, cand))
                iter.remove()
            }
        }
        for (b in beforeOnly) out.add(Change(Status.FIXED, b, null))
        for (a in afterLeft.values) out.add(Change(Status.NEW, null, a))

        // most important first inside the report: worst severity, then higher score
        val sorted = out.sortedWith(compareBy<Change>({ order(it.status) }, { (it.after ?: it.before)!!.rank }, { -(it.after ?: it.before)!!.score }))
        return Diff(before, after, sorted)
    }

    private fun order(s: Status) = when (s) { Status.NEW -> 0; Status.WORSE -> 1; Status.FIXED -> 2; Status.BETTER -> 3; Status.CHANGED -> 4; Status.SAME -> 5 }

    private fun classify(b: Entry, a: Entry): Status = when {
        a.rank < b.rank -> Status.WORSE            // lower rank number = more severe
        a.rank > b.rank -> Status.BETTER
        a.count > b.count -> Status.WORSE          // same severity but it now matches in more places
        a.count < b.count -> Status.BETTER
        else -> Status.SAME
    }

    // ---------- Markdown ----------

    fun markdown(d: Diff, maxSame: Int = 0): String {
        val sb = StringBuilder()
        sb.append("# Before / After\n\n")
        sb.append("**Result: ").append(d.verdict).append("**\n\n")
        sb.append(d.summary()).append("\n\n")
        sb.append("- Before: ").append(d.before.label.ifEmpty { "baseline" }).append(" (").append(d.before.entries.size).append(" findings)\n")
        sb.append("- After: ").append(d.after.label.ifEmpty { "current scan" }).append(" (").append(d.after.entries.size).append(" findings)\n\n")

        fun block(title: String, list: List<Change>, line: (Change) -> String) {
            if (list.isEmpty()) return
            sb.append("## ").append(title).append(" (").append(list.size).append(")\n\n")
            for (c in list) sb.append("- ").append(line(c)).append("\n")
            sb.append("\n")
        }
        block("New findings", d.added) { "[${it.after!!.severity}] ${it.title} - `${it.location}`" }
        block("Got worse", d.worse) { c -> "${c.title} - `${c.location}`: ${arrow(c.before!!, c.after!!)}" }
        block("Fixed", d.fixed) { "[${it.before!!.severity}] ${it.title} - `${it.location}`" }
        block("Got better", d.better) { c -> "${c.title} - `${c.location}`: ${arrow(c.before!!, c.after!!)}" }
        block("Same weakness, changed detail", d.of(Status.CHANGED)) { c -> "`${c.location}`: \"${c.before!!.title}\" -> \"${c.after!!.title}\"" }
        if (maxSame > 0) block("Unchanged", d.same.take(maxSame)) { "[${it.after!!.severity}] ${it.title} - `${it.location}`" }
        else if (d.same.isNotEmpty()) sb.append(d.same.size).append(" finding(s) unchanged (not listed).\n\n")
        sb.append("_").append(d.note).append("_\n")
        return sb.toString()
    }

    private fun arrow(b: Entry, a: Entry): String {
        val parts = ArrayList<String>()
        if (a.severity != b.severity) parts.add("${b.severity} -> ${a.severity}")
        if (a.count != b.count) parts.add("x${b.count} -> x${a.count}")
        return parts.joinToString(", ")
    }

    // ---------- JSON (stored next to the project, so the baseline survives closing the app) ----------

    fun toJson(s: Snapshot): String {
        val arr = JSONArray()
        for (e in s.entries) arr.put(
            JSONObject().put("rule", e.ruleId).put("title", e.title).put("loc", e.location).put("sev", e.severity)
                .put("conf", e.confidence).put("cwe", e.cwe).put("count", e.count).put("score", e.score)
        )
        return JSONObject().put("format", FORMAT).put("pkg", s.pkg).put("version", s.version).put("label", s.label)
            .put("savedAt", s.savedAt).put("findings", arr).toString()
    }

    /** null = not a snapshot this version understands (never throws: a damaged file just means "no baseline"). */
    fun fromJson(text: String): Snapshot? = try {
        val o = JSONObject(text)
        if (o.optInt("format", 0) != FORMAT) null
        else {
            val arr = o.getJSONArray("findings")
            val list = ArrayList<Entry>()
            for (i in 0 until arr.length()) {
                val j = arr.getJSONObject(i)
                val rule = j.optString("rule"); val title = j.getString("title"); val loc = j.getString("loc")
                list.add(Entry(rule + "|" + title + "|" + loc, rule, title, loc, j.optString("sev", "INFO"), j.optString("conf"),
                    j.optString("cwe"), j.optInt("count", 1), j.optInt("score", 0)))
            }
            Snapshot(o.optString("pkg"), o.optString("version"), o.optString("label"), o.optLong("savedAt", 0L), list)
        }
    } catch (_: Throwable) { null }
}
