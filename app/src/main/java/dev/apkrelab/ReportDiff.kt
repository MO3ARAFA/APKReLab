package dev.apkrelab

import dev.apkrelab.ScanCompare.Entry
import dev.apkrelab.ScanCompare.Snapshot

/**
 * 2.2 (session 1): the same Before / After comparison as [ScanCompare], but between two scan REPORTS (the Markdown the app and the
 * sandbox write), plus what a report carries that a Finding list does not: the MUST FIX list, the exported components, the permission
 * list, the deep links and (when the report text has them) the SDK levels.
 *
 * Provenance: the finding comparison is NOT new. [ScanCompare.diff] (0.71.0) does it and is reused as is, so the statuses keep ScanCompare's
 * names (NEW / FIXED / WORSE / BETTER / CHANGED / SAME) and its wording: "Fixed" means "the scanner no longer reports it", never "the weakness is gone".
 * What is new here: reading a report back into a [Snapshot], the MUST FIX delta and the manifest delta, and the `diff_scans` agent tool.
 *
 * Rules that keep it honest:
 *  - Deterministic text only. The AI verdict is not read (not stable between runs, same reason as [ScanCompare]).
 *  - Key = rule + title + location, the key [ScanCompare.keyOf] already uses. The card number is never part of a key (it moves with every scan);
 *    the MUST FIX list is mapped from card number to that key inside ONE report.
 *  - A section the report does not carry is "not in this report", never an empty set: a missing Attack surface is not "every component removed".
 *  - Pure Kotlin, no Android classes, no org.json: runs in the sandbox tests.
 */
object ReportDiff {

    /** Switch for the mutation checks: false = the finding comparison is skipped (everything reads as unchanged). */
    internal var COMPARE_KEYS = true
    /** Switch for the mutation checks: false = the manifest delta is empty. */
    internal var MANIFEST_DELTA = true
    /** Switch for the mutation checks: false = a permission that disappeared is not reported. */
    internal var REPORT_REMOVED = true

    /** One exported component row of the Attack surface table. */
    class Comp(val kind: String, val name: String, val actions: String, val protection: String) {
        val key: String get() = "$kind $name"
    }

    class Parsed(
        val package_: String,
        val snapshot: Snapshot,
        /** Entry keys of the MUST FIX cards; null = the report has no MUST FIX line at all (not "empty"). */
        val mustFix: Set<String>?,
        /** null = the report has no Attack surface section. */
        val components: List<Comp>?,
        val permissions: Set<String>?,
        val deepLinks: Set<String>?,
        val targetSdk: String?,
        val minSdk: String?
    )

    class Delta<T>(val added: List<T>, val removed: List<T>)

    class Result(
        val before: Parsed,
        val after: Parsed,
        val diff: ScanCompare.Diff,
        /** MUST FIX cards (by key) only in the new report / only in the old one; null when either report has no MUST FIX line. */
        val mustFix: Delta<Entry>?,
        val components: Delta<Comp>?,
        /** A component present in both whose protection changed: (old, new). */
        val protectionChanged: List<Pair<Comp, Comp>>,
        val permissions: Delta<String>?,
        val deepLinks: Delta<String>?,
        val sdkChanges: List<String>
    ) {
        val manifestChanged: Boolean
            get() = (components?.let { it.added.isNotEmpty() || it.removed.isNotEmpty() } ?: false) || protectionChanged.isNotEmpty() ||
                (permissions?.let { it.added.isNotEmpty() || it.removed.isNotEmpty() } ?: false) ||
                (deepLinks?.let { it.added.isNotEmpty() || it.removed.isNotEmpty() } ?: false) || sdkChanges.isNotEmpty()
    }

    // ---------------------------------------------------------------- parsing

    private val CARD = Regex("""^#### (\d+)\. \[(CRITICAL|HIGH|MEDIUM|LOW|INFO)] (.*)$""")
    private val LOC = Regex("""^- Location: `?(.*?)`?\s*$""")
    private val RULE = Regex("""\bRule: ([\w\-*.]+)""")
    private val CWE = Regex("""^- CWE: (CWE-\d+|-|n/a)""")
    private val CONF = Regex("""\bConfidence: (HIGH|MEDIUM|LOW)\b""")
    private val PRIO = Regex("""^- Priority: (\d+)/100""")
    private val MUST = Regex("""#(\d+) \[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)] """)
    private val TITLE_PKG = Regex("""^# APK ReLab report: (\S+)""")
    private val TARGET = Regex("""targetSdkVersion\s*=\s*"(\d+)"""")
    private val MIN = Regex("""minSdkVersion\s*=\s*"(\d+)"""")

    /** Reads a report back. Never throws on odd text: unknown lines are skipped, a report with no cards gives an empty snapshot. */
    fun parse(report: String): Parsed {
        val lines = report.split('\n')
        var pkg = ""
        // ---- cards
        class Card(val no: Int, val sev: String, val title: String) {
            var loc = ""; var rule = ""; var cwe = ""; var conf = ""; var score = 0
        }
        val cards = ArrayList<Card>()
        var cur: Card? = null
        var section = ""
        val mustLines = ArrayList<String>()
        var mustSeen = false
        var inMust = false
        val compRows = ArrayList<Comp>()
        var compSeen = false
        var perms: Set<String>? = null
        val links = LinkedHashSet<String>()
        var linksSeen = false
        for (raw in lines) {
            val line = raw.trimEnd('\r')
            if (pkg.isEmpty()) TITLE_PKG.find(line)?.let { pkg = it.groupValues[1] }
            if (line.startsWith("## ")) { section = line.removePrefix("## ").trim(); cur = null; inMust = false
                if (section == "Attack surface") compSeen = true
                if (section == "Deep links") linksSeen = true }
            else if (line.startsWith("### ") && section == "Security scan") { cur = null }
            val m = CARD.find(line)
            if (m != null) { cur = Card(m.groupValues[1].toInt(), m.groupValues[2], m.groupValues[3].trim()).also { cards.add(it) }; inMust = false; continue }
            // MUST FIX block of the Verdict: "- **MUST FIX:**" then indented bullets until the next top-level bullet
            if (line.startsWith("- **MUST FIX:**")) {
                mustSeen = true; inMust = true
                if (MUST.containsMatchIn(line)) mustLines.add(line)
                continue
            }
            if (inMust) {
                if (line.startsWith("- **") || line.startsWith("## ")) inMust = false
                else if (MUST.containsMatchIn(line)) mustLines.add(line)
            }
            val c = cur
            if (c != null) {
                LOC.find(line)?.let { if (c.loc.isEmpty()) c.loc = it.groupValues[1] }
                if (line.startsWith("- CWE:")) {
                    CWE.find(line)?.let { c.cwe = it.groupValues[1] }
                    RULE.find(line)?.let { c.rule = it.groupValues[1] }
                    CONF.find(line)?.let { c.conf = it.groupValues[1] }
                }
                PRIO.find(line)?.let { c.score = it.groupValues[1].toInt() }
            }
            if (section == "Attack surface") {
                if (line.startsWith("| `")) {
                    val cells = splitRow(line)
                    if (cells.size >= 4) compRows.add(Comp(cells[1].trim(), cells[0].trim().trim('`'), cells[2].trim(), cells[3].trim()))
                } else if (line.startsWith("**Permissions:**")) {
                    perms = line.removePrefix("**Permissions:**").split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSortedSet()
                }
            }
            if (section == "Deep links" && line.startsWith("| ") && !line.startsWith("|---") && !line.startsWith("| Links accepted")) {
                val cells = splitRow(line)
                if (cells.size >= 2) {
                    val act = cells[1].trim().trim('`')
                    for (l in Regex("`([^`]+)`").findAll(cells[0])) links.add(act + " <- " + l.groupValues[1])
                }
            }
        }
        // a report with a permission line but no components table is still an Attack surface section
        if (compSeen && perms == null) perms = emptySet()
        // ---- snapshot (same merge rule as ScanCompare.snapshot: worst severity, counts added)
        val byKey = LinkedHashMap<String, Entry>()
        val keyOfCard = HashMap<Int, String>()
        for (c in cards) {
            val key = c.rule + "|" + c.title + "|" + c.loc
            keyOfCard[c.no] = key
            if (c.sev == "INFO") continue
            val old = byKey[key]
            byKey[key] = if (old == null) Entry(key, c.rule, c.title, c.loc, c.sev, c.conf, c.cwe, 1, c.score)
            else Entry(key, c.rule, c.title, c.loc,
                if (ScanCompare.rankOf(c.sev) < old.rank) c.sev else old.severity, if (c.score > old.score) c.conf else old.confidence,
                old.cwe.ifEmpty { c.cwe }, old.count + 1, maxOf(old.score, c.score))
        }
        val snap = Snapshot(pkg, "", "", 0L, byKey.values.toList())
        val must: Set<String>? = if (!mustSeen) null else mustLines.flatMap { l -> MUST.findAll(l).map { it.groupValues[1].toInt() }.toList() }
            .mapNotNull { keyOfCard[it] }.toCollection(LinkedHashSet())
        return Parsed(
            pkg, snap, must, if (compSeen) compRows else null, perms, if (linksSeen) links else null,
            TARGET.find(report)?.groupValues?.get(1), MIN.find(report)?.groupValues?.get(1)
        )
    }

    /** Cells of a Markdown table row; "|" inside backticks is kept. */
    private fun splitRow(line: String): List<String> {
        val out = ArrayList<String>(); val sb = StringBuilder(); var tick = false
        val body = line.trim().removePrefix("|").removeSuffix("|")
        for (ch in body) {
            if (ch == '`') tick = !tick
            if (ch == '|' && !tick) { out.add(sb.toString()); sb.setLength(0) } else sb.append(ch)
        }
        out.add(sb.toString())
        return out
    }

    // ---------------------------------------------------------------- diff

    fun diff(oldReport: String, newReport: String, oldLabel: String = "old report", newLabel: String = "new report"): Result {
        val a = parse(oldReport); val b = parse(newReport)
        val sa = Snapshot(a.package_, "", oldLabel, 0L, a.snapshot.entries)
        val sb = Snapshot(b.package_, "", newLabel, 0L, b.snapshot.entries)
        val d = if (COMPARE_KEYS) ScanCompare.diff(sa, sb) else ScanCompare.diff(sa, sa.let { Snapshot(it.pkg, it.version, newLabel, 0L, it.entries) })

        val mf: Delta<Entry>? = if (a.mustFix == null || b.mustFix == null) null else {
            val byKeyB = b.snapshot.entries.associateBy { it.key }; val byKeyA = a.snapshot.entries.associateBy { it.key }
            Delta(b.mustFix.minus(a.mustFix).mapNotNull { byKeyB[it] }, a.mustFix.minus(b.mustFix).mapNotNull { byKeyA[it] })
        }
        var compDelta: Delta<Comp>? = null
        var protChanged: List<Pair<Comp, Comp>> = emptyList()
        var permDelta: Delta<String>? = null
        var linkDelta: Delta<String>? = null
        val sdk = ArrayList<String>()
        if (MANIFEST_DELTA) {
            if (a.components != null && b.components != null) {
                val ka = a.components.associateBy { it.key }; val kb = b.components.associateBy { it.key }
                compDelta = Delta(b.components.filter { it.key !in ka }.distinctBy { it.key }, if (REPORT_REMOVED) a.components.filter { it.key !in kb }.distinctBy { it.key } else emptyList())
                protChanged = b.components.filter { ka[it.key] != null && ka[it.key]!!.protection != it.protection }.distinctBy { it.key }.map { ka[it.key]!! to it }
            }
            if (a.permissions != null && b.permissions != null)
                permDelta = Delta(b.permissions.minus(a.permissions).sorted(), if (REPORT_REMOVED) a.permissions.minus(b.permissions).sorted() else emptyList())
            if (a.deepLinks != null && b.deepLinks != null)
                linkDelta = Delta(b.deepLinks.minus(a.deepLinks).sorted(), if (REPORT_REMOVED) a.deepLinks.minus(b.deepLinks).sorted() else emptyList())
            if (a.targetSdk != null && b.targetSdk != null && a.targetSdk != b.targetSdk) sdk.add("targetSdk ${a.targetSdk} -> ${b.targetSdk}")
            if (a.minSdk != null && b.minSdk != null && a.minSdk != b.minSdk) sdk.add("minSdk ${a.minSdk} -> ${b.minSdk}")
        }
        return Result(a, b, d, mf, compDelta, protChanged, permDelta, linkDelta, sdk)
    }

    // ---------------------------------------------------------------- text

    fun markdown(r: Result, maxList: Int = 40): String {
        val sb = StringBuilder()
        sb.append(ScanCompare.markdown(r.diff).trimEnd()).append("\n\n")
        sb.append("## MUST FIX delta\n\n")
        val m = r.mustFix
        if (m == null) sb.append("Not comparable: at least one report has no MUST FIX line.\n\n")
        else if (m.added.isEmpty() && m.removed.isEmpty()) sb.append("No change (").append(r.after.mustFix?.size ?: 0).append(" card(s) in MUST FIX in the new report).\n\n")
        else {
            for (e in m.added.take(maxList)) sb.append("- NEW in MUST FIX: [").append(e.severity).append("] ").append(e.title).append(" - `").append(e.location).append("`\n")
            for (e in m.removed.take(maxList)) sb.append("- LEFT MUST FIX: [").append(e.severity).append("] ").append(e.title).append(" - `").append(e.location).append("`\n")
            sb.append("\n")
        }
        sb.append("## Manifest attack-surface delta\n\n")
        if (r.components == null && r.permissions == null && r.deepLinks == null && r.sdkChanges.isEmpty())
            sb.append("Not comparable: the two reports do not both carry an Attack surface or Deep links section.\n")
        else if (!r.manifestChanged) sb.append("No change in exported components, permissions or deep links.\n")
        else {
            fun <T> lines(title: String, d: Delta<T>?, txt: (T) -> String) {
                if (d == null) return
                for (x in d.added.take(maxList)) sb.append("- ").append(title).append(" added: ").append(txt(x)).append("\n")
                if (d.added.size > maxList) sb.append("- ... ").append(d.added.size - maxList).append(" more added\n")
                for (x in d.removed.take(maxList)) sb.append("- ").append(title).append(" removed: ").append(txt(x)).append("\n")
                if (d.removed.size > maxList) sb.append("- ... ").append(d.removed.size - maxList).append(" more removed\n")
            }
            lines("exported component", r.components) { "`${it.name}` (${it.kind}, ${it.protection})" }
            for ((o, n) in r.protectionChanged) sb.append("- exported component protection changed: `").append(n.name).append("` ").append(o.protection).append(" -> ").append(n.protection).append("\n")
            lines("permission", r.permissions) { it }
            lines("deep link", r.deepLinks) { "`$it`" }
            for (s in r.sdkChanges) sb.append("- ").append(s).append("\n")
        }
        sb.append("\n_The report text is the only input: a section a report does not carry is not compared. SDK levels are read only when the report text shows them._\n")
        return sb.toString()
    }

    /** `diff_scans` for the agent and the sandbox: two report files. Returns "error: ..." text on problems, never throws. */
    fun diffFiles(oldPath: String, newPath: String, maxBytes: Long = 8L * 1024 * 1024): String {
        fun read(p: String): String? {
            val f = java.io.File(p)
            if (!f.isFile) return null
            if (f.length() > maxBytes) return ""
            return f.readText()
        }
        return try {
            val o = read(oldPath) ?: return "error: not a file: $oldPath"
            val n = read(newPath) ?: return "error: not a file: $newPath"
            if (o.isEmpty() || n.isEmpty()) return "error: a report is empty or larger than ${maxBytes / (1024 * 1024)} MB"
            if (!o.contains("# APK ReLab report") || !n.contains("# APK ReLab report")) return "error: not an APK ReLab Markdown report (first line must be '# APK ReLab report: <package>')"
            markdown(diff(o, n, java.io.File(oldPath).name, java.io.File(newPath).name))
        } catch (t: Throwable) {
            "error: " + (t.message ?: t.javaClass.simpleName)
        }
    }
}
