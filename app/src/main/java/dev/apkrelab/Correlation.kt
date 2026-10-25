package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding

/**
 * 1.2.0: findings that share a root cause, so one fix can close several. Nodes are the reported cards of MEDIUM or worse; an edge joins two cards that share
 *  - the entry method the reach pass traced ("Entry: ..." of the call path),
 *  - the tainted field the detail names ("through field X"),
 *  - the class (two different rules in one class; same class + same title was already merged by dedupe; several sources ending in one sink of a class are linked
 *    by this edge and described by the shared sink).
 * Connected components of two or more cards are linked. The suggested fix comes from the strongest shared element (sink, then entry, then field, then class).
 * No AI and nothing new detected: every input is a field of the card.
 */
object Correlation {
    class Group(val cards: List<Int>, val kind: String, val element: String) {
        /** One line for each member card. [label] turns a card index into its report number. */
        fun line(label: (Int) -> String): String = "Related findings: " + cards.joinToString(", ") { label(it) } + ". Suggested fix: " + fix() + "."
        fun fix(): String = when (kind) {
            "sink" -> "validate the input at $element"
            "entry" -> "validate the Intent at $element"
            "field" -> "validate the value before it is stored in $element"
            else -> "review $element as a whole"
        }
    }

    /** 1.2.0: switch for the mutation check of the entry edge. */
    internal var ENTRY_EDGE = true

    private val fieldRe = Regex("through field ([A-Za-z0-9_$./]+\\.[A-Za-z0-9_$]+):")
    fun entryOf(f: Finding): String? = f.chain.lineSequence().firstOrNull { it.startsWith("Entry: ") }?.removePrefix("Entry: ")?.trim()?.takeIf { it.isNotEmpty() }
    private fun fieldOf(f: Finding): String? = fieldRe.find(f.detail)?.groupValues?.get(1)
    private fun cls(f: Finding) = f.classType?.removePrefix("L")?.removeSuffix(";")?.replace('/', '.')

    /** Groups over [cards] (the report's list, in its order); indices are positions in that list. */
    fun groups(cards: List<Finding>): List<Group> {
        val idx = cards.indices.filter { cards[it].severity.rank <= SecurityScanner.Severity.MEDIUM.rank }
        val parent = IntArray(cards.size) { it }
        fun find(x: Int): Int { var r = x; while (parent[r] != r) r = parent[r]; var y = x; while (parent[y] != r) { val n = parent[y]; parent[y] = r; y = n }; return r }
        fun union(a: Int, b: Int) { val ra = find(a); val rb = find(b); if (ra != rb) parent[maxOf(ra, rb)] = minOf(ra, rb) }
        // edges by shared key: every card with the same key joins the first one
        fun link(key: (Finding) -> String?) {
            val first = HashMap<String, Int>()
            for (i in idx) { val k = key(cards[i]) ?: continue; val f = first[k]; if (f == null) first[k] = i else union(f, i) }
        }
        if (ENTRY_EDGE) link { entryOf(it) }
        link { fieldOf(it) }
        link { cls(it) }
        val comps = idx.groupBy { find(it) }.values.filter { it.size >= 2 }
        return comps.map { members -> describe(members.sorted(), cards) }.sortedBy { it.cards.first() }
    }

    /** The strongest element every member shares (sink in one class, then entry, then field, then class); "mixed" when the members are only chained. */
    private fun describe(m: List<Int>, cards: List<Finding>): Group {
        fun allSame(key: (Finding) -> String?): String? { val ks = m.map { key(cards[it]) }; return if (ks.all { it != null && it == ks[0] }) ks[0] else null }
        allSame { f -> FixTemplates.sinkOf(f)?.let { s -> cls(f)?.let { "$it|$s" } } }?.let { return Group(m, "sink", it.substringAfter('|') + " in " + it.substringBefore('|').substringAfterLast('.')) }
        if (ENTRY_EDGE) allSame { entryOf(it) }?.let { return Group(m, "entry", it) }
        allSame { fieldOf(it) }?.let { return Group(m, "field", it) }
        allSame { cls(it) }?.let { return Group(m, "class", it) }
        return Group(m, "class", m.mapNotNull { cls(cards[it])?.substringAfterLast('.') }.distinct().take(3).joinToString(" / ") + " (linked by shared entries, sinks or fields)")
    }

    /** Card index -> its group, for rendering one line under each member. */
    fun byCard(groups: List<Group>): Map<Int, Group> { val m = HashMap<Int, Group>(); for (g in groups) for (c in g.cards) m[c] = g; return m }
}
