package dev.apkrelab

import org.json.JSONObject

/**
 * 0.89.0: vendor token formats (assets/secret_formats.json, generated from the gitleaks rule set by tools/secrets/gen_secret_formats.py; gitleaks is MIT licensed).
 * A rule matches a string when: one of its keywords occurs (case-insensitive, the same cheap pre-filter gitleaks uses), its regex finds a token, the token's Shannon entropy
 * reaches the rule's minimum, and neither the rule's nor the global stop words / allow-list patterns apply. Pure; the callers pass the strings (smali constants, resources,
 * native strings).
 */
object SecretFormats {

    class Rule(val id: String, val desc: String, val regex: Regex, val entropy: Double, val keywords: List<String>, val group: Int,
               val stop: List<String>, val allow: List<Regex>)

    class Hit(val ruleId: String, val desc: String, val secret: String)

    @Volatile private var rules: List<Rule> = emptyList()
    @Volatile private var globalStop: List<String> = emptyList()
    @Volatile private var trigrams: Set<String> = emptySet()
    @Volatile private var byKeyword: Map<String, List<Rule>> = emptyMap()
    @Volatile private var shortKeyword: List<Pair<String, Rule>> = emptyList()      // keywords under 3 characters ("q~", "sk", "s."): no trigram, a plain contains()
    @Volatile var failedToCompile: List<String> = emptyList()
        private set

    /** Java is nearly RE2: the few Go-only spellings are translated. */
    private fun translate(rx: String): String = rx.replace("(?P<", "(?<").replace("[[:alnum:]]", "\\p{Alnum}").replace("[[:alpha:]]", "\\p{Alpha}")
        .replace("[[:digit:]]", "\\d").replace("[[:xdigit:]]", "\\p{XDigit}").replace("[[:upper:]]", "\\p{Upper}").replace("[[:lower:]]", "\\p{Lower}")

    /** Loads the rule file; returns the number of rules usable. */
    fun load(json: String): Int {
        val o = JSONObject(json)
        val g = o.optJSONArray("stopwords"); val gs = ArrayList<String>()
        if (g != null) for (i in 0 until g.length()) gs.add(g.getString(i).lowercase())
        val arr = o.getJSONArray("rules"); val out = ArrayList<Rule>(); val bad = ArrayList<String>()
        for (i in 0 until arr.length()) {
            val r = arr.getJSONObject(i)
            try {
                val kws = r.getJSONArray("keywords").let { a -> (0 until a.length()).map { a.getString(it).lowercase() } }
                val stop = r.optJSONArray("stop")?.let { a -> (0 until a.length()).map { a.getString(it).lowercase() } } ?: emptyList()
                val allow = r.optJSONArray("allow")?.let { a -> (0 until a.length()).map { Regex(translate(a.getString(it))) } } ?: emptyList()
                out.add(Rule(r.getString("id"), r.optString("desc"), Regex(translate(r.getString("regex"))), r.optDouble("entropy", 0.0), kws, r.optInt("group", 0), stop, allow))
            } catch (_: Throwable) { bad.add(r.optString("id")) }
        }
        failedToCompile = bad; globalStop = gs; rules = out
        val bk = HashMap<String, MutableList<Rule>>(); val tri = HashSet<String>(); val sh = ArrayList<Pair<String, Rule>>()
        for (r in out) for (k in r.keywords) { if (k.length >= 3) { bk.getOrPut(k) { ArrayList() }.add(r); tri.add(k.substring(0, 3)) } else if (k.isNotEmpty()) sh.add(k to r) }
        byKeyword = bk; trigrams = tri; shortKeyword = sh
        return out.size
    }

    fun loaded(): Boolean = rules.isNotEmpty()
    fun ruleCount(): Int = rules.size

    internal fun entropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val c = HashMap<Char, Int>(); for (ch in s) c[ch] = (c[ch] ?: 0) + 1
        var h = 0.0; for (v in c.values) { val p = v.toDouble() / s.length; h -= p * (Math.log(p) / Math.log(2.0)) }
        return h
    }

    /** Rules whose keyword occurs in [lower]: a trigram scan first (cheap), then the keywords starting with that trigram. */
    private fun candidates(lower: String): Collection<Rule> {
        var out: MutableSet<Rule>? = null
        val tri = trigrams
        for (i in 0..lower.length - 3) {
            if (lower.substring(i, i + 3) !in tri) continue
            for ((k, rs) in byKeyword) if (k.regionMatches(0, lower, i, k.length) && k.length <= lower.length - i) { if (out == null) out = LinkedHashSet(); out.addAll(rs) }
        }
        for ((k, r) in shortKeyword) if (lower.contains(k)) { if (out == null) out = LinkedHashSet(); out.add(r) }
        return out ?: emptyList()
    }

    private fun check(r: Rule, text: String): List<Hit> {
        val hits = ArrayList<Hit>()
        for (m in r.regex.findAll(text)) {
            // gitleaks: the rule's secretGroup, else the FIRST NON-EMPTY capture group (a rule with alternatives has one group per branch), else the whole match
            val secret = if (r.group > 0 && r.group < m.groupValues.size) m.groupValues[r.group] else m.groupValues.drop(1).firstOrNull { it.isNotEmpty() } ?: m.value
            if (secret.isEmpty()) continue
            if (r.entropy > 0 && entropy(secret) < r.entropy) continue
            val low = secret.lowercase()
            if (r.stop.any { low.contains(it) } || globalStop.any { low.contains(it) }) continue
            if (r.allow.any { it.containsMatchIn(secret) || it.containsMatchIn(m.value) }) continue
            hits.add(Hit(r.id, r.desc, secret))
        }
        return hits
    }

    /**
     * A value that is a template, not a credential: the same character repeated ("xxxxxxxxxxxx"), a run of X / 0 / *, or a word that says so. The prefix of a vendor format is the
     * evidence of a real token, so no "does it look like an identifier" test applies (it rejected a real `api_org_...` token).
     */
    fun looksLikePlaceholder(secret: String): Boolean {
        val body = secret.substringAfterLast('_').substringAfterLast('-').ifEmpty { secret }
        if (body.length >= 8 && body.toSet().size <= 2) return true
        val low = secret.lowercase()
        return listOf("xxxxxxxx", "00000000", "********", "example", "placeholder", "your_", "your-", "<token", "changeme", "dummy", "fake", "redacted", "insert_").any { low.contains(it) }
    }

    /** Hits in a string constant or a line of text. */
    fun scan(text: String): List<Hit> {
        if (rules.isEmpty() || text.length < 8 || text.length > 2000) return emptyList()
        val cand = candidates(text.lowercase())
        if (cand.isEmpty()) return emptyList()
        val out = ArrayList<Hit>()
        for (r in cand) out.addAll(check(r, text))
        return out
    }
}
