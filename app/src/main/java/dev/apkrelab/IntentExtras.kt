package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap

/**
 * 0.95.0: which Intent extras (and link query parameters) a class READS, and where the app WRITES them and from what kind of value. A WebView sink that takes its URL from
 * `getStringExtra("url")` is only attacker-reachable when somebody the attacker controls sets that extra: the component is exported, or the internal caller puts a user / remote /
 * forwarded value in it. When the only writer puts a constant the chain is not exploitable from outside, and the scenario builder drops it. Linear, approximate (no control flow).
 */
object IntentExtras {
    class Read(val classType: String, val method: String, val key: String, val kind: String)
    class Write(val classType: String, val method: String, val key: String, val origin: String, val detail: String)

    private val reads = ConcurrentHashMap<String, Read>()
    private val writes = ConcurrentHashMap<String, Write>()
    fun clear() { reads.clear(); writes.clear() }

    private val readRe = Regex("invoke-virtual \\{([^}]*)\\}, Landroid/content/Intent;->get([A-Za-z]+)Extra\\(Ljava/lang/String;")
    private val queryRe = Regex("invoke-virtual \\{([^}]*)\\}, Landroid/net/Uri;->getQueryParameter\\(Ljava/lang/String;\\)")
    private val writeRe = Regex("invoke-virtual \\{([^}]*)\\}, Landroid/content/Intent;->putExtra\\(Ljava/lang/String;(?:Ljava/lang/String;|I|Z|J|Landroid/os/Parcelable;|Ljava/io/Serializable;|\\[Ljava/lang/String;)\\)")
    private val methodRe = Regex("^[ \\t]*\\.method [^\\n]*? ([A-Za-z0-9_$<>]+)\\(", RegexOption.MULTILINE)
    private val regTok = Regex("[vp]\\d+")
    private val nonWriting = Regex("^(invoke|return|goto|if-|iput|sput|aput|throw|check-cast|monitor|fill-array|packed-switch|sparse-switch|nop|\\.|:|#)")

    private fun regs(list: String): List<String> = regTok.findAll(list).map { it.value }.toList()

    /** What a call returns, by the callee: the origin kind and a short description. */
    internal fun classify(callee: String): Pair<String, String> {
        val cls = callee.substringBefore(";->") + ";"; val name = callee.substringAfter(";->").substringBefore("(")
        return when {
            name == "getText" && (cls.contains("TextView") || cls.contains("EditText")) -> "USER_INPUT" to "text typed by the user (${cls.removePrefix("L").removeSuffix(";").substringAfterLast('/')}.getText)"
            cls == "Landroid/content/Intent;" && name.startsWith("get") && name.endsWith("Extra") || cls == "Landroid/content/Intent;" && name == "getDataString" || cls == "Landroid/net/Uri;" && (name == "getQueryParameter" || name == "toString" || name == "getPath") || cls == "Landroid/content/Intent;" && name == "getData" ->
                "PASSTHROUGH" to "forwarded from an incoming Intent or link ($name)"
            cls.startsWith("Lorg/json/") || cls.startsWith("Lcom/google/gson/") || cls.startsWith("Lcom/fasterxml/") || cls.startsWith("Lretrofit2/") || cls.startsWith("Lokhttp3/") || cls.startsWith("Lcom/squareup/moshi/") || cls.startsWith("Lkotlinx/serialization/") ->
                "REMOTE" to "parsed data (${cls.removePrefix("L").removeSuffix(";").substringAfterLast('/')}.$name), usually a server response"
            cls == "Landroid/content/SharedPreferences;" -> "STORAGE" to "a stored preference ($name)"
            cls == "Landroid/content/res/Resources;" || (cls == "Landroid/content/Context;" || cls.endsWith("Activity;")) && name == "getString" -> "RESOURCE" to "a string resource (fixed at build time)"
            cls == "Ljava/lang/StringBuilder;" || cls == "Ljava/lang/String;" && (name == "valueOf" || name == "format" || name == "concat") -> "BUILT" to "a string built from parts (their origin is not traced)"
            cls.startsWith("Landroid/") || cls.startsWith("Ljava/") || cls.startsWith("Ljavax/") || cls.startsWith("Lkotlin/") -> "CALL" to "the result of ${cls.removePrefix("L").removeSuffix(";").substringAfterLast('/')}.$name()"
            else -> "CALL" to "the result of ${cls.removePrefix("L").removeSuffix(";").replace('/', '.')}.$name()"
        }
    }

    fun collect(classType: String, text: String) {
        if (!text.contains("Landroid/content/Intent;->") && !text.contains("Landroid/net/Uri;->getQueryParameter")) return
        val starts = methodRe.findAll(text).map { it.range.first to it.groupValues[1] }.toList()
        for ((idx, st) in starts.withIndex()) {
            val end = if (idx + 1 < starts.size) starts[idx + 1].first else text.length
            val body = text.substring(st.first, end); val mname = st.second
            if (!body.contains("Intent;->") && !body.contains("getQueryParameter")) continue
            val defs = HashMap<String, Pair<String, String>>()          // register -> (origin kind, description)
            var lastCall: String? = null
            for (raw in body.lineSequence()) {
                val l = raw.trim()
                if (l.isEmpty()) continue
                if (l.startsWith("const-string")) { val r = regTok.find(l)?.value ?: continue; val v = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"").find(l)?.groupValues?.get(1) ?: ""; defs[r] = "CONSTANT" to v; continue }
                if (l.startsWith("invoke")) {
                    lastCall = Regex("\\}, (L[^;]+;->[A-Za-z0-9_$<>]+)\\(").find(l)?.groupValues?.get(1)
                    readRe.find(l)?.let { m ->
                        val rs = regs(m.groupValues[1]); val key = rs.getOrNull(1)?.let { defs[it] }
                        if (key != null && key.first == "CONSTANT") reads.putIfAbsent("$classType|$mname|${key.second}", Read(classType, mname, key.second, m.groupValues[2]))
                    }
                    queryRe.find(l)?.let { m ->
                        val rs = regs(m.groupValues[1]); val key = rs.getOrNull(1)?.let { defs[it] }
                        if (key != null && key.first == "CONSTANT") reads.putIfAbsent("$classType|$mname|?${key.second}", Read(classType, mname, key.second, "query"))
                    }
                    writeRe.find(l)?.let { m ->
                        val rs = regs(m.groupValues[1]); val key = rs.getOrNull(1)?.let { defs[it] }; val v = rs.getOrNull(2)
                        if (key != null && key.first == "CONSTANT" && v != null) {
                            val d = defs[v] ?: ("PARAM" to "a parameter or value whose definition is not in this method")
                            writes.putIfAbsent("$classType|$mname|${key.second}|${d.first}", Write(classType, mname, key.second, d.first, d.second.take(120)))
                        }
                    }
                    continue
                }
                if (l.startsWith("move-result")) { val r = regTok.find(l)?.value ?: continue; val c = lastCall; if (c != null) defs[r] = classify(c) else defs.remove(r); lastCall = null; continue }
                if (l.startsWith("iget") || l.startsWith("sget")) {
                    val r = regTok.find(l)?.value ?: continue; val f = Regex("(L[^;]+;->[A-Za-z0-9_$]+)").find(l)?.groupValues?.get(1) ?: ""
                    defs[r] = "FIELD" to "the field " + f.removePrefix("L").replace(";->", ".").replace('/', '.'); continue
                }
                if (l.startsWith("move-object") || l.startsWith("move ")) { val ts = regs(l); if (ts.size >= 2) defs[ts[0]] = defs[ts[1]] ?: ("PARAM" to "a parameter or value whose definition is not in this method") ; continue }
                if (!nonWriting.containsMatchIn(l)) regTok.find(l)?.let { defs.remove(it.value) }
            }
        }
    }

    fun readsOf(dottedClass: String, method: String? = null): List<Read> {
        val t = "L" + dottedClass.replace('.', '/') + ";"
        return reads.values.filter { (it.classType == t || it.classType.startsWith(t.removeSuffix(";") + "$")) && (method == null || it.method == method) }.sortedBy { it.key }
    }

    /** The writers of [key]; when [classes] (dotted names from a call path) is not empty, those in these classes first, and only them when there are any. */
    fun writesOf(key: String, classes: Collection<String> = emptyList()): List<Write> {
        val all = writes.values.filter { it.key == key }
        if (classes.isEmpty()) return all
        val set = classes.map { "L" + it.replace('.', '/') + ";" }
        val inPath = all.filter { w -> set.any { w.classType == it || w.classType.startsWith(it.removeSuffix(";") + "$") } }
        return inPath.ifEmpty { all }
    }
}
