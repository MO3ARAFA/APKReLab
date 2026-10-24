package dev.apkrelab

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * 0.102.0: decoded-strings overlay. Some apps (a protector, an in-app scheme) decrypt EVERY string through one static `(I)Ljava/lang/String;` method: the smali holds
 * `const v0, 0x1a2` / `invoke-static {v0}, Lvs/C;->d(I)Ljava/lang/String;` / `move-result-object v0` and no `const-string` at all, so every rule that reads string constants
 * (secrets, URLs, cipher names, Intent extras, root-check paths) is blind. The owner dumps the strings on a test device (the report prints a Frida snippet: `index<TAB>"plaintext"`),
 * imports the dump, and [apply] rewrites those three instructions into `const-string v0, "plaintext"` in the class text the scan reads. Nothing is written to the APK or to the
 * cached class index (the overlay is applied when the text is read), and the smali viewer / editor keep the original text.
 *
 * Only a call whose argument register holds a CONSTANT assigned earlier in the same straight-line block (no label, no other write to the register in between) is rewritten; a computed
 * or parameter index, an index missing from the dump, or a call whose result is not moved straight away is left alone and counted as "unresolved".
 */
class StringOverlay(val method: String, val strings: Map<Int, String>) {
    /** class type -> [replaced, unresolved]; keyed by class so reading a class text several times (the grouped analysis does) counts it once. */
    private val perClass = ConcurrentHashMap<String, IntArray>()
    val replaced: Int get() = perClass.values.sumOf { it[0] }
    val unresolved: Int get() = perClass.values.sumOf { it[1] }
    fun resetStats() = perClass.clear()

    /** The class text with the decryptor calls it can resolve replaced by `const-string`. [classType] is only the key for the statistics. */
    fun apply(text: String, classType: String = ""): String {
        if (!text.contains(method)) return text                     // the fast path: nearly every class never calls the decryptor
        val lines = text.split('\n')
        val out = ArrayList<String>(lines.size)
        val consts = HashMap<String, Int>()                           // register -> constant, valid in the current straight-line block
        var done = 0; var left = 0
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            val t = line.trim()
            if (t.startsWith(":") || t.startsWith(".method") || t.startsWith(".end method") || t.startsWith(".catch") || t.startsWith(".packed-switch") || t.startsWith(".sparse-switch")) consts.clear()
            val call = if (t.startsWith("invoke-static") && t.contains(method)) callArg(t) else null
            if (call != null) {
                val idx = consts[call]
                var j = i + 1
                while (j < lines.size && skippable(lines[j].trim())) j++
                val mr = if (j < lines.size) lines[j].trim() else ""
                val dest = if (mr.startsWith("move-result-object ")) mr.removePrefix("move-result-object ").trim() else null
                val s = if (idx != null) strings[idx] else null
                if (s != null && dest != null) {
                    out.add(line.substring(0, line.length - line.trimStart().length) + "const-string " + dest + ", \"" + escape(s) + "\"")
                    for (k in i + 1 until j) out.add(lines[k])       // keep the .line / .local directives between the call and the move-result
                    consts.remove(dest)
                    done++
                    i = j + 1
                    continue
                }
                left++
                out.add(line); i++
                continue
            }
            noteWrite(t, consts)
            out.add(line); i++
        }
        if (classType.isNotEmpty() && (done > 0 || left > 0)) perClass[classType] = intArrayOf(done, left)
        return if (done == 0) text else out.joinToString("\n")
    }

    private fun skippable(t: String) = t.isEmpty() || t.startsWith(".line") || t.startsWith(".local") || t.startsWith(".restart local") || t.startsWith(".end local") || t.startsWith(".prologue") || t.startsWith("#")

    /** The single argument register of `invoke-static {vN}, <method>` (also the `/range {vN .. vN}` form), or null. */
    private fun callArg(t: String): String? {
        val m = argRe.find(t) ?: return null
        return m.groupValues[1].ifEmpty { m.groupValues[2] }
    }

    /** Tracks `const* vN, <int>`; any other instruction that writes vN forgets it. */
    private fun noteWrite(t: String, consts: HashMap<String, Int>) {
        if (t.isEmpty() || t.startsWith(".") || t.startsWith("#") || t.startsWith(":")) return
        val c = constRe.find(t)
        if (c != null) {
            val reg = c.groupValues[1]; val v = parseInt(c.groupValues[2], c.value.startsWith("const/high16"))
            if (v != null) consts[reg] = v else consts.remove(reg)
            return
        }
        val op = t.substringBefore(' ')
        if (op.startsWith("invoke") || op.startsWith("return") || op.startsWith("if-") || op.startsWith("iput") || op.startsWith("sput") || op.startsWith("aput") ||
            op.startsWith("goto") || op.startsWith("throw") || op.startsWith("monitor") || op.endsWith("-switch") || op == "nop" || op.startsWith("fill-array")) return
        val first = destRe.find(t)?.groupValues?.get(1) ?: return
        consts.remove(first)
        if (op.contains("wide") || op.startsWith("const-wide") || op.endsWith("-long") || op.endsWith("-double")) consts.remove(nextReg(first))
    }

    private fun nextReg(r: String): String = r.take(1) + ((r.drop(1).toIntOrNull() ?: -2) + 1)

    companion object {
        private val argRe = Regex("""invoke-static(?:/range)?\s+\{\s*([vp]\d+)\s*(?:\.\.\s*[vp]\d+\s*)?\}|\{\s*([vp]\d+)\s*\}""")      // braces escaped: Android's ICU engine rejects a bare '}' (Java accepts it)
        private val constRe = Regex("""^const(?:/4|/16|/high16)?\s+([vp]\d+),\s*(-?0x[0-9a-fA-F]+)""")
        private val destRe = Regex("""^[a-z0-9/\-]+\s+([vp]\d+)""")

        private fun parseInt(s: String, high16: Boolean): Int? = try {
            val neg = s.startsWith("-"); val h = s.removePrefix("-").removePrefix("0x").toLong(16)
            val v = (if (neg) -h else h)
            (if (high16) v shl 16 else v).toInt()
        } catch (_: Throwable) { null }

        /** The smali string escapes (backslash, quote, control characters); everything else is kept as is. */
        fun escape(s: String): String {
            val sb = StringBuilder(s.length + 8)
            for (c in s) when {
                c == '\\' -> sb.append("\\\\")
                c == '"' -> sb.append("\\\"")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 -> sb.append("\\u").append(String.format("%04x", c.code))
                else -> sb.append(c)
            }
            return sb.toString()
        }

        class Parsed(val method: String?, val strings: Map<Int, String>, val skippedLines: Int)

        /**
         * Reads a dump. Two shapes: lines `index<TAB>text` (text either raw or a JSON string literal; a line that does not start with `<int><TAB>` continues the previous text; a first line
         * `#decryptor<TAB>Lvs/C;->d(I)Ljava/lang/String;` names the method), or JSON: `{"method": "...", "strings": {"12": "x"}}`, `{"12": "x"}` or `[{"i": 12, "s": "x"}]`.
         */
        fun parse(raw: String): Parsed {
            val text = raw.removePrefix("\uFEFF").trim()
            if (text.startsWith("{") || text.startsWith("[")) parseJson(text)?.let { return it }
            var method: String? = null
            val map = LinkedHashMap<Int, String>()
            var last: Int? = null; var skipped = 0
            for (line in raw.removePrefix("\uFEFF").split('\n')) {
                val l = line.trimEnd('\r')
                if (l.startsWith("#")) {
                    val m = headerRe.find(l)
                    if (m != null && m.groupValues[1].contains("->")) method = m.groupValues[1].trim()
                    continue
                }
                val tab = l.indexOf('\t')
                val idx = if (tab > 0) l.substring(0, tab).trim().toIntOrNull() else null
                if (idx != null) {
                    map[idx] = unquote(l.substring(tab + 1)); last = idx
                } else if (last != null && l.isNotEmpty()) {
                    map[last] = map[last] + "\n" + l                 // a raw multi-line string printed by console.log
                } else if (l.isNotBlank()) skipped++
            }
            return Parsed(method, map, skipped)
        }

        private val headerRe = Regex("""^#\s*(?:decryptor|method)\s*[:\t ]\s*(\S+)""")

        private fun unquote(s: String): String {
            if (s.length >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
                try { return org.json.JSONTokener(s).nextValue() as? String ?: s } catch (_: Throwable) { }
            }
            return s
        }

        private fun parseJson(text: String): Parsed? = try {
            val map = LinkedHashMap<Int, String>(); var method: String? = null
            if (text.startsWith("[")) {
                val a = JSONArray(text)
                for (k in 0 until a.length()) { val o = a.getJSONObject(k); map[o.getInt("i")] = o.getString("s") }
            } else {
                val o = JSONObject(text)
                method = o.optString("method", o.optString("decryptor", "")).ifEmpty { null }
                val src = o.optJSONObject("strings") ?: o
                val ks = src.keys()
                while (ks.hasNext()) { val k = ks.next().toString(); k.toIntOrNull()?.let { map[it] = src.optString(k) } }
            }
            Parsed(method, map, 0)
        } catch (_: Throwable) { null }

        /** The overlay for a dump; [fallbackMethod] (the app's dominant decryptor) is used when the dump does not name one. Null when there is no method or no strings. */
        fun from(raw: String, fallbackMethod: String?): StringOverlay? {
            val p = parse(raw)
            val m = p.method ?: fallbackMethod ?: return null
            return if (p.strings.isEmpty()) null else StringOverlay(m, p.strings)
        }

        /** The overlay currently applied to class texts (one APK is loaded at a time). */
        @Volatile var current: StringOverlay? = null

        /** [text] through the current overlay, if any. */
        fun view(text: String, classType: String): String { val o = current ?: return text; return o.apply(text, classType) }

        /** The dump saved with an APK's workspace; null when absent or unusable. */
        fun load(file: File): StringOverlay? = try { if (file.isFile) from(file.readText(), null) else null } catch (_: Throwable) { null }
    }
}
