package dev.apkrelab

/**
 * 0.44.0: light taint analysis over the baksmali text of ONE class (rule id `taint-flow`).
 *
 * Idea: instead of "this class calls rawQuery", report "data that came from an attacker-controlled SOURCE reaches rawQuery".
 * Sources: Intent getters (extras, data, data string), parameters of @JavascriptInterface methods (web content calls them),
 * parameters of ContentProvider methods (other apps call them when the provider is exported).
 * Sinks: WebView load / JavaScript, SQL statements, shell commands, file paths, reflection by name, dynamic code / native
 * library loading, URL to contact (SSRF).
 *
 * How it works (per method, linear pass over the instructions, no branches / loops modelled):
 *  - a register is tainted or not (level 2 = proven chain, level 1 = passed through unknown app code or a provider parameter);
 *  - move / move-result / aget propagate, const / new-instance / arithmetic clear;
 *  - String, StringBuilder, Uri, File, Bundle, JSON, collections and Kotlin string helpers propagate (see [kindOf]);
 *    sanitizers (URLEncoder, sqlEscapeString, Integer.parseInt ...) clear;
 *  - fields of THIS class (iput / iget / sput / sget) and calls to methods of THIS class (arguments in, return value out) are
 *    followed with a small fixpoint (at most [MAX_ROUNDS] rounds), so source and sink may sit in different methods of one class.
 * Limits: data flow BETWEEN classes is not followed here (0.49.0: see TaintLinker.kt, rule taint-xclass); no path sensitivity (a check on another branch is not understood, a
 * validation-like call anywhere in the method only lowers the confidence); reflection and lambdas are not modelled.
 * A finding is a lead: verify with get_class / get_java and check that the component is exported or reachable (reach field).
 */
internal object TaintEngine {

    private const val MAX_ROUNDS = 4
    private const val MAX_FINDINGS = 24

    private val HIGH = SecurityScanner.Severity.HIGH
    private val CRIT = SecurityScanner.Severity.CRITICAL
    private val MED = SecurityScanner.Severity.MEDIUM

    // ---------- data model ----------

    internal class Taint(val level: Int, val src: String)

    private class Line(val off: Int, val text: String)

    private class MInfo(val key: String, val name: String, val isStatic: Boolean, val paramTypes: List<String>) {
        val lines = ArrayList<Line>()
        var jsBridge = false
        var validation: Boolean? = null
    }

    private class Sink(
        val owner: String,
        val name: String,
        val args: IntArray,          // parameter indexes that matter (-1 = the receiver)
        val title: String,
        val sev: SecurityScanner.Severity,
        val cwe: String,
        val what: String,
        val fix: String,
        val descPrefix: String = "", // the descriptor must start with this (tells overloads apart)
        val inherent: String = "HIGH"
    )

    private class Hit(val sink: Sink, val off: Int, val taint: Taint, val m: MInfo)

    private class State(val ownerType: String, val appPrefix: String) {
        val fields = HashMap<String, Taint>()
        val returns = HashMap<String, Taint>()
        val seeds = HashMap<String, HashMap<String, Taint>>()
        var changed = false
        var rec: XRecorder? = null   // 0.49.0: set only in the final pass of [summarize]

        fun raise(map: HashMap<String, Taint>, key: String, t: Taint) {
            if (t.src.startsWith("@")) return   // symbolic labels (summaries) never leave their own method
            val old = map[key]
            if (old == null || old.level < t.level) {
                map[key] = t
                changed = true
            }
        }
    }

    // ---------- sources, sanitizers, propagators ----------

    private val intentSources = setOf(
        "getStringExtra", "getStringArrayExtra", "getStringArrayListExtra", "getCharSequenceExtra", "getCharSequenceArrayExtra",
        "getParcelableExtra", "getParcelableArrayExtra", "getParcelableArrayListExtra", "getSerializableExtra",
        "getExtras", "getBundleExtra", "getData", "getDataString"
    )

    private val providerMethods = setOf("query", "insert", "update", "delete", "openFile", "openAssetFile", "call", "bulkInsert")

    // 0.46.0: SharedPreferences content is also untrusted input (writable on rooted devices, restored from backups,
    // injectable through a content provider backup agent). Weaker than an Intent: level 1 -> MEDIUM confidence.
    private val prefsSources = setOf("getString", "getStringSet", "getAll")

    private fun sourceOf(owner: String, name: String): Taint? = when {
        owner == "Landroid/content/Intent;" && intentSources.contains(name) -> Taint(2, "Intent.$name()")
        owner == "Landroid/content/SharedPreferences;" && prefsSources.contains(name) ->
            Taint(1, "SharedPreferences.$name() (shared prefs are modifiable on rooted devices and in restored backups)")
        else -> null
    }

    private fun isSanitizer(owner: String, name: String): Boolean = when (owner) {
        "Ljava/net/URLEncoder;" -> name == "encode"
        "Landroid/text/TextUtils;" -> name == "htmlEncode"
        "Landroid/database/DatabaseUtils;" -> name.startsWith("sqlEscape")
        "Landroid/net/Uri;" -> name == "encode"
        "Landroid/text/Html;" -> name == "escapeHtml"
        "Ljava/io/File;" -> name == "getName"
        "Ljava/lang/Integer;", "Ljava/lang/Long;", "Ljava/lang/Double;", "Ljava/lang/Float;",
        "Ljava/lang/Boolean;", "Ljava/lang/Short;", "Ljava/lang/Byte;", "Ljava/util/UUID;" -> true
        else -> false
    }

    /** Classes whose objects ACCUMULATE data: an argument taints the receiver (append, put, add ...). */
    private val builderOwners = setOf(
        "Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;", "Landroid/net/Uri\$Builder;",
        "Landroid/os/Bundle;", "Landroid/os/BaseBundle;", "Lorg/json/JSONObject;", "Lorg/json/JSONArray;",
        "Ljava/util/ArrayList;", "Ljava/util/List;", "Ljava/util/LinkedList;", "Ljava/util/Map;", "Ljava/util/HashMap;",
        "Ljava/util/LinkedHashMap;", "Ljava/util/TreeMap;", "Ljava/util/Set;", "Ljava/util/HashSet;", "Ljava/util/Collection;",
        "Ljava/util/Deque;", "Ljava/util/ArrayDeque;", "Ljava/util/Queue;"
    )

    /** Classes whose methods just transform their inputs: the result is tainted when the receiver or an argument is. */
    private val pureOwners = setOf(
        "Ljava/lang/String;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;", "Landroid/net/Uri;", "Ljava/net/URLDecoder;",
        "Ljava/net/URL;", "Ljava/net/URI;", "Ljava/io/File;", "Ljava/util/Objects;", "Landroid/text/TextUtils;",
        "Landroid/content/Intent;", "Ljava/util/Arrays;", "Ljava/util/Iterator;", "Ljava/util/ListIterator;",
        "Ljava/util/Map\$Entry;", "Ljava/util/Collections;"
    )

    private val purePrefixes = listOf("Lkotlin/text/", "Lkotlin/collections/")

    /** 0 = unknown, 1 = pure transform, 2 = builder / container. */
    private fun kindOf(owner: String): Int {
        if (builderOwners.contains(owner)) return 2
        if (pureOwners.contains(owner)) return 1
        for (p in purePrefixes) if (owner.startsWith(p)) return 1
        return 0
    }

    // ---------- sinks ----------

    private const val T_WEB = "Untrusted input is loaded into a WebView"
    private const val T_JS = "Untrusted input is run as JavaScript in a WebView"
    private const val T_SQL = "Untrusted input reaches an SQL statement"
    private const val T_CMD = "Untrusted input reaches a shell command"
    private const val T_FILE = "Untrusted input is used as a file path"
    private const val T_REFL = "Untrusted input selects a class or method by name"
    private const val T_CODE = "Untrusted input is loaded as code or a native library"
    private const val T_SSRF = "Untrusted input chooses the server the app contacts"
    private const val T_URI = "Untrusted input chooses the file or content URI the app opens"

    private const val FIX_WEB = "Allow-list the scheme and host before loading (https and your own domains only), or map a small id to a fixed URL. Never pass an Intent extra straight to the WebView."
    private const val FIX_JS = "Do not build JavaScript from outside input. Pass data as JSON through a fixed function (JSON.stringify on a value you control) and validate it first."
    private const val FIX_SQL = "Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names."
    private const val FIX_CMD = "Do not build shell commands from input. Call an API instead, or pass fixed arguments and validate each one against an allow-list."
    private const val FIX_FILE = "Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory."
    private const val FIX_REFL = "Look the name up in an explicit allow-list (a map of known keys to classes) instead of passing it to Class.forName / getMethod."
    private const val FIX_CODE = "Load code only from the app's own read-only locations (assets, code cache created by the app); never from a path or name given by the caller."
    private const val FIX_URI = "Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size."
    private const val FIX_SSRF = "Allow-list the host (and use https) before opening the connection; resolve a small id to a fixed URL on your side."

    private val sinks: List<Sink> = listOf(
        // WebView
        Sink("Landroid/webkit/WebView;", "loadUrl", intArrayOf(0), T_WEB, HIGH, "CWE-79",
            "the WebView loads a URL chosen by the caller (javascript: and file: URLs run with the app's rights, a remote page can reach any JavaScript bridge)", FIX_WEB),
        Sink("Landroid/webkit/WebView;", "loadData", intArrayOf(0), T_WEB, HIGH, "CWE-79",
            "HTML chosen by the caller is rendered inside the app's WebView", FIX_WEB),
        Sink("Landroid/webkit/WebView;", "loadDataWithBaseURL", intArrayOf(0, 1), T_WEB, HIGH, "CWE-79",
            "HTML or the base URL chosen by the caller is rendered inside the app's WebView", FIX_WEB),
        Sink("Landroid/webkit/WebView;", "evaluateJavascript", intArrayOf(0), T_JS, HIGH, "CWE-79",
            "text chosen by the caller is executed as JavaScript in the page", FIX_JS),
        // SQL
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the SQL text itself contains the input (selectionArgs are safe, the sql string is not)", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "rawQueryWithFactory", intArrayOf(1), T_SQL, HIGH, "CWE-89", "the SQL text itself contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "execSQL", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the SQL statement contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "compileStatement", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the SQL statement contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "query", intArrayOf(0, 2, 4, 5, 6), T_SQL, HIGH, "CWE-89",
            "table, selection, GROUP BY, HAVING or ORDER BY contains the input (only selectionArgs are bound safely)", FIX_SQL, "Ljava/lang/String;"),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "query", intArrayOf(1, 3, 5, 6, 7), T_SQL, HIGH, "CWE-89",
            "table, selection, GROUP BY, HAVING or ORDER BY contains the input (only selectionArgs are bound safely)", FIX_SQL, "Z"),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "delete", intArrayOf(0, 1), T_SQL, HIGH, "CWE-89", "the table or the WHERE clause contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteDatabase;", "update", intArrayOf(0, 2), T_SQL, HIGH, "CWE-89", "the table or the WHERE clause contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "appendWhere", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the WHERE text contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the table list contains the input", FIX_SQL),
        // 0.72.0: SQLiteQueryBuilder.query / buildQuery* / update / delete (the usual ContentProvider.query body); only the bound selectionArgs are safe
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "query", intArrayOf(1, 2, 4, 5, 6, 7), T_SQL, HIGH, "CWE-89", "projection, selection, GROUP BY, HAVING, ORDER BY or LIMIT contains the input (only selectionArgs are bound safely)", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "buildQuery", intArrayOf(0, 1, 2, 3, 4, 5), T_SQL, HIGH, "CWE-89", "projection, selection, GROUP BY, HAVING, ORDER BY or LIMIT contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "buildQueryString", intArrayOf(1, 2, 3, 4, 5, 6, 7), T_SQL, HIGH, "CWE-89", "tables, columns, WHERE, GROUP BY, HAVING, ORDER BY or LIMIT contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "update", intArrayOf(2), T_SQL, HIGH, "CWE-89", "the WHERE clause contains the input", FIX_SQL),
        Sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "delete", intArrayOf(1), T_SQL, HIGH, "CWE-89", "the WHERE clause contains the input", FIX_SQL),
        Sink("Landroidx/sqlite/db/SupportSQLiteDatabase;", "query", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the SQL text contains the input", FIX_SQL),
        Sink("Landroidx/sqlite/db/SupportSQLiteDatabase;", "execSQL", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the SQL statement contains the input", FIX_SQL),
        Sink("Landroidx/sqlite/db/SimpleSQLiteQuery;", "<init>", intArrayOf(0), T_SQL, HIGH, "CWE-89", "the SQL text contains the input", FIX_SQL),
        // shell
        Sink("Ljava/lang/Runtime;", "exec", intArrayOf(0), T_CMD, CRIT, "CWE-78", "the command line contains the input, so the caller can run other commands with the app's rights", FIX_CMD),
        Sink("Ljava/lang/ProcessBuilder;", "<init>", intArrayOf(0), T_CMD, CRIT, "CWE-78", "the command contains the input", FIX_CMD),
        Sink("Ljava/lang/ProcessBuilder;", "command", intArrayOf(0), T_CMD, CRIT, "CWE-78", "the command contains the input", FIX_CMD),
        // file paths
        Sink("Ljava/io/FileInputStream;", "<init>", intArrayOf(0), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is read (../ reaches the app's private files)", FIX_FILE),
        Sink("Ljava/io/FileOutputStream;", "<init>", intArrayOf(0), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is written or overwritten", FIX_FILE),
        Sink("Ljava/io/FileReader;", "<init>", intArrayOf(0), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is read", FIX_FILE),
        Sink("Ljava/io/FileWriter;", "<init>", intArrayOf(0), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is written or overwritten", FIX_FILE),
        Sink("Ljava/io/RandomAccessFile;", "<init>", intArrayOf(0), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is opened", FIX_FILE),
        Sink("Landroid/os/ParcelFileDescriptor;", "open", intArrayOf(0), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is handed out as a descriptor", FIX_FILE),
        Sink("Ljava/io/File;", "delete", intArrayOf(-1), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is deleted", FIX_FILE),
        Sink("Ljava/io/File;", "renameTo", intArrayOf(-1), T_FILE, HIGH, "CWE-22", "a file chosen by the caller is moved", FIX_FILE),
        // reflection and code loading
        Sink("Ljava/lang/Class;", "forName", intArrayOf(0), T_REFL, HIGH, "CWE-470", "the caller picks which class is loaded and initialised", FIX_REFL),
        Sink("Ljava/lang/ClassLoader;", "loadClass", intArrayOf(0), T_REFL, HIGH, "CWE-470", "the caller picks which class is loaded", FIX_REFL),
        Sink("Ljava/lang/Class;", "getMethod", intArrayOf(0), T_REFL, MED, "CWE-470", "the caller picks which method is looked up", FIX_REFL),
        Sink("Ljava/lang/Class;", "getDeclaredMethod", intArrayOf(0), T_REFL, MED, "CWE-470", "the caller picks which method is looked up", FIX_REFL),
        Sink("Ldalvik/system/DexClassLoader;", "<init>", intArrayOf(0, 2), T_CODE, CRIT, "CWE-94", "the caller picks the dex / jar path or the native library folder, so foreign code runs inside the app", FIX_CODE),
        Sink("Ldalvik/system/PathClassLoader;", "<init>", intArrayOf(0), T_CODE, CRIT, "CWE-94", "the caller picks the code path, so foreign code runs inside the app", FIX_CODE),
        Sink("Ljava/lang/System;", "load", intArrayOf(0), T_CODE, CRIT, "CWE-94", "the caller picks the native library that is loaded", FIX_CODE),
        Sink("Ljava/lang/System;", "loadLibrary", intArrayOf(0), T_CODE, HIGH, "CWE-94", "the caller picks the native library that is loaded", FIX_CODE),
        Sink("Ljava/lang/Runtime;", "load", intArrayOf(0), T_CODE, CRIT, "CWE-94", "the caller picks the native library that is loaded", FIX_CODE),
        // server to contact
        Sink("Ljava/net/URL;", "<init>", intArrayOf(0), T_SSRF, MED, "CWE-918", "the caller picks the host the app connects to (internal services, attacker servers that receive the app's headers or tokens)", FIX_SSRF, "", "MEDIUM"),
        Sink("Lokhttp3/Request\$Builder;", "url", intArrayOf(0), T_SSRF, MED, "CWE-918", "the caller picks the host the app connects to", FIX_SSRF, "", "MEDIUM"),
        // 0.72.0: the caller picks the URI the app opens (file:// or content://): the app reads its own private files or another provider's data
        Sink("Landroid/content/ContentResolver;", "openInputStream", intArrayOf(0), T_URI, MED, "CWE-73", "the caller picks the URI the app reads, so a file:// URI makes the app read its own private files", FIX_URI, "", "MEDIUM"),
        Sink("Landroid/content/ContentResolver;", "openOutputStream", intArrayOf(0), T_URI, MED, "CWE-73", "the caller picks the URI the app writes to", FIX_URI, "", "MEDIUM"),
        Sink("Landroid/content/ContentResolver;", "openFileDescriptor", intArrayOf(0), T_URI, MED, "CWE-73", "the caller picks the URI the app opens as a file descriptor", FIX_URI, "", "MEDIUM"),
        Sink("Landroid/content/ContentResolver;", "openAssetFileDescriptor", intArrayOf(0), T_URI, MED, "CWE-73", "the caller picks the URI the app opens as an asset descriptor", FIX_URI, "", "MEDIUM")
    )

    private val sinkIndex: HashMap<String, List<Sink>> = HashMap<String, List<Sink>>().also { idx ->
        for (s in sinks) {
            val k = s.owner + "->" + s.name
            idx[k] = (idx[k] ?: emptyList()) + s
        }
    }

    private val sinkOwners: List<String> = sinks.map { it.owner }.distinct()

    // ---------- parsing ----------

    private val invokeRe = rx("^invoke-[a-z-]+(?:/range)?\\s+\\{([^}]*)\\},\\s*(\\S+?)->([^(\\s]+)\\(([^)]*)\\)(\\S+)$")

    private val validationRe = rx(
        "Ljava/lang/String;->(startsWith|endsWith|matches|contains)\\(|Ljava/util/(List|Set|Collection|ArrayList|HashSet);->contains\\(|" +
            "->(getHost|getScheme|getAuthority|getCanonicalPath|getCanonicalFile|normalize|sqlEscapeString|isDigitsOnly|isHttpsUrl|isValidUrl)\\(|" +
            "Ljava/util/regex/|const-string [vp]\\d+, \"\\.\\.\""
    )

    private fun paramTypes(desc: String): List<String> {
        val out = ArrayList<String>()
        var i = 0
        while (i < desc.length) {
            val start = i
            while (i < desc.length && desc[i] == '[') i++
            if (i >= desc.length) break
            if (desc[i] == 'L') {
                val semi = desc.indexOf(';', i)
                i = if (semi < 0) desc.length else semi + 1
            } else {
                i++
            }
            out.add(desc.substring(start, i))
        }
        return out
    }

    /** Register position (inside the argument register list, receiver excluded) where each parameter starts; long / double take two. */
    private fun slotsOf(types: List<String>): IntArray {
        val a = IntArray(types.size)
        var s = 0
        for (k in types.indices) {
            a[k] = s
            s += if (types[k] == "J" || types[k] == "D") 2 else 1
        }
        return a
    }

    private fun regsOf(s: String): List<String> {
        val t = s.trim()
        if (t.isEmpty()) return emptyList()
        val dots = t.indexOf("..")
        if (dots >= 0) {
            val a = t.substring(0, dots).trim()
            val b = t.substring(dots + 2).trim()
            if (a.length < 2 || b.length < 2 || a[0] != b[0]) return emptyList()
            val lo = a.substring(1).toIntOrNull() ?: return emptyList()
            val hi = b.substring(1).toIntOrNull() ?: return emptyList()
            if (hi < lo || hi - lo > 255) return emptyList()
            val out = ArrayList<String>()
            for (n in lo..hi) out.add(a[0].toString() + n)
            return out
        }
        return t.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun newMethod(line: String): MInfo? {
        val body = line.removePrefix(".method").trim()
        val lastSp = body.lastIndexOf(' ')
        val sig = if (lastSp < 0) body else body.substring(lastSp + 1)
        val open = sig.indexOf('(')
        val close = sig.indexOf(')')
        if (open < 0 || close < open) return null
        val name = sig.substring(0, open)
        val desc = sig.substring(open + 1, close)
        val mods = if (lastSp < 0) "" else body.substring(0, lastSp)
        val isStatic = mods.split(' ').contains("static")
        return MInfo(sig, name, isStatic, paramTypes(desc))
    }

    private fun parseMethods(text: String): List<MInfo> {
        val out = ArrayList<MInfo>()
        var cur: MInfo? = null
        var pos = 0
        val n = text.length
        while (pos < n) {
            var e = text.indexOf('\n', pos)
            if (e < 0) e = n
            var s = pos
            while (s < e && (text[s] == ' ' || text[s] == '\t' || text[s] == '\r')) s++
            var f = e
            while (f > s && (text[f - 1] == ' ' || text[f - 1] == '\t' || text[f - 1] == '\r')) f--
            if (f > s) {
                val line = text.substring(s, f)
                val c = cur
                if (c == null) {
                    if (line.startsWith(".method ")) cur = newMethod(line)
                } else if (line.startsWith(".end method")) {
                    out.add(c)
                    cur = null
                } else {
                    if (line.startsWith(".annotation") && line.contains("Landroid/webkit/JavascriptInterface;")) c.jsBridge = true
                    c.lines.add(Line(s, line))
                }
            }
            pos = e + 1
        }
        return out
    }

    // ---------- analysis ----------

    private fun best(a: Taint?, b: Taint?): Taint? = if (a == null) b else if (b == null) a else if (b.level > a.level) b else a

    private fun bestOf(list: List<String>, regs: HashMap<String, Taint>): Taint? {
        var r: Taint? = null
        for (x in list) r = best(r, regs[x])
        return r
    }

    private fun shortOwner(owner: String): String = owner.removePrefix("L").removeSuffix(";").substringAfterLast('/').replace('$', '.')

    /** 0.49.0: a tainted register is passed to a method of the app's own code (same class or another one): remember callee + slot. */
    private fun recordEdges(st: State, regs: HashMap<String, Taint>, list: List<String>, owner: String, name: String, desc: String, ret: String) {
        val rec = st.rec ?: return
        if (st.appPrefix.isEmpty() || !owner.startsWith(st.appPrefix)) return
        val key = owner + "->" + name + "(" + desc + ")" + ret
        for ((k, r) in list.withIndex()) {
            val x = regs[r] ?: continue
            rec.edge(x.src, x.level, key, k)
        }
    }

    private fun doInvoke(t: String, off: Int, m: MInfo, st: State, regs: HashMap<String, Taint>, hits: MutableList<Hit>?): Taint? {
        val mm = invokeRe.find(t) ?: return null
        val list = regsOf(mm.groupValues[1])
        val owner = mm.groupValues[2]
        val name = mm.groupValues[3]
        val desc = mm.groupValues[4]
        val ret = mm.groupValues[5]
        val isStatic = t.startsWith("invoke-static")
        val anyT: Taint? = bestOf(list, regs)
        if (anyT != null && st.rec != null) recordEdges(st, regs, list, owner, name, desc, ret)

        // sink check: the receiver or one of the listed parameters is tainted
        if (hits != null && anyT != null) {
            val cands = sinkIndex[owner + "->" + name]
            if (cands != null) {
                val slots = slotsOf(paramTypes(desc))
                val argBase = if (isStatic) 0 else 1
                for (s in cands) {
                    if (s.descPrefix.isNotEmpty() && !desc.startsWith(s.descPrefix)) continue
                    var tt: Taint? = null
                    for (a in s.args) {
                        val ri = if (a == -1) (if (isStatic) -1 else 0) else if (a < slots.size) argBase + slots[a] else -1
                        if (ri < 0) continue
                        val rn = list.getOrNull(ri) ?: continue
                        tt = best(tt, regs[rn])
                    }
                    if (tt != null) hits.add(Hit(s, off, tt, m))
                }
            }
        }

        // the value produced by this call (consumed by the following move-result-object)
        val src = sourceOf(owner, name)
        if (src != null) return src
        if (isSanitizer(owner, name)) return null

        if (owner == st.ownerType) {
            val key = name + "(" + desc + ")" + ret
            if (anyT != null) {
                for ((k, r) in list.withIndex()) {
                    val x = regs[r]
                    if (x != null) st.raise(st.seeds.getOrPut(key) { HashMap() }, "p" + k, x)
                }
            }
            val known = st.returns[key]
            if (known != null) return known
            if (st.rec != null && (ret.startsWith("L") || ret.startsWith("["))) return Taint(1, "@R" + owner + "->" + key)
            return null
        }

        val kind = kindOf(owner)
        if (kind != 0) {
            if (anyT == null) return null
            val recv = if (isStatic) null else list.getOrNull(0)
            if (recv != null && (kind == 2 || name == "<init>")) {
                val argT = bestOf(list.drop(1), regs)
                if (argT != null) regs[recv] = best(regs[recv], argT) ?: argT
            }
            return anyT
        }

        // 0.49.0 (summaries only): the result of a call into another app class is a symbolic value "@R<callee>"
        if (st.rec != null && st.appPrefix.isNotEmpty() && owner.startsWith(st.appPrefix) && (ret.startsWith("L") || ret.startsWith("["))) {
            return Taint(1, "@R" + owner + "->" + name + "(" + desc + ")" + ret)
        }

        // unknown call into the app's own code: keep a weaker trace (the callee may or may not return the data)
        if (anyT != null && st.appPrefix.isNotEmpty() && owner.startsWith(st.appPrefix) && (ret.startsWith("L") || ret.startsWith("["))) {
            return Taint(1, anyT.src + " via " + shortOwner(owner) + "." + name + "()")
        }
        return null
    }

    private fun runMethod(m: MInfo, st: State, hits: MutableList<Hit>?, isProvider: Boolean) {
        val regs = HashMap<String, Taint>()
        val seeded = st.seeds[m.key]
        if (seeded != null) regs.putAll(seeded)
        if (m.jsBridge || (isProvider && providerMethods.contains(m.name))) {
            val slots = slotsOf(m.paramTypes)
            val base = if (m.isStatic) 0 else 1
            val tt = if (m.jsBridge) Taint(2, "a JavaScript-bridge parameter (called by web content)")
            else Taint(1, "a ContentProvider method parameter (other apps can call it when the provider is exported)")
            for (k in m.paramTypes.indices) {
                val ty = m.paramTypes[k]
                if (ty.startsWith("L") || ty.startsWith("[")) regs["p" + (base + slots[k])] = tt
            }
        }
        if (st.rec != null) {
            // 0.49.0: every object parameter that is not already a real source gets the label "@P<slot>" (slot = position in an invoke's register list)
            val slots = slotsOf(m.paramTypes)
            val base = if (m.isStatic) 0 else 1
            for (k in m.paramTypes.indices) {
                val ty = m.paramTypes[k]
                if (!(ty.startsWith("L") || ty.startsWith("["))) continue
                val slot = base + slots[k]
                if (regs["p$slot"] == null) regs["p$slot"] = Taint(2, "@P$slot")
            }
        }
        var pending: Taint? = null
        for (ln in m.lines) {
            val t = ln.text
            val c0 = t[0]
            if (c0 == '.' || c0 == ':' || c0 == '#') continue
            val prev = pending
            pending = null
            val sp = t.indexOf(' ')
            val op = if (sp < 0) t else t.substring(0, sp)
            if (op.startsWith("invoke-")) {
                pending = doInvoke(t, ln.off, m, st, regs, hits)
                continue
            }
            if (sp < 0) continue
            if (op.startsWith("filled-new-array")) {
                pending = bestOf(regsOf(t.substringAfter('{').substringBefore('}')), regs)
                continue
            }
            val parts = t.substring(sp + 1).split(',').map { it.trim() }
            val d = parts[0]
            when {
                op.startsWith("move-result") -> {
                    if (op == "move-result-object" && prev != null) regs[d] = prev else regs.remove(d)
                }
                op == "move-exception" -> regs.remove(d)
                op.startsWith("move") -> {
                    val s = parts.getOrNull(1)
                    val tt = if (s != null) regs[s] else null
                    if (tt != null) regs[d] = tt else regs.remove(d)
                }
                op.startsWith("iget") -> {
                    val f = parts.getOrNull(2)
                    val tt = if (f != null) st.fields[f] else null
                    if (tt != null) regs[d] = tt else regs.remove(d)
                }
                op.startsWith("sget") -> {
                    val f = parts.getOrNull(1)
                    val tt = if (f != null) st.fields[f] else null
                    if (tt != null) regs[d] = tt else regs.remove(d)
                }
                op.startsWith("iput") -> {
                    val tt = regs[d]
                    val f = parts.getOrNull(2)
                    if (tt != null && f != null) st.raise(st.fields, f, tt)
                }
                op.startsWith("sput") -> {
                    val tt = regs[d]
                    val f = parts.getOrNull(1)
                    if (tt != null && f != null) st.raise(st.fields, f, tt)
                }
                op.startsWith("aget") -> {
                    val a = parts.getOrNull(1)
                    val tt = if (a != null) regs[a] else null
                    if (tt != null) regs[d] = tt else regs.remove(d)
                }
                op.startsWith("aput") -> {
                    val a = parts.getOrNull(1)
                    val tt = regs[d]
                    if (tt != null && a != null) regs[a] = tt
                }
                op.startsWith("return-object") -> {
                    val tt = regs[d]
                    if (tt != null) {
                        st.raise(st.returns, m.key, tt)
                        st.rec?.ret(tt.src, tt.level)
                    }
                }
                op.startsWith("return") || op.startsWith("if-") || op.startsWith("goto") || op == "throw" ||
                    op.startsWith("monitor") || op.endsWith("-switch") || op == "check-cast" || op == "fill-array-data" -> {
                }
                else -> regs.remove(d)
            }
        }
    }

    /**
     * 0.49.0: stage A of the cross-class analysis (see TaintLinker.kt). Runs the register analysis again with symbolic taints and
     * hands the per-method summaries to [linker]. Findings are NOT produced here; [scan] stays unchanged.
     */
    fun summarize(classType: String, clsIndex: Int, text: String, appPkg: String, linker: TaintLinker) {
        val appPrefix = appPrefixOf(appPkg)
        if (appPrefix.isEmpty() || text.indexOf("invoke-") < 0) return
        val hasSink = sinkOwners.any { text.contains(it) }
        val isProvider = text.contains(".super Landroid/content/ContentProvider;")
        val hasSource = text.contains("Landroid/content/Intent;->get") || text.contains("Landroid/webkit/JavascriptInterface;") || isProvider
        val methods = parseMethods(text)
        if (methods.isEmpty()) return
        val st = State(classType, appPrefix)
        if (hasSource) {
            var round = 0
            do {
                st.changed = false
                for (m in methods) runMethod(m, st, null, isProvider)
                round++
            } while (st.changed && round < MAX_ROUNDS)
        }
        val rec = XRecorder(classType, clsIndex, text)
        st.rec = rec
        for (m in methods) {
            var touches = false
            for (ln in m.lines) {
                val t = ln.text
                if (!t.startsWith("invoke-")) continue
                if (t.contains(appPrefix) || (hasSink && sinkOwners.any { t.contains(it) })) { touches = true; break }
            }
            if (!touches) continue
            rec.begin(m.key, m.name)
            val hits = ArrayList<Hit>()
            runMethod(m, st, hits, isProvider)
            for (h in hits) {
                if (!h.taint.src.startsWith("@")) continue   // real-source flows inside the class are reported by [scan]
                rec.hit(h.taint.src, shortOwner(h.sink.owner) + "." + h.sink.name, h.sink.title, h.sink.sev, h.sink.cwe,
                    h.sink.what, h.sink.fix, h.sink.inherent, h.off, hasValidation(h.m))
            }
            rec.end()
        }
        if (rec.methods.isNotEmpty()) linker.add(rec.methods)
    }

    private fun appPrefixOf(appPkg: String): String {
        if (appPkg.isEmpty()) return ""
        val segs = appPkg.split('.')
        return "L" + (if (segs.size >= 2) segs.take(2) else segs).joinToString("/") + "/"
    }

    private fun lowerOne(s: SecurityScanner.Severity): SecurityScanner.Severity {
        val next = minOf(SecurityScanner.Severity.INFO.rank, s.rank + 1)
        return SecurityScanner.Severity.values().first { it.rank == next }
    }

    private fun hasValidation(m: MInfo): Boolean {
        val cached = m.validation
        if (cached != null) return cached
        var v = false
        for (ln in m.lines) {
            if (validationRe.containsMatchIn(ln.text)) { v = true; break }
        }
        m.validation = v
        return v
    }

    fun scan(ctx: RuleContext): List<SecurityScanner.Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        val isProvider = text.contains(".super Landroid/content/ContentProvider;")
        val hasSource = text.contains("Landroid/content/Intent;->get") || text.contains("Landroid/webkit/JavascriptInterface;") ||
            text.contains("Landroid/content/SharedPreferences;->get") || isProvider
        if (!hasSource) return emptyList()
        if (!sinkOwners.any { text.contains(it) }) return emptyList()

        val methods = parseMethods(text)
        if (methods.isEmpty()) return emptyList()
        val st = State(ctx.classType, appPrefixOf(ctx.appPkg))
        var round = 0
        do {
            st.changed = false
            for (m in methods) runMethod(m, st, null, isProvider)
            round++
        } while (st.changed && round < MAX_ROUNDS)
        val hits = ArrayList<Hit>()
        for (m in methods) runMethod(m, st, hits, isProvider)
        if (hits.isEmpty()) return emptyList()

        val out = ArrayList<SecurityScanner.Finding>()
        val seen = HashSet<String>()
        for (h in hits) {
            if (out.size >= MAX_FINDINGS) break
            if (!seen.add(h.sink.title + "|" + h.m.key)) continue
            val validation = hasValidation(h.m)
            var conf = if (h.taint.level >= 2) "HIGH" else "MEDIUM"
            if (h.sink.inherent == "MEDIUM" && conf == "HIGH") conf = "MEDIUM"
            if (validation) conf = if (conf == "HIGH") "MEDIUM" else "LOW"
            // 0.46.2: reading shared prefs and then opening a file / URL is everyday code, so these flows stay LOW (severity lowered one level)
            val fromPrefs = h.taint.src.startsWith("SharedPreferences.")
            if (fromPrefs) conf = "LOW"
            var sev = h.sink.sev
            if (conf == "LOW") sev = lowerOne(sev)
            val sb = StringBuilder()
            sb.append("Data from ").append(h.taint.src).append(" reaches ")
                .append(shortOwner(h.sink.owner)).append('.').append(h.sink.name).append("() in method ").append(h.m.name)
                .append("(): ").append(h.sink.what).append(". The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way.")
            if (h.taint.src.startsWith("Intent.")) sb.append(" An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.")
            if (fromPrefs) sb.append(" The source is SharedPreferences, which only an attacker with root or a tampered backup can change: treat this as a lead, not as a confirmed flaw.")
            if (validation) sb.append(" The method also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.")
            val f = ctx.finding(sev, h.sink.title, sb.toString(), h.sink.fix, h.off, h.sink.cwe)
            f.confidence = conf
            f.ruleId = TaintFlowRule.id
            out.add(f)
        }
        return out
    }
}

/** Source-to-sink flows inside one class (see [TaintEngine]). */
object TaintFlowRule : ScanRule {
    override val id = "taint-flow"
    override val title = "Untrusted input flows into a dangerous API (taint analysis)"
    override val cwes = listOf("CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-470", "CWE-94", "CWE-918")

    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> = TaintEngine.scan(ctx)
}
