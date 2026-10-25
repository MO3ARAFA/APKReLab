package dev.apkrelab.ir;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 0.55.0 (P1, first experimental version): taint analysis on the SSA form of every REACHABLE app method, chained across methods
 * with per-method summaries over the {@link CallGraph}. It is a SEPARATE report: nothing in the scanner reads it, so no existing
 * finding changes. Source and sink tables mirror the Kotlin TaintEngine (same titles), so the two can be compared item by item.
 *
 * Model
 *  - A taint value ({@link Tv}) is a set of symbolic parameter labels (bit k = "logical argument k of this method", receiver = 0 for
 *    instance methods) plus at most one REAL source (Intent extra, SharedPreferences ...) with a level (2 = intent, 1 = prefs).
 *  - Every SSA {@link SsaForm.Value} gets one taint value. A value only grows (monotone), phis join their operands, and the method
 *    is iterated until nothing changes. Taint is flow-insensitive per value (not per program point), which is sound and only a
 *    little imprecise because SSA already separates the versions of a register.
 *  - Objects that accumulate data (StringBuilder, Bundle, collections, arrays ...) are mutated in place: the argument's taint is
 *    added to the receiver value AND to every value it aliases through move / check-cast / phi (see {@code raiseObj}).
 *  - Summary of a method: which parameters reach its return value, whether it returns a real source, and which parameters reach a
 *    sink (with the chain of methods down to the sink, depth at most {@link #MAX_DEPTH}). Summaries are solved with a worklist:
 *    when a summary changes, its callers are analysed again.
 *  - Fields: a real source stored into a field is remembered per field reference (field-based, not object-based) and read back by
 *    every method that reads that field. Symbolic parameter labels never go into fields.
 *  - SharedPreferences (0.67.0): Editor.putString / putStringSet store a real source under "prefs:<key>" in the same map; getString /
 *    getStringSet / getAll read it back (key literal, or a wildcard when the key is not a literal).
 *  - Calls: app callees come from the CallGraph edges of that call site (so virtual dispatch follows the RTA graph); framework
 *    callees use the same tables as the Kotlin engine (source / sanitizer / builder / pure transform / sink).
 *
 * Limits (same honesty as the Kotlin engine): no path sensitivity, no reflection, no taint through unknown library calls,
 * parameters of other methods are not mutated by a callee (only the return value and sinks are tracked).
 */
public final class TaintIr {
    private TaintIr() {
    }

    public static final int MAX_DEPTH = 6;       // methods in one flow chain
    public static final int MAX_REFS = 16;       // sink references kept per parameter slot
    public static final int MAX_ROUNDS = 30;     // iterations of one method body
    public static final int MAX_APPROX_TARGETS = 64;   // 0.68.0: callees followed per call site when the edges come from the CHA fallback ("virtual~" / "interface~")
    public static final int MAX_REQUEUE = 40;    // a method is analysed at most this many times (guarantees termination)

    // ======================================================================================== taint value

    static final class Tv {
        static final Tv NONE = new Tv(0L, 0, null, null);

        final long params;     // bit k = logical argument k (k < 64)
        final int level;       // 0 = no real source
        final String src;
        final String via;      // callee / field the real source came through, or null
        final boolean weak;    // 0.68.5: the real source passed an Object field of an obfuscated (merged) class; a strong path wins in a join
        final boolean internal; // 0.68.6: the Intent was read in a component the manifest does not export (implies weak)

        Tv(long params, int level, String src, String via) {
            this(params, level, src, via, false, false);
        }

        Tv(long params, int level, String src, String via, boolean weak) {
            this(params, level, src, via, weak, false);
        }

        Tv(long params, int level, String src, String via, boolean weak, boolean internal) {
            this.params = params;
            this.level = level;
            this.src = level > 0 ? src : null;
            this.via = level > 0 ? via : null;
            this.internal = level > 0 && internal;
            this.weak = level > 0 && (weak || internal);
        }

        /** 0.68.5: a strong source of any level beats a weak one; within the same strength the higher level wins. */
        static int rankOf(int level, boolean weak) {
            return level == 0 ? 0 : (weak ? level : level + 8);
        }

        int rank() {
            return rankOf(level, weak);
        }

        Tv asWeak() {
            return level > 0 && !weak ? new Tv(params, level, src, via, true, internal) : this;
        }

        /** 0.68.6: a real source read in a component that is not exported. */
        static Tv internalSource(int level, String src, String via) {
            return new Tv(0L, level, src, via, true, true);
        }

        static Tv param(int k) {
            return k >= 0 && k < 64 ? new Tv(1L << k, 0, null, null) : NONE;
        }

        static Tv real(int level, String src, String via) {
            return new Tv(0L, level, src, via);
        }

        static Tv real(int level, String src, String via, boolean weak) {
            return new Tv(0L, level, src, via, weak);
        }

        static Tv real(int level, String src, String via, boolean weak, boolean internal) {
            return new Tv(0L, level, src, via, weak, internal);
        }

        boolean isNone() {
            return params == 0L && level == 0;
        }

        Tv join(Tv o) {
            if (o == null || o.isNone()) return this;
            if (isNone()) return o;
            long p = params | o.params;
            if (rank() >= o.rank()) return p == params ? this : new Tv(p, level, src, via, weak, internal);
            return new Tv(p, o.level, o.src, o.via, o.weak, o.internal);
        }

        boolean covers(Tv o) {
            return (params & o.params) == o.params && rank() >= o.rank();
        }

        Tv realOnly() {
            return level > 0 ? new Tv(0L, level, src, via, weak, internal) : NONE;
        }
    }

    // ======================================================================================== tables (mirror of TaintEngine)

    static final class Sink {
        final String owner, name, title, sev, cwe, descPrefix;
        final int[] args;     // parameter indexes that matter, -1 = receiver

        Sink(String owner, String name, int[] args, String title, String sev, String cwe, String descPrefix) {
            this.owner = owner;
            this.name = name;
            this.args = args;
            this.title = title;
            this.sev = sev;
            this.cwe = cwe;
            this.descPrefix = descPrefix;
        }
    }

    static final String T_WEB = "Untrusted input is loaded into a WebView";
    static final String T_JS = "Untrusted input is run as JavaScript in a WebView";
    static final String T_SQL = "Untrusted input reaches an SQL statement";
    static final String T_CMD = "Untrusted input reaches a shell command";
    static final String T_FILE = "Untrusted input is used as a file path";
    static final String T_REFL = "Untrusted input selects a class or method by name";
    static final String T_CODE = "Untrusted input is loaded as code or a native library";
    /** 0.86.1 (recall kit case 36): ObjectInputStream built over untrusted bytes. */
    static final String T_DESER = "Untrusted data is deserialized (ObjectInputStream)";
    static final String T_SSRF = "Untrusted input chooses the server the app contacts";
    static final String T_URI = "Untrusted input chooses the file or content URI the app opens";
    static final String T_REDIRECT = "Untrusted Intent is launched by this app (intent redirection)";

    // 0.74.0: intent redirection. The Intent OBJECT that came from the caller (getParcelableExtra) is handed to startActivity / startService /
    // sendBroadcast: the app launches whatever component the attacker names, with the app's own identity and permissions (InsecureShop PrivateActivity).
    // Only that source counts: an Intent that merely CARRIES tainted extras (putExtra / putExtras(getExtras())) is the normal forwarding pattern and stays
    // quiet. Kept out of SINKS on purpose: SINKS feeds the scope planner, and every big app calls Context.startActivity in hundreds of classes. The
    // owner is usually the app's own Activity class (invoke-virtual {p0, v0}, Lapp/Main;->startActivity), so the match is by method name + signature.
    static final Set<String> REDIRECT_NAMES = new HashSet<>(Arrays.asList(
            "startActivity", "startActivityForResult", "startService", "startForegroundService", "sendBroadcast", "bindService"));
    static final Set<String> REDIRECT_SOURCES = new HashSet<>(Arrays.asList("Intent.getParcelableExtra()"));
    private static final Map<String, Sink> REDIRECT_SINKS = new HashMap<>();
    static {
        for (String n : REDIRECT_NAMES)
            REDIRECT_SINKS.put(n, new Sink("Landroid/content/Context;", n, new int[]{0}, T_REDIRECT, "HIGH", "CWE-940", "(Landroid/content/Intent;"));
    }

    private static final Map<String, List<Sink>> SINKS = new HashMap<>();

    private static void sink(String owner, String name, int[] args, String title, String sev, String cwe, String prefix) {
        SINKS.computeIfAbsent(owner + "->" + name, k -> new ArrayList<>()).add(new Sink(owner, name, args, title, sev, cwe, prefix));
    }

    private static void sink(String owner, String name, int[] args, String title, String sev, String cwe) {
        sink(owner, name, args, title, sev, cwe, "");
    }

    private static int[] a(int... x) {
        return x;
    }

    static {
        String wv = "Landroid/webkit/WebView;", db = "Landroid/database/sqlite/SQLiteDatabase;";
        sink(wv, "loadUrl", a(0), T_WEB, "HIGH", "CWE-79");
        sink(wv, "loadData", a(0), T_WEB, "HIGH", "CWE-79");
        sink(wv, "loadDataWithBaseURL", a(0, 1), T_WEB, "HIGH", "CWE-79");
        sink(wv, "evaluateJavascript", a(0), T_JS, "HIGH", "CWE-79");
        sink(db, "rawQuery", a(0), T_SQL, "HIGH", "CWE-89");
        sink(db, "rawQueryWithFactory", a(1), T_SQL, "HIGH", "CWE-89");
        sink(db, "execSQL", a(0), T_SQL, "HIGH", "CWE-89");
        sink(db, "compileStatement", a(0), T_SQL, "HIGH", "CWE-89");
        sink(db, "query", a(0, 2, 4, 5, 6), T_SQL, "HIGH", "CWE-89", "Ljava/lang/String;");
        sink(db, "query", a(1, 3, 5, 6, 7), T_SQL, "HIGH", "CWE-89", "Z");
        sink(db, "delete", a(0, 1), T_SQL, "HIGH", "CWE-89");
        sink(db, "update", a(0, 2), T_SQL, "HIGH", "CWE-89");
        sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "appendWhere", a(0), T_SQL, "HIGH", "CWE-89");
        sink("Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", a(0), T_SQL, "HIGH", "CWE-89");
        // 0.72.0: SQLiteQueryBuilder.query / buildQuery* / update / delete (the usual ContentProvider.query body). Only the bound selectionArgs are safe.
        String qb = "Landroid/database/sqlite/SQLiteQueryBuilder;";
        sink(qb, "query", a(1, 2, 4, 5, 6, 7), T_SQL, "HIGH", "CWE-89");               // (db, projection, selection, args, groupBy, having, sortOrder[, limit])
        sink(qb, "buildQuery", a(0, 1, 2, 3, 4, 5), T_SQL, "HIGH", "CWE-89");          // (projection, selection, groupBy, having, sortOrder, limit)
        sink(qb, "buildQueryString", a(1, 2, 3, 4, 5, 6, 7), T_SQL, "HIGH", "CWE-89"); // static (distinct, tables, columns, where, groupBy, having, orderBy, limit)
        sink(qb, "update", a(2), T_SQL, "HIGH", "CWE-89");                              // (db, values, selection, args)
        sink(qb, "delete", a(1), T_SQL, "HIGH", "CWE-89");                              // (db, selection, args)
        sink("Landroidx/sqlite/db/SupportSQLiteDatabase;", "query", a(0), T_SQL, "HIGH", "CWE-89");
        sink("Landroidx/sqlite/db/SupportSQLiteDatabase;", "execSQL", a(0), T_SQL, "HIGH", "CWE-89");
        sink("Landroidx/sqlite/db/SimpleSQLiteQuery;", "<init>", a(0), T_SQL, "HIGH", "CWE-89");
        sink("Ljava/io/ObjectInputStream;", "<init>", a(0), T_DESER, "HIGH", "CWE-502");   // 0.86.1
        sink("Ljava/lang/Runtime;", "exec", a(0), T_CMD, "CRITICAL", "CWE-78");
        sink("Ljava/lang/ProcessBuilder;", "<init>", a(0), T_CMD, "CRITICAL", "CWE-78");
        sink("Ljava/lang/ProcessBuilder;", "command", a(0), T_CMD, "CRITICAL", "CWE-78");
        sink("Ljava/io/FileInputStream;", "<init>", a(0), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/io/FileOutputStream;", "<init>", a(0), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/io/FileReader;", "<init>", a(0), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/io/FileWriter;", "<init>", a(0), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/io/RandomAccessFile;", "<init>", a(0), T_FILE, "HIGH", "CWE-22");
        sink("Landroid/os/ParcelFileDescriptor;", "open", a(0), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/io/File;", "delete", a(-1), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/io/File;", "renameTo", a(-1), T_FILE, "HIGH", "CWE-22");
        sink("Ljava/lang/Class;", "forName", a(0), T_REFL, "HIGH", "CWE-470");
        sink("Ljava/lang/ClassLoader;", "loadClass", a(0), T_REFL, "HIGH", "CWE-470");
        sink("Ljava/lang/Class;", "getMethod", a(0), T_REFL, "MEDIUM", "CWE-470");
        sink("Ljava/lang/Class;", "getDeclaredMethod", a(0), T_REFL, "MEDIUM", "CWE-470");
        sink("Ldalvik/system/DexClassLoader;", "<init>", a(0, 2), T_CODE, "CRITICAL", "CWE-94");
        sink("Ldalvik/system/PathClassLoader;", "<init>", a(0), T_CODE, "CRITICAL", "CWE-94");
        sink("Ljava/lang/System;", "load", a(0), T_CODE, "CRITICAL", "CWE-94");
        sink("Ljava/lang/System;", "loadLibrary", a(0), T_CODE, "HIGH", "CWE-94");
        sink("Ljava/lang/Runtime;", "load", a(0), T_CODE, "CRITICAL", "CWE-94");
        sink("Ljava/net/URL;", "<init>", a(0), T_SSRF, "MEDIUM", "CWE-918");
        sink("Lokhttp3/Request$Builder;", "url", a(0), T_SSRF, "MEDIUM", "CWE-918");
        // 0.72.0: the caller picks the URI the app opens. A file:// or content:// URI the attacker controls makes the app read its OWN private files
        // (or another provider's data) and hand the bytes on (copy, upload, show). MEDIUM: it depends on what is done with the stream.
        String cr = "Landroid/content/ContentResolver;";
        sink(cr, "openInputStream", a(0), T_URI, "MEDIUM", "CWE-73");
        sink(cr, "openOutputStream", a(0), T_URI, "MEDIUM", "CWE-73");
        sink(cr, "openFileDescriptor", a(0), T_URI, "MEDIUM", "CWE-73");
        sink(cr, "openAssetFileDescriptor", a(0), T_URI, "MEDIUM", "CWE-73");
    }

    static final Set<String> INTENT_SOURCES = new HashSet<>(Arrays.asList(
            "getStringExtra", "getStringArrayExtra", "getStringArrayListExtra", "getCharSequenceExtra", "getCharSequenceArrayExtra",
            "getParcelableExtra", "getParcelableArrayExtra", "getParcelableArrayListExtra", "getSerializableExtra",
            "getExtras", "getBundleExtra", "getData", "getDataString",
            "getByteArrayExtra"));   // 0.86.1 (recall kit case 36): a byte[] extra carries serialized objects / binary payloads
    private static final Set<String> PREFS_SOURCES = new HashSet<>(Arrays.asList("getString", "getStringSet", "getAll"));

    // 0.67.0 (heap model, step 1): SharedPreferences. A string (set) written with Editor.putString / putStringSet is remembered per KEY
    // (the string literal of the key argument) and handed back by SharedPreferences.getString / getStringSet with the same key.
    // Not tracked: the preferences FILE name (same key in two files is mixed), keys built at run time (see PREFS_UNKNOWN), other value types.
    private static final String PREFS_OWNER = "Landroid/content/SharedPreferences;";
    private static final String EDITOR_OWNER = "Landroid/content/SharedPreferences$Editor;";
    private static final Set<String> PREFS_PUTS = new HashSet<>(Arrays.asList("putString", "putStringSet"));
    private static final String PREFS_PREFIX = "prefs:";
    private static final String PREFS_UNKNOWN = "prefs:*";   // written with a key that is not a literal: a read of any key sees it
    private static final String PREFS_ANY = "prefs:?";       // every write ends here too: read by getAll and by a read whose key is not a literal

    // 0.74.0: Parcel reads inside the methods that unmarshal an object (a Parcelable constructor / CREATOR.createFromParcel / readFromParcel, or a Binder
    // onTransact). The Parcel is filled by another process when the object arrives through an Intent extra or an exported service (OVAA
    // MemoryCorruptionParcelable: Class.forName(parcel.readString())). Level 1 (a lead): many Parcelables only travel inside the app.
    static final String PARCEL_OWNER = "Landroid/os/Parcel;";
    static final Set<String> PARCEL_SOURCES = new HashSet<>(Arrays.asList(
            "readString", "createStringArray", "createStringArrayList", "readStringArray", "readStringList", "readCharSequence",
            "readBundle", "readParcelable", "readSerializable", "readHashMap", "readValue"));
    private static final Set<String> PARCEL_ENTRY_METHODS = new HashSet<>(Arrays.asList("<init>", "createFromParcel", "readFromParcel", "onTransact"));

    // 0.74.0: the NAME of an archive entry (Zip Slip, CWE-22): "../../x" in a zip that came from outside makes the extraction write outside its folder.
    // Level 1; the canonical-path / startsWith guard is already recognised by SsaBridge.hasValidation, which lowers the confidence.
    private static final Set<String> ZIP_ENTRY_OWNERS = new HashSet<>(Arrays.asList(
            "Ljava/util/zip/ZipEntry;", "Ljava/util/jar/JarEntry;", "Lorg/apache/commons/compress/archivers/ArchiveEntry;",
            "Lorg/apache/commons/compress/archivers/zip/ZipArchiveEntry;", "Lorg/apache/commons/compress/archivers/tar/TarArchiveEntry;"));

    /** {level, name} of a real source, or null. */
    static Tv sourceOf(String owner, String name) {
        if (owner.equals("Landroid/content/Intent;") && INTENT_SOURCES.contains(name)) return Tv.real(2, "Intent." + name + "()", null);
        if (owner.equals("Landroid/content/SharedPreferences;") && PREFS_SOURCES.contains(name))
            return Tv.real(1, "SharedPreferences." + name + "()", null);
        if (name.equals("getName") && ZIP_ENTRY_OWNERS.contains(owner)) return Tv.real(1, "ZipEntry.getName()", null);
        return null;
    }

    /** 0.57.0: owners of every sink API (the scope planner looks for them in the invoke lines of a big app). */
    static Set<String> sinkOwners() {
        Set<String> out = sinkOwners;
        if (out == null) {
            out = new HashSet<>();
            for (List<Sink> l : SINKS.values()) for (Sink k : l) out.add(k.owner);
            sinkOwners = out = Collections.unmodifiableSet(out);       // 1.0.0: built once (CallSkeleton.digest asked for it once per class)
        }
        return out;
    }

    private static volatile Set<String> sinkOwners;

    /** 0.57.0: true when owner->name is one of the sink APIs. */
    static boolean isSink(String owner, String name) {
        return SINKS.containsKey(owner + "->" + name);
    }

    static boolean isSanitizer(String owner, String name) {
        switch (owner) {
            case "Ljava/net/URLEncoder;":
                return name.equals("encode");
            case "Landroid/text/TextUtils;":
                return name.equals("htmlEncode");
            case "Landroid/database/DatabaseUtils;":
                return name.startsWith("sqlEscape");
            case "Landroid/net/Uri;":
                return name.equals("encode");
            case "Landroid/text/Html;":
                return name.equals("escapeHtml");
            case "Ljava/io/File;":
                return name.equals("getName");
            case "Ljava/lang/Integer;": case "Ljava/lang/Long;": case "Ljava/lang/Double;": case "Ljava/lang/Float;":
            case "Ljava/lang/Boolean;": case "Ljava/lang/Short;": case "Ljava/lang/Byte;": case "Ljava/util/UUID;":
                return true;
            default:
                return false;
        }
    }

    private static final Set<String> BUILDERS = new HashSet<>(Arrays.asList(
            "Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;", "Landroid/net/Uri$Builder;",
            "Landroid/os/Bundle;", "Landroid/os/BaseBundle;", "Lkotlin/Lazy;", "Lkotlin/UnsafeLazyImpl;", "Lkotlin/SynchronizedLazyImpl;", "Lorg/json/JSONObject;", "Lorg/json/JSONArray;",
            "Ljava/util/ArrayList;", "Ljava/util/List;", "Ljava/util/LinkedList;", "Ljava/util/Map;", "Ljava/util/HashMap;",
            "Ljava/util/LinkedHashMap;", "Ljava/util/TreeMap;", "Ljava/util/Set;", "Ljava/util/HashSet;", "Ljava/util/Collection;",
            "Ljava/util/Deque;", "Ljava/util/ArrayDeque;", "Ljava/util/Queue;",
            // 0.68.3: container classes the code names directly (NewPipe: AbstractCollection.iterator / size / isEmpty were dropped as unknown library calls)
            "Ljava/util/AbstractCollection;", "Ljava/util/AbstractList;", "Ljava/util/AbstractSet;", "Ljava/util/AbstractMap;",
            "Ljava/util/AbstractSequentialList;", "Ljava/util/AbstractQueue;", "Ljava/util/LinkedHashSet;", "Ljava/util/TreeSet;",
            "Ljava/util/SortedSet;", "Ljava/util/NavigableSet;", "Ljava/util/SortedMap;", "Ljava/util/NavigableMap;",
            "Ljava/util/Vector;", "Ljava/util/Stack;", "Ljava/util/Hashtable;", "Ljava/util/WeakHashMap;", "Ljava/util/IdentityHashMap;",
            "Ljava/util/EnumMap;", "Ljava/util/PriorityQueue;", "Ljava/util/concurrent/ConcurrentHashMap;", "Ljava/util/concurrent/ConcurrentMap;",
            "Ljava/util/concurrent/CopyOnWriteArrayList;", "Ljava/util/concurrent/CopyOnWriteArraySet;",
            "Ljava/util/concurrent/ConcurrentLinkedQueue;", "Ljava/util/concurrent/ConcurrentLinkedDeque;",
            "Ljava/util/concurrent/LinkedBlockingQueue;", "Ljava/util/concurrent/LinkedBlockingDeque;",
            "Landroid/util/ArrayMap;", "Landroidx/collection/ArrayMap;", "Landroid/util/ArraySet;", "Landroidx/collection/ArraySet;",
            "Landroid/util/SparseArray;", "Landroid/content/ContentValues;",
            // 0.68.4 (sandbox measurement on Wikipedia / NewPipe / Mastodon / k9mail): small value holders and builders that were dropped as unknown library calls
            "Lkotlin/Pair;", "Lkotlin/Triple;", "Landroid/database/MatrixCursor;", "Lorg/apache/http/message/BasicNameValuePair;",
            "Lokhttp3/Headers$Builder;", "Lokhttp3/HttpUrl$Builder;", "Lokhttp3/FormBody$Builder;", "Lokhttp3/Request$Builder;"));
    private static final Set<String> PURE = new HashSet<>(Arrays.asList(
            "Ljava/lang/String;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;", "Landroid/net/Uri;", "Ljava/net/URLDecoder;",
            "Ljava/net/URL;", "Ljava/net/URI;", "Ljava/io/File;", "Ljava/util/Objects;", "Landroid/text/TextUtils;",
            "Landroid/content/Intent;", "Ljava/util/Arrays;", "Ljava/util/Iterator;", "Ljava/util/ListIterator;",
            "Ljava/util/Map$Entry;", "Ljava/util/Collections;", "Ljava/lang/Iterable;",
            // 0.68.4: decoders / parsers whose result is the (re-shaped) input
            "Lkotlinx/serialization/json/Json;", "Lkotlinx/serialization/json/Json$Default;", "Landroid/util/Base64;", "Ljava/util/Base64;",
            "Ljava/util/Base64$Decoder;", "Ljava/util/Base64$Encoder;", "Ljava/util/regex/Pattern;", "Ljava/util/regex/Matcher;",
            // 0.77.0 (Termux FileReceiverActivity): a cursor queried from a caller's content URI carries the caller's data, so its columns
            // (OpenableColumns.DISPLAY_NAME = the sharer's file name) are as untrusted as the URI; ContentResolver.query / openInputStream
            // take the URI's taint, Cursor getters return the cursor's
            "Landroid/content/ContentResolver;", "Landroid/database/Cursor;", "Landroid/database/CursorWrapper;",
            // 0.86.1: stream wrappers hand the taint of the bytes / stream they wrap to the object built over them (ObjectInputStream sink)
            "Ljava/io/ByteArrayInputStream;", "Ljava/io/BufferedInputStream;", "Ljava/util/zip/GZIPInputStream;"));   // 0.67.1: Iterable.iterator() hands the collection's taint to the iterator

    /** 0 = unknown, 1 = pure transform, 2 = builder / container. */
    static int kindOf(String owner) {
        if (BUILDERS.contains(owner)) return 2;
        if (PURE.contains(owner)) return 1;
        if (owner.startsWith("Lkotlin/text/") || owner.startsWith("Lkotlin/collections/")) return 1;
        if (owner.startsWith("Ljava/time/") || owner.startsWith("Lj$/time/")) return 1;      // 0.68.4: LocalDate.parse(text) and the like
        return 0;
    }

    /** ContentProvider methods that other apps call with data they control (same list as the Kotlin engine). */
    private static final Set<String> PROVIDER_METHODS = new HashSet<>(Arrays.asList(
            "query", "insert", "update", "delete", "openFile", "openAssetFile", "call", "bulkInsert"));
    private static final Tv PROVIDER_SRC = Tv.real(1, "a ContentProvider method parameter", null);
    /** 0.84.0: the same source in a provider the manifest does NOT export: only the app itself (or a URI it grants) reaches it, so a weak lead. */
    private static final Tv PROVIDER_SRC_INTERNAL = Tv.internalSource(1, "a ContentProvider method parameter", null);

    /** Edge kinds that come from an invoke instruction (callback / clinit / icc / trigger edges pass no arguments). */
    private static final Set<String> INVOKE_KINDS = new HashSet<>(Arrays.asList("static", "direct", "super", "virtual", "interface"));

    // ======================================================================================== descriptors

    /** All parameter types of "name(IJLx/Y;[I)V" (primitives included). */
    static List<String> allParams(String sig) {
        List<String> out = new ArrayList<>();
        int open = sig.indexOf('('), close = sig.indexOf(')');
        if (open < 0 || close < open) return out;
        for (int i = open + 1; i < close; ) {
            int s = i;
            while (i < close && sig.charAt(i) == '[') i++;
            if (i >= close) break;
            if (sig.charAt(i) == 'L') {
                int semi = sig.indexOf(';', i);
                if (semi < 0 || semi > close) break;
                i = semi + 1;
            } else {
                i++;
            }
            out.add(sig.substring(s, i));
        }
        return out;
    }

    /** Position of every logical argument inside a register list (wide values take two entries). */
    static int[] physical(List<String> params, boolean hasReceiver) {
        int n = params.size() + (hasReceiver ? 1 : 0);
        int[] pos = new int[n];
        int p = 0, k = 0;
        if (hasReceiver) pos[k++] = p++;
        for (String t : params) {
            pos[k++] = p;
            p += (t.equals("J") || t.equals("D")) ? 2 : 1;
        }
        return pos;
    }

    // ======================================================================================== results

    /** A sink reached through a chain of app methods. */
    public static final class SinkRef {
        public final String method;       // method that contains the sink call
        public final int insn;
        public final String api, title, sev, cwe;
        public final List<String> chain;  // methods from the first callee down to {@link #method} (inclusive)

        SinkRef(String method, int insn, String api, String title, String sev, String cwe, List<String> chain) {
            this.method = method;
            this.insn = insn;
            this.api = api;
            this.title = title;
            this.sev = sev;
            this.cwe = cwe;
            this.chain = chain;
        }

        String key() {
            return method + "@" + insn + "|" + title;
        }
    }

    static final class Summary {
        long retParams;
        int retLevel;
        String retSrc;
        boolean retWeak;
        boolean retInternal;
        final Map<Integer, Map<String, SinkRef>> sinkParams = new TreeMap<>();
        int refsDropped;      // 0.66.5: sink references not kept because the slot was full (MAX_REFS); measurement only

        void addSink(int slot, SinkRef r) {
            Map<String, SinkRef> m = sinkParams.computeIfAbsent(slot, k -> new LinkedHashMap<>());
            SinkRef old = m.get(r.key());
            if (old != null) {
                if (old.chain.size() <= r.chain.size()) return;
                m.put(r.key(), r);
                return;
            }
            if (m.size() >= MAX_REFS) {
                refsDropped++;
                return;
            }
            m.put(r.key(), r);
        }

        String fingerprint() {
            StringBuilder sb = new StringBuilder();
            sb.append(retParams).append('/').append(retLevel).append('/').append(retSrc).append(retWeak ? "~" : "").append(retInternal ? "!" : "");
            for (Map.Entry<Integer, Map<String, SinkRef>> e : sinkParams.entrySet()) {
                sb.append('|').append(e.getKey()).append(':');
                for (SinkRef r : e.getValue().values()) sb.append(r.key()).append('#').append(r.chain.size()).append(',');
            }
            return sb.toString();
        }

        boolean isEmpty() {
            return retParams == 0L && retLevel == 0 && sinkParams.isEmpty();
        }
    }

    /** One source-to-sink flow with a real source. */
    public static final class Flow {
        public final String source;
        public final int level;
        public final String via;            // callee / field the source came through, or null
        public final boolean weak;          // 0.68.5: the source passed an Object field of an obfuscated (merged) class, or (internal) was read in an unexported component
        public final boolean internal;      // 0.68.6: the Intent was read in a component the manifest does not export
        public final SinkRef sink;
        public final List<String> chain;    // methods from where the tainted value is held down to the sink method
        public boolean reachable;
        public List<String> entryPath = Collections.emptyList();

        Flow(String source, int level, String via, SinkRef sink, List<String> chain) {
            this(source, level, via, false, false, sink, chain);
        }

        Flow(String source, int level, String via, boolean weak, SinkRef sink, List<String> chain) {
            this(source, level, via, weak, false, sink, chain);
        }

        Flow(String source, int level, String via, boolean weak, boolean internal, SinkRef sink, List<String> chain) {
            this.source = source;
            this.level = level;
            this.via = via;
            this.weak = weak || internal;
            this.internal = internal;
            this.sink = sink;
            this.chain = chain;
        }

        public String key() {
            return sink.method + "|" + sink.title;
        }

        public boolean crossesMethods() {
            return chain.size() > 1 || via != null;
        }
    }

    /** Old finding to compare with: the method that holds the sink and the finding title. */
    public static final class Old {
        public final String method, title;

        public Old(String method, String title) {
            this.method = method;
            this.title = title == null ? "" : title;
        }
    }

    /**
     * 0.66.5: MEASUREMENT ONLY (nothing here changes a result). Where the analysis silently loses taint, which caps were hit, and which
     * methods cost the most. Drops are counted in the last analysis of each method (a re-run replaces the earlier count), as
     * [0] = a real source (Intent / SharedPreferences ...) was in the dropped argument, [1] = only a parameter label was.
     */
    public static final class Stats {
        public static final int TOP = 5;           // methods printed in the status line
        /** 0.103.2: methods kept per group and while merging. With only TOP kept, a method that left the top list and came back lost its earlier run counts (the same app showed 38 runs in one report and 73 in the next). */
        public static final int KEEP = 40;

        /** One expensive method: total time over all its analyses, runs, instructions, most rounds one run needed. */
        public static final class Slow {
            public final String key;
            public final long nanos;
            public final int runs, insns, rounds;

            Slow(String key, long nanos, int runs, int insns, int rounds) {
                this.key = key;
                this.nanos = nanos;
                this.runs = runs;
                this.insns = insns;
                this.rounds = rounds;
            }
        }

        public int analyses;
        public final long[] outOfScope = new long[2];    // call edge to an app method that has no summary (outside the scope / not analysed)
        public final long[] unresolved = new long[2];    // call to a method of an app class the graph has, but no app callee edge (abstract / interface without implementation)
        public final long[] library = new long[2];       // call into a library / framework class the tables do not know, or a class outside this group
        public long capRefs;        // sink references dropped because a slot had MAX_REFS already
        public long capRounds;      // methods whose last analysis still changed after MAX_ROUNDS
        public long capRequeue;     // methods that reached MAX_REQUEUE analyses (later re-runs skipped)
        public long capApprox;      // 0.68.2: call sites linked by the CHA fallback ("virtual~" / "interface~") that had more than MAX_APPROX_TARGETS callees (the rest are skipped)
        public final Map<String, Long> owners = new HashMap<>();
        public final List<Slow> slowest = new ArrayList<>();

        public synchronized void merge(Stats o) {
            if (o == null || o == this) return;
            analyses += o.analyses;
            for (int i = 0; i < 2; i++) {
                outOfScope[i] += o.outOfScope[i];
                unresolved[i] += o.unresolved[i];
                library[i] += o.library[i];
            }
            capRefs += o.capRefs;
            capRounds += o.capRounds;
            capRequeue += o.capRequeue;
            capApprox += o.capApprox;
            for (Map.Entry<String, Long> e : o.owners.entrySet()) owners.merge(e.getKey(), e.getValue(), Long::sum);
            Map<String, Slow> byKey = new LinkedHashMap<>();
            for (Slow x : slowest) byKey.put(x.key, x);
            for (Slow x : o.slowest) {
                Slow y = byKey.get(x.key);
                byKey.put(x.key, y == null ? x : new Slow(x.key, x.nanos + y.nanos, x.runs + y.runs, Math.max(x.insns, y.insns), Math.max(x.rounds, y.rounds)));
            }
            slowest.clear();
            slowest.addAll(byKey.values());
            Collections.sort(slowest, (x, y) -> Long.compare(y.nanos, x.nanos));
            while (slowest.size() > KEEP) slowest.remove(slowest.size() - 1);
        }

        private static String ms(long nanos) {
            long ms = nanos / 1000000L;
            return ms < 1000 ? ms + "ms" : String.format(java.util.Locale.US, "%.1fs", ms / 1000.0);
        }

        /** One line for the scan status: losses (real / parameter only), the top owners behind the library drops, caps hit, slowest methods. */
        public synchronized String line() {
            StringBuilder sb = new StringBuilder("taint losses real/param-only: callee not analysed ")
                    .append(outOfScope[0]).append('/').append(outOfScope[1])
                    .append(", app method unresolved ").append(unresolved[0]).append('/').append(unresolved[1])
                    .append(", library or outside group ").append(library[0]).append('/').append(library[1]);
            if (!owners.isEmpty()) {
                List<Map.Entry<String, Long>> es = new ArrayList<>(owners.entrySet());
                Collections.sort(es, (x, y) -> {
                    int c = Long.compare(y.getValue(), x.getValue());
                    return c != 0 ? c : x.getKey().compareTo(y.getKey());
                });
                sb.append(" (top owners of real drops: ");
                for (int i = 0; i < es.size() && i < TOP; i++) sb.append(i == 0 ? "" : ", ").append(es.get(i).getKey()).append(' ').append(es.get(i).getValue());
                sb.append(')');
            }
            sb.append("; caps hit: sink refs ").append(capRefs).append(", rounds ").append(capRounds).append(" method(s), requeue ").append(capRequeue).append(" method(s), ~ sites ").append(capApprox);
            if (!slowest.isEmpty()) {
                sb.append("; slowest methods: ");
                for (int i = 0; i < slowest.size() && i < TOP; i++) {
                    Slow x = slowest.get(i);
                    sb.append(i == 0 ? "" : ", ").append(shortKey(x.key)).append(' ').append(ms(x.nanos))
                            .append(" [").append(x.insns).append(" insns, ").append(x.rounds).append(" rounds, ").append(x.runs).append(" runs]");
                }
            }
            return sb.toString();
        }
    }

    public static final class Result {
        public final List<Flow> flows = new ArrayList<>();
        public final Stats stats = new Stats();      // 0.66.5
        public int methodsAnalysed, analyses, nonEmptySummaries, failed;
        public boolean reachableOnly;
        public long millis;
        public final List<String> failures = new ArrayList<>();
        public String compareText = "";

        public String format() {
            StringBuilder sb = new StringBuilder();
            sb.append("TAINT ON SSA (P1: flows the in-class engine did not report are added to the scan as taint-flow findings)\n");
            sb.append("scope: ").append(reachableOnly ? "only methods the call graph reaches" : "every app method (each flow below says whether an entry reaches it)").append('\n');
            sb.append("methods analysed: ").append(methodsAnalysed).append(" (").append(analyses).append(" analyses incl. re-runs), non-empty summaries: ")
                    .append(nonEmptySummaries).append(", failed: ").append(failed).append(", time ").append(millis).append(" ms\n");
            int cross = 0, reach = 0;
            for (Flow f : flows) {
                if (f.crossesMethods()) cross++;
                if (f.reachable) reach++;
            }
            sb.append("flows with a real source: ").append(flows.size()).append(" (across methods: ").append(cross)
                    .append(", reachable from an entry: ").append(reach).append(")\n\n");
            if (!compareText.isEmpty()) sb.append(compareText).append('\n');
            int n = 0;
            for (Flow f : flows) {
                sb.append(++n).append(". [").append(f.sink.sev).append("] ").append(f.sink.title).append(" (").append(f.sink.cwe).append(")\n");
                sb.append("   source: ").append(f.source);
                if (f.via != null) sb.append(" via ").append(f.via);
                sb.append('\n');
                sb.append("   sink:   ").append(f.sink.api).append(" in ").append(f.sink.method).append(" @insn ").append(f.sink.insn).append('\n');
                sb.append("   chain:  ").append(join(f.chain, " -> ")).append('\n');
                if (f.reachable) sb.append("   entry:  ").append(join(f.entryPath, " -> ")).append('\n');
                else sb.append("   entry:  not reachable in the call graph\n");
            }
            if (!failures.isEmpty()) {
                sb.append("\nFAILURES (first ").append(failures.size()).append("):\n");
                for (String s : failures) sb.append("  ").append(s).append('\n');
            }
            return sb.toString();
        }

        private static String join(List<String> l, String sep) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < l.size(); i++) sb.append(i == 0 ? "" : sep).append(l.get(i));
            return sb.toString();
        }
    }

    // ======================================================================================== driver

    public static Result analyze(CallGraph g) {
        return analyze(g, true, null);
    }

    /**
     * @param reachableOnly analyse only methods the call graph reaches (default); false analyses every app method with a body
     * @param old           old taint findings to compare with (may be null)
     */
    public static Result analyze(CallGraph g, boolean reachableOnly, Collection<Old> old) {
        long t0 = System.currentTimeMillis();
        Run run = new Run(g);
        Result res = new Result();
        List<String> order = new ArrayList<>();
        for (Map.Entry<String, MethodIr> e : g.methods.entrySet()) {
            MethodIr m = e.getValue();
            if (m.insns.isEmpty() || m.isAbstract() || m.isNative()) continue;
            if (reachableOnly && !g.isReachable(e.getKey())) continue;
            order.add(e.getKey());
        }
        res.methodsAnalysed = order.size();
        res.reachableOnly = reachableOnly;
        Set<String> scope = new HashSet<>(order);
        Deque<String> q = new ArrayDeque<>(order);
        Set<String> queued = new HashSet<>(order);
        Map<String, Integer> runs = new HashMap<>();
        int requeueCapped = 0;
        while (!q.isEmpty()) {
            String key = q.poll();
            queued.remove(key);
            int n = runs.merge(key, 1, Integer::sum);
            if (n > MAX_REQUEUE) {
                if (n == MAX_REQUEUE + 1) requeueCapped++;
                continue;
            }
            res.analyses++;
            MethodIr m = g.methods.get(key);
            String before = run.fingerprintOf(key);
            try {
                run.analyse(m);
            } catch (RuntimeException ex) {
                res.failed++;
                if (res.failures.size() < 10) res.failures.add(key + ": " + ex);
                continue;
            }
            if (!before.equals(run.fingerprintOf(key))) {
                for (String c : g.taintCallersOf(key)) if (scope.contains(c) && queued.add(c)) q.add(c);
            }
            for (String c : run.takeFieldReaders()) if (scope.contains(c) && !c.equals(key) && queued.add(c)) q.add(c);
        }
        for (Summary s : run.summaries.values()) if (!s.isEmpty()) res.nonEmptySummaries++;
        collectStats(run, res, requeueCapped);
        Map<String, Flow> best = new LinkedHashMap<>();
        for (List<Flow> l : run.flowsOf.values()) {
            for (Flow f : l) {
                String k = f.sink.key() + "|" + f.source;
                Flow o = best.get(k);
                if (o == null || (o.weak && !f.weak) || (o.weak == f.weak && o.chain.size() > f.chain.size())) best.put(k, f);
            }
        }
        for (Flow f : best.values()) {
            String origin = f.chain.get(0);
            f.reachable = g.isReachable(origin);
            if (f.reachable) f.entryPath = g.pathTo(origin);
            res.flows.add(f);
        }
        Collections.sort(res.flows, (x, y) -> {
            int c = Integer.compare(rank(x.sink.sev), rank(y.sink.sev));
            if (c != 0) return c;
            c = Boolean.compare(y.reachable, x.reachable);
            return c != 0 ? c : x.key().compareTo(y.key());
        });
        if (old != null) res.compareText = compare(res.flows, old);
        res.millis = System.currentTimeMillis() - t0;
        return res;
    }

    /** 0.66.5: fold the per-method records of one run into {@code res.stats}. Reads only; no result changes. */
    private static void collectStats(Run run, Result res, int requeueCapped) {
        Stats st = res.stats;
        st.analyses = res.analyses;
        st.capRequeue = requeueCapped;
        for (int[] l : run.losses.values()) {
            st.outOfScope[0] += l[0];
            st.outOfScope[1] += l[1];
            st.unresolved[0] += l[2];
            st.unresolved[1] += l[3];
            st.library[0] += l[4];
            st.library[1] += l[5];
            st.capRefs += l[6];
            st.capRounds += l[7];
            st.capApprox += l[8];
        }
        for (Map<String, Integer> mo : run.libOwners.values())
            for (Map.Entry<String, Integer> e : mo.entrySet()) st.owners.merge(e.getKey(), (long) e.getValue(), Long::sum);
        List<Map.Entry<String, long[]>> es = new ArrayList<>(run.timing.entrySet());
        Collections.sort(es, (x, y) -> {
            int c = Long.compare(y.getValue()[0], x.getValue()[0]);
            return c != 0 ? c : x.getKey().compareTo(y.getKey());
        });
        for (int i = 0; i < es.size() && i < Stats.KEEP; i++) {
            long[] t = es.get(i).getValue();
            st.slowest.add(new Stats.Slow(es.get(i).getKey(), t[0], (int) t[1], (int) t[2], (int) t[3]));
        }
    }

    private static int rank(String sev) {
        switch (sev) {
            case "CRITICAL": return 0;
            case "HIGH": return 1;
            case "MEDIUM": return 2;
            default: return 3;
        }
    }

    /** "Lcom/x/Y;" of a method key ("Lcom/x/Y;->name(desc)ret"); the whole string when it has no "->". */
    static String classOf(String methodKey) {
        int i = methodKey.indexOf("->");
        return i < 0 ? methodKey : methodKey.substring(0, i);
    }

    /**
     * The Kotlin scanner merges findings with the same title inside one class into ONE card (SecurityScanner.scanSmali), and that card
     * keeps only the first method. So a flow whose class already has an old finding with the same title is "merged into an old card",
     * not "only new": the old engine did report it (as part of the card's count).
     */
    private static String compare(List<Flow> flows, Collection<Old> old) {
        Set<String> nw = new LinkedHashSet<>();
        for (Flow f : flows) nw.add(f.sink.method + "|" + f.sink.title);
        Set<String> od = new LinkedHashSet<>();
        Set<String> oldClassTitle = new HashSet<>();
        for (Old o : old) {
            od.add(o.method + "|" + o.title);
            oldClassTitle.add(classOf(o.method) + "|" + o.title);
        }
        int both = 0;
        List<String> onlyOld = new ArrayList<>(), onlyNew = new ArrayList<>(), merged = new ArrayList<>();
        for (String k : od) if (nw.contains(k)) both++;
        else onlyOld.add(k);
        for (String k : nw) {
            if (od.contains(k)) continue;
            int bar = k.indexOf('|');
            String ct = classOf(k.substring(0, bar)) + k.substring(bar);
            if (oldClassTitle.contains(ct)) merged.add(k);
            else onlyNew.add(k);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("COMPARE with the Kotlin taint findings (same sink method + title)\n");
        sb.append("  both: ").append(both).append(", only old: ").append(onlyOld.size()).append(", only new: ").append(onlyNew.size());
        if (!merged.isEmpty()) sb.append(", same class and title as an old card (merged by the scanner, not new): ").append(merged.size());
        sb.append('\n');
        for (String k : onlyOld) sb.append("  ONLY OLD  ").append(k).append('\n');
        for (String k : onlyNew) sb.append("  ONLY NEW  ").append(k).append('\n');
        for (String k : merged) sb.append("  MERGED    ").append(k).append('\n');
        return sb.toString();
    }

    // ======================================================================================== solver state

    /**
     * 0.69.0: identity of one heap cell. Today every cell lives in the single GLOBAL object space (obj == "") so behaviour is the
     * same as the old per-field-reference map; 0.70.0 starts putting an allocation site in obj without touching any call site.
     */
    /** 0.70.0: suffix of a source name that was read from the result Intent of onActivityResult (see Intra.invoke). */
    static final String ACTIVITY_RESULT_SUFFIX = " in onActivityResult";

    /** 1.0.0: object space of the writes through R8-merged objects of one class id ("#" + id), see MergeTags. */
    static final String TAG_SPACE = "#";
    /** 1.0.0: switch for the mutation check of MergeTags (false = 0.108 behaviour). */
    static boolean MERGE_TAGS = !Boolean.getBoolean("apkrelab.noMergeTags");

    static final class HeapKey {
        static final String GLOBAL = "";
        final String obj;      // abstract object (allocation site) or GLOBAL
        final String field;    // field reference, or the "prefs:<key>" pseudo-field
        private final int hash;

        HeapKey(String obj, String field) {
            this.obj = obj;
            this.field = field;
            this.hash = 31 * obj.hashCode() + field.hashCode();
        }

        static HeapKey global(String field) {
            return new HeapKey(GLOBAL, field);
        }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof HeapKey)) return false;
            HeapKey k = (HeapKey) o;
            return hash == k.hash && obj.equals(k.obj) && field.equals(k.field);
        }

        @Override public int hashCode() {
            return hash;
        }
    }

    /**
     * 1.0.0: what a call site's reference says (owner, name, descriptor, argument layout, sink candidates). It was re-parsed on every pass of every analysis of a method:
     * about 25% of the bytes a big app's Deep scan allocated (Axis Pay, JFR allocation samples). A pure function of the reference and the invoke kind, so it is kept in a
     * fixed lossy table shared by every thread, like {@link Canon}: a slot holds the last call seen, a race only loses a little reuse, the memory never grows.
     */
    static final class Call {
        private static final int BITS = 14, SLOTS = 1 << BITS;
        private static final Call[] TABLE = new Call[SLOTS];
        final String ref, owner, sig, name, desc, ret;
        final boolean isStatic;
        final int[] phys;
        final List<Sink> cands;

        private Call(Insn in, boolean isStatic) {
            ref = in.ref;
            this.isStatic = isStatic;
            owner = Canon.of(in.targetOwner());
            sig = Canon.of(in.targetSig());
            int paren = sig.indexOf('(');
            name = paren < 0 ? sig : Canon.of(sig.substring(0, paren));
            desc = Canon.of(sig.substring(Math.max(0, paren)));
            ret = Canon.of(sig.substring(sig.lastIndexOf(')') + 1));
            phys = owner.isEmpty() ? new int[0] : physical(allParams(sig), !isStatic);
            cands = owner.isEmpty() ? null : SINKS.get(owner + "->" + name);
        }

        static Call of(Insn in) {
            boolean st = in.op.startsWith("invoke-static");
            int h = in.ref.hashCode() * 31 + (st ? 1 : 0);
            int i = (h ^ (h >>> BITS)) & (SLOTS - 1);
            Call c = TABLE[i];
            if (c != null && c.isStatic == st && (c.ref == in.ref || c.ref.equals(in.ref))) return c;
            c = new Call(in, st);
            TABLE[i] = c;
            return c;
        }
    }

    private static final class Run {
        final CallGraph g;
        final Map<String, Summary> summaries = new HashMap<>();
        final Map<String, List<Flow>> flowsOf = new HashMap<>();
        final Map<HeapKey, Tv> heap = new HashMap<>();                       // 0.69.0: keyed by HeapKey (object space + field); GLOBAL space = old per-field-ref behaviour
        final Map<HeapKey, Set<String>> heapReaders = new HashMap<>();
        final Map<HeapKey, Boolean> heapAllString = new HashMap<>();          // 0.105.0: true while every tainted write to the key stored a value statically known to be a String
        final Map<String, Set<Integer>> tagsWritten = new HashMap<>();        // 1.0.0: field ref -> class ids of R8-merged objects it was written through (MergeTags)
        private MergeTags tags;

        MergeTags tags() {
            if (tags == null) tags = g.mergeFacts != null ? g.mergeFacts.tags : new MergeTags(MergeTags.of(g));
            return tags;
        }

        /** 1.0.0: what a read of [ref] sees when its object can only have one of the class ids [ids]: writes of unknown id, and writes of those ids. */
        Tv readTagged(String ref, Set<Integer> ids, String reader) {
            Tv t = readHeap(HeapKey.global(ref), reader);
            for (int id : ids) {
                Tv x = heap.get(new HeapKey(TAG_SPACE + id, ref));
                if (x != null) t = t == null ? x : t.join(x);
            }
            return t;
        }

        /** 1.0.0: allStrings over the keys a tagged read sees ([ids] null = the plain key). */
        boolean allStrings(String ref, Set<Integer> ids) {
            if (ids == null) return allStrings(ref);
            boolean any = false;
            Boolean b = heapAllString.get(HeapKey.global(ref));
            if (b != null) { if (!b) return false; any = true; }
            for (int id : ids) {
                b = heapAllString.get(new HeapKey(TAG_SPACE + id, ref));
                if (b != null) { if (!b) return false; any = true; }
            }
            return any;
        }
        final Set<String> dirtyReaders = new LinkedHashSet<>();
        // 0.66.5 (measurement only): per method, replaced by every analysis of that method except the time, which adds up
        final Map<String, long[]> timing = new HashMap<>();                  // key -> {nanos, runs, insns, most rounds}
        final Map<String, int[]> losses = new HashMap<>();                   // key -> {outReal, outParam, unresReal, unresParam, libReal, libParam, refsDropped, roundCap, approxCapped}
        final Map<String, Map<String, Integer>> libOwners = new HashMap<>();
        private Set<String> appOwners;

        boolean isAppOwner(String owner) {
            if (appOwners == null) {
                Set<String> x = new HashSet<>();
                for (String k : g.methods.keySet()) x.add(classOf(k));
                appOwners = x;
            }
            return appOwners.contains(owner);
        }

        Run(CallGraph g) {
            this.g = g;
        }

        final Map<String, String> fingerprints = new HashMap<>();   // 0.60.0: a summary's fingerprint is computed once per change, not twice per analysis

        String fingerprintOf(String key) {
            String f = fingerprints.get(key);
            if (f == null) {
                Summary s = summaries.get(key);
                f = s == null ? "" : s.fingerprint();
                fingerprints.put(key, f);
            }
            return f;
        }

        Set<String> takeFieldReaders() {
            Set<String> r = new LinkedHashSet<>(dirtyReaders);
            dirtyReaders.clear();
            return r;
        }

        void raiseField(String ref, Tv t, String writer) {
            raiseHeap(HeapKey.global(ref), t, writer, false);
        }

        void raiseField(String ref, Tv t, String writer, boolean isString) {
            raiseHeap(HeapKey.global(ref), t, writer, isString);
        }

        /** 0.105.0: true when every tainted value written to field [ref] so far was a String (see Intra.castsAwayFromString). */
        boolean allStrings(String ref) {
            return Boolean.TRUE.equals(heapAllString.get(HeapKey.global(ref)));
        }

        /** 0.69.0: every heap write goes through here, so a later object-sensitive HeapKey needs no call-site change. */
        void raiseHeap(HeapKey k, Tv t, String writer, boolean isString) {
            Tv r = t.realOnly();
            if (r.isNone()) return;
            // 1.0.0: a write through an object of known class id: its readers register on the plain key (see readTagged)
            HeapKey rk = k.obj.startsWith(TAG_SPACE) ? HeapKey.global(k.field) : k;
            if (rk != k) tagsWritten.computeIfAbsent(k.field, x -> new HashSet<>()).add(Integer.parseInt(k.obj.substring(TAG_SPACE.length())));
            Boolean was = heapAllString.get(k);
            boolean now = was == null ? isString : was && isString;
            if (was == null || was != now) {
                heapAllString.put(k, now);
                // a reader that dropped the value because every write was a String must look again
                if (was != null) {
                    Set<String> rd = heapReaders.get(rk);
                    if (rd != null) dirtyReaders.addAll(rd);
                }
            }
            Tv old = heap.get(k);
            if (old != null && old.covers(r)) return;
            Tv withVia = Tv.real(r.level, r.src, "field " + shortRef(k.field) + " (written in " + shortKey(writer) + ")", r.weak, r.internal);
            heap.put(k, old == null ? withVia : old.join(withVia));
            Set<String> rd = heapReaders.get(rk);
            if (rd != null) dirtyReaders.addAll(rd);
        }

        /** 0.69.0: registers the reader for re-queueing and returns the stored value (null when nothing was written). */
        Tv readHeap(HeapKey k, String reader) {
            heapReaders.computeIfAbsent(k, x -> new HashSet<>()).add(reader);
            return heap.get(k);
        }

        void analyse(MethodIr m) {
            long t0 = System.nanoTime();
            Intra in = new Intra(this, m);
            in.solve();
            Summary s = in.finish();
            summaries.put(m.key(), s);
            fingerprints.remove(m.key());
            flowsOf.put(m.key(), in.flows);
            noteCost(m, in, s, System.nanoTime() - t0);
        }

        private void noteCost(MethodIr m, Intra in, Summary s, long nanos) {
            String k = m.key();
            long[] t = timing.get(k);
            if (t == null) {
                t = new long[4];
                timing.put(k, t);
            }
            t[0] += nanos;
            t[1]++;
            t[2] = m.insns.size();
            t[3] = Math.max(t[3], in.rounds);
            int[] l = {in.dOut[0], in.dOut[1], in.dUnres[0], in.dUnres[1], in.dLib[0], in.dLib[1], s.refsDropped, in.roundCap ? 1 : 0, in.approxCapped.size()};
            boolean any = false;
            for (int x : l) any |= x != 0;
            if (any) losses.put(k, l);
            else losses.remove(k);
            if (in.libOwners != null) libOwners.put(k, in.libOwners);
            else libOwners.remove(k);
        }
    }

    /** The superclass chain of the class ends in a framework class named ...Provider (ContentProvider, FileProvider ...). */
    static boolean isProvider(CallGraph g, String type) {
        String ch = g.superChain(type);
        int i = ch.lastIndexOf(" -> ");
        String last = i < 0 ? ch : ch.substring(i + 4);
        return last.endsWith("Provider;");
    }

    static String shortKey(String key) {
        int i = key.indexOf("->");
        if (i < 0) return key;
        String c = key.substring(0, i);
        if (c.startsWith("L")) c = c.substring(1);
        if (c.endsWith(";")) c = c.substring(0, c.length() - 1);
        int sl = c.lastIndexOf('/');
        return (sl >= 0 ? c.substring(sl + 1) : c) + "." + key.substring(i + 2);
    }

    static String shortRef(String ref) {
        if (ref != null && ref.startsWith(FANOUT_MARK)) ref = ref.substring(FANOUT_MARK.length());
        if (ref != null && ref.startsWith(ERASED_MARK)) ref = ref.substring(ERASED_MARK.length());
        if (ref != null && ref.startsWith(PARCEL_HELD_MARK)) ref = ref.substring(PARCEL_HELD_MARK.length());
        return ref == null || ref.isEmpty() ? "" : shortKey(ref);
    }

    // ======================================================================================== one method

    /** 0.83.0: a call site that resolves to at least this many targets returns a weak taint (polymorphic fan-out). */
    static final int FANOUT_WEAK = 8;
    /** Prefix of {@code Tv.via} marking a weak taint that came out of a high fan-out call (SsaBridge words it; {@link #shortRef} strips it). */
    static final String FANOUT_MARK = "fanout:";
    /** 0.83.0: chains with this many type-erased methods are weak (see Intra.addFlow). */
    static final int ERASED_WEAK = 3;
    static final String ERASED_MARK = "erased:";
    /** 0.83.0: a Parcel value that is stored and used in another method (see Intra.addFlow). */
    static final String PARCEL_HELD_MARK = "parcelheld:";

    /** 0.83.0: number of methods of [chain] (keys `Lc;->name(params)ret`) whose reference parameters and return are all java.lang.Object. */
    static int erasedHops(List<String> chain) {
        int n = 0;
        for (String key : chain) {
            int a = key.indexOf('('), b = key.indexOf(')');
            if (a < 0 || b < a) continue;
            String ps = key.substring(a + 1, b), ret = key.substring(b + 1);
            if (ps.isEmpty()) continue;
            boolean anyObj = false, ok = true;
            for (int i = 0; i < ps.length() && ok; ) {
                char c = ps.charAt(i);
                if (c == '[') { ok = false; break; }
                if (c == 'L') {
                    int e = ps.indexOf(';', i);
                    if (e < 0) { ok = false; break; }
                    if (ps.substring(i, e + 1).equals("Ljava/lang/Object;")) anyObj = true; else ok = false;
                    i = e + 1;
                } else i++;                                   // primitive
            }
            if (ok && anyObj && (ret.equals("V") || ret.equals("Ljava/lang/Object;") || ret.length() == 1)) n++;
        }
        return n;
    }

    /** 0.80.0: test hook for {@link Intra#isMergedObjectField}. */
    static boolean mergedObjectField(String ref) {
        return Intra.isMergedObjectField(ref);
    }

    private static final class Intra {
        final Run run;
        final MethodIr m;
        final SsaForm ssa;
        final int[] regToSlot;
        final Map<SsaForm.Value, Tv> tv = new IdentityHashMap<>();
        final Map<Integer, List<String>> calleesAt = new HashMap<>();
        final Summary sum = new Summary();
        final List<Flow> flows = new ArrayList<>();
        final Map<String, Flow> flowByKey = new HashMap<>();
        final boolean[] seedSlot;     // logical argument slots that are real sources by themselves (provider parameters), or null
        final boolean seedInternal;   // 0.84.0: the provider is not an exported entry of the graph
        boolean changed, collect;
        // 0.66.5 (measurement only)
        int rounds;
        boolean roundCap;
        final Set<Integer> approxCapped = new HashSet<>();   // 0.68.2: insn indexes of CHA-fallback sites that hit MAX_APPROX_TARGETS (counter only)
        final int[] dOut = new int[2], dUnres = new int[2], dLib = new int[2];
        Map<String, Integer> libOwners;

        Intra(Run run, MethodIr m) {
            this.run = run;
            this.m = m;
            this.ssa = SsaForm.buildCached(m);
            int regs = m.registerCount() + 2;
            regToSlot = new int[regs];
            Arrays.fill(regToSlot, -1);
            List<String> pt = allParams(m.sig());
            int[] pos = physical(pt, !m.isStatic);
            for (int k = 0; k < pos.length; k++) {
                int r = m.firstParam() + pos[k];
                if (r >= 0 && r < regs) regToSlot[r] = k;
            }
            boolean[] seed = null;
            if (!m.isStatic && PROVIDER_METHODS.contains(m.name) && isProvider(run.g, m.owner)) {
                seed = new boolean[pt.size() + 1];
                for (int k = 0; k < pt.size(); k++) seed[k + 1] = pt.get(k).startsWith("L") || pt.get(k).startsWith("[");
            }
            seedSlot = seed;
            seedInternal = seed != null && run.g.hasComponentList() && !run.g.isExportedEntry(m.owner);
            for (CallGraph.Edge e : run.g.taintEdgesFrom(m.key())) {
                // 0.68.0: the "~" kinds (CHA fallback for a call site RTA left without a target) carry arguments too, at most MAX_APPROX_TARGETS per site
                boolean approx = e.kind.endsWith("~");
                if (e.external || !INVOKE_KINDS.contains(approx ? e.kind.substring(0, e.kind.length() - 1) : e.kind)) continue;
                List<String> at = calleesAt.computeIfAbsent(e.insn, k -> new ArrayList<>());
                if (approx && at.size() >= MAX_APPROX_TARGETS) {
                    approxCapped.add(e.insn);
                    continue;
                }
                at.add(e.callee);
            }
        }

        void solve() {
            for (int round = 0; round < MAX_ROUNDS; round++) {
                changed = false;
                pass();
                rounds = round + 1;
                if (!changed) break;
                if (round == MAX_ROUNDS - 1) roundCap = true;
            }
            collect = true;
            pass();
        }

        Summary finish() {
            return sum;
        }

        // ---------- value taint ----------

        Tv get(SsaForm.Value v) {
            if (v == null) return Tv.NONE;
            if (v.entry) {
                if (!v.param || v.reg >= regToSlot.length) return Tv.NONE;
                int s = regToSlot[v.reg];
                if (s < 0) return Tv.NONE;
                Tv p = Tv.param(s);
                return seedSlot != null && s < seedSlot.length && seedSlot[s] ? p.join(seedInternal ? PROVIDER_SRC_INTERNAL : PROVIDER_SRC) : p;
            }
            Tv t = tv.get(v);
            return t == null ? Tv.NONE : t;
        }

        void raise(SsaForm.Value v, Tv t) {
            if (v == null || v.entry || t == null || t.isNone()) return;
            Tv old = tv.get(v);
            if (old != null && old.covers(t)) return;
            tv.put(v, old == null ? t : old.join(t));
            changed = true;
        }

        /** Add taint to an object value and to everything it aliases (move / check-cast / phi). */
        void raiseObj(SsaForm.Value v, Tv t) {
            if (v == null || t.isNone()) return;
            Deque<SsaForm.Value> st = new ArrayDeque<>();
            Set<SsaForm.Value> seen = Collections.newSetFromMap(new IdentityHashMap<>());
            st.push(v);
            while (!st.isEmpty()) {
                SsaForm.Value x = st.pop();
                if (!seen.add(x)) continue;
                raise(x, t);
                if (x.phi != null) {
                    for (SsaForm.Value o : x.phi.operands) if (o != null) st.push(o);
                } else if (x.def != null && (x.def.kind == Insn.Kind.MOVE || x.def.kind == Insn.Kind.CHECK_CAST)) {
                    SsaForm.Value[] us = ssa.usesOf(x.def);
                    if (us.length > 0) st.push(us[0]);
                }
            }
        }

        // ---------- one sweep over the method ----------

        void pass() {
            for (int bi : ssa.cfg.rpo) {
                Cfg.BasicBlock b = ssa.cfg.blocks.get(bi);
                if (!b.reachable) continue;
                for (SsaForm.Phi p : ssa.phis[bi]) {
                    Tv j = Tv.NONE;
                    for (SsaForm.Value o : p.operands) j = j.join(get(o));
                    raise(p.result, j);
                }
                if (b.pseudo) continue;
                for (int i = b.first; i <= b.last; i++) transfer(m.insns.get(i));
            }
        }

        Tv joinAll(SsaForm.Value[] vs, int from, int to) {
            Tv t = Tv.NONE;
            for (int i = from; i < to && i < vs.length; i++) t = t.join(get(vs[i]));
            return t;
        }

        void transfer(Insn in) {
            SsaForm.Value[] u = ssa.usesOf(in), d = ssa.defsOf(in);
            switch (in.kind) {
                case MOVE:
                case CHECK_CAST: {
                    Tv t = joinAll(u, 0, u.length);
                    for (SsaForm.Value y : d) raise(y, t);
                    break;
                }
                case FIELD_GET: {
                    Set<Integer> tags = u.length > 0 && in.op.startsWith("iget") ? readTags(in, u[0]) : null;
                    Tv t = tags == null ? run.readHeap(HeapKey.global(in.ref), m.key()) : run.readTagged(in.ref, tags, m.key());
                    // 0.105.0: every tainted write stored a String, and every use of this read casts it to a type no String has: the cast would throw for the tainted
                    // value, so what gets through is something else the field held (R8 merges unrelated classes into one Object field: Axis Pay m42.c)
                    if (t != null && t.level > 0 && d.length == 1 && run.allStrings(in.ref, tags) && castsAwayFromString(d[0])) t = null;
                    if (t != null && t.level > 0 && !t.weak && isMergedObjectField(in.ref)) t = t.asWeak();   // 0.68.5
                    if (t != null) for (SsaForm.Value y : d) raise(y, t);
                    break;
                }
                case FIELD_PUT: {
                    int vc = in.op.contains("-wide") ? 2 : 1;
                    Tv t = joinAll(u, 0, vc);
                    if (t.level > 0) {
                        boolean str = vc == 1 && u.length > 0 && isString(u[0], 0);
                        int tag = u.length > vc && in.op.startsWith("iput") ? putTag(in, u[vc]) : MergeTags.UNKNOWN;
                        if (tag == MergeTags.UNKNOWN) run.raiseField(in.ref, t, m.key(), str);
                        else run.raiseHeap(new HeapKey(TAG_SPACE + tag, in.ref), t, m.key(), str);
                    }
                    break;
                }
                case ARRAY_GET:
                    if (u.length > 0) {
                        Tv t = get(u[0]);
                        for (SsaForm.Value y : d) raise(y, t);
                    }
                    break;
                case ARRAY_PUT: {
                    int vc = in.op.contains("-wide") ? 2 : 1;
                    Tv t = joinAll(u, 0, vc);
                    if (u.length > vc) raiseObj(u[vc], t);
                    break;
                }
                case FILLED_ARRAY: {
                    Tv t = joinAll(u, 0, u.length);
                    for (SsaForm.Value y : d) raise(y, t);
                    break;
                }
                case RETURN:
                    if (collect && u.length > 0) {
                        Tv t = joinAll(u, 0, u.length);
                        sum.retParams |= t.params;
                        if (t.rank() > Tv.rankOf(sum.retLevel, sum.retWeak)) {
                            sum.retLevel = t.level;
                            sum.retSrc = t.src;
                            sum.retWeak = t.weak;
                            sum.retInternal = t.internal;
                        }
                    }
                    break;
                case INVOKE:
                    invoke(in, u, d);
                    break;
                default:
                    break;
            }
        }

        /** 0.70.0: v is (a move / cast / phi of) the Intent-typed parameter of the method being analysed, and the method is onActivityResult. */
        boolean isActivityResultIntent(SsaForm.Value v) {
            // 0.79.0 (Markor GsContextUtils.extractResultFromActivityResult(Activity, int, int, Intent)): a helper that onActivityResult hands
            // its (requestCode, resultCode, data) to, recognised by name + the (II Intent) parameter run, is the same answer
            // 0.83.0 (AnkiDroid `b8.a(IILandroid/content/Intent;)Z` = androidx ActivityResultRegistry.dispatchResult, renamed by R8): by SHAPE.
            // (int requestCode, int resultCode, Intent data) is the shape of an activity answer whatever the method is called
            boolean helper = m.desc.contains("IILandroid/content/Intent;)");
            return (m.name.equals("onActivityResult") || helper) && viaIntentParam(v, 0);
        }

        private boolean viaIntentParam(SsaForm.Value v, int depth) { return viaParamOfType(v, depth, "Landroid/content/Intent;"); }

        /** 0.74.0: v is (a move / cast / phi of) a parameter of the method being analysed whose declared type is [type]. */
        private boolean viaParamOfType(SsaForm.Value v, int depth, String type) {
            if (v == null || depth > 8) return false;
            if (v.entry) {
                if (!v.param || v.reg >= regToSlot.length) return false;
                int slot = regToSlot[v.reg];
                if (slot < 0) return false;
                List<String> pt = allParams(m.sig());
                int idx = m.isStatic ? slot : slot - 1;      // slot 0 of an instance method is "this"
                return idx >= 0 && idx < pt.size() && pt.get(idx).equals(type);
            }
            if (v.phi != null) {
                if (v.phi.operands.length == 0) return false;
                for (SsaForm.Value o : v.phi.operands) if (!viaParamOfType(o, depth + 1, type)) return false;
                return true;
            }
            if (v.def != null && (v.def.kind == Insn.Kind.MOVE || v.def.kind == Insn.Kind.CHECK_CAST)) {
                SsaForm.Value[] us = ssa.usesOf(v.def);
                return us.length > 0 && viaParamOfType(us[0], depth + 1, type);
            }
            return false;
        }

        // ---------- calls ----------

        void invoke(Insn in, SsaForm.Value[] u, SsaForm.Value[] d) {
            Call call = Call.of(in);
            String owner = call.owner, sig = call.sig, name = call.name;
            if (owner.isEmpty()) return;
            boolean isStatic = call.isStatic;
            int[] phys = call.phys;
            Tv[] t = new Tv[phys.length];
            SsaForm.Value[] av = new SsaForm.Value[phys.length];
            for (int k = 0; k < phys.length; k++) {
                av[k] = phys[k] < u.length ? u[phys[k]] : null;
                t[k] = get(av[k]);
            }
            // sink
            List<Sink> cands = call.cands;
            if (collect && cands != null) {
                String desc = call.desc;
                for (Sink s : cands) {
                    if (!s.descPrefix.isEmpty() && !desc.startsWith(s.descPrefix)) continue;
                    Tv tt = Tv.NONE;
                    for (int a : s.args) {
                        int k = a == -1 ? (isStatic ? -1 : 0) : (isStatic ? a : a + 1);
                        if (k >= 0 && k < t.length) tt = tt.join(t[k]);
                    }
                    if (!tt.isNone()) hit(s, in, tt);
                }
            }
            // 0.74.0: intent redirection (see REDIRECT_NAMES): the Intent object itself came from the caller
            if (collect && !isStatic && REDIRECT_NAMES.contains(name) && call.desc.startsWith("(Landroid/content/Intent;") && t.length > 1 && !t[1].isNone()
                    && !owner.startsWith("Landroid/content/Intent;")) hit(REDIRECT_SINKS.get(name), in, t[1]);
            // 0.67.0: SharedPreferences.Editor.putString(key, value): a REAL source in the value is remembered for that key
            if (!isStatic && owner.equals(EDITOR_OWNER) && PREFS_PUTS.contains(name) && t.length >= 3) {
                Tv val = t[2].realOnly();
                if (!val.isNone()) {
                    String key = constString(av[1]);
                    run.raiseField(key == null ? PREFS_UNKNOWN : PREFS_PREFIX + key, val, m.key());
                    run.raiseField(PREFS_ANY, val, m.key());
                    return;      // consumed by the heap, not a lost taint (a parameter-only value still falls through and is counted)
                }
            }
            // real source
            Tv src = sourceOf(owner, name);
            if (src != null && owner.equals("Landroid/content/Intent;") && run.g.isInternalComponent(classOf(m.key())))
                src = Tv.internalSource(src.level, src.src, src.via);                 // 0.68.6: read in a component that is not exported
            // 0.70.0: the Intent handed to onActivityResult is the ANSWER of an activity this app started (file picker, camera, its own
            // screens), not an input another app sends to one of our components. It is attacker data only when that activity can be
            // hijacked (implicit Intent) or is untrusted, so it is a weak lead, never a strong source. Only the method's own Intent
            // parameter counts: getIntent() or a locally built Intent inside onActivityResult keeps its normal strength.
            if (src != null && !isStatic && owner.equals("Landroid/content/Intent;") && av.length > 0 && isActivityResultIntent(av[0]))
                src = Tv.internalSource(src.level, src.src + ACTIVITY_RESULT_SUFFIX, src.via);
            // 0.74.0: Parcel.readString() & co inside an unmarshalling method, on the method's own Parcel parameter
            if (src == null && !isStatic && owner.equals(PARCEL_OWNER) && PARCEL_SOURCES.contains(name) && PARCEL_ENTRY_METHODS.contains(m.name)
                    && av.length > 0 && viaParamOfType(av[0], 0, PARCEL_OWNER))
                src = Tv.real(1, "Parcel." + name + "()", null);
            if (src != null) {
                if (!isStatic && owner.equals(PREFS_OWNER)) src = src.join(prefsHeap(name, av));
                for (SsaForm.Value y : d) raise(y, src);
                return;
            }
            // app callees (RTA edges of this call site)
            List<String> callees = calleesAt.get(in.index);
            Tv res = Tv.NONE;
            boolean app = false;
            if (callees != null) {
                for (String c : callees) {
                    Summary sc = run.summaries.get(c);
                    app = true;
                    if (sc == null) {
                        if (collect) {
                            int tk = taintKind(t);
                            if (tk >= 0) dOut[tk]++;
                        }
                        continue;
                    }
                    for (int k = 0; k < t.length; k++) {
                        if (t[k].isNone()) continue;
                        if (collect) {
                            Map<String, SinkRef> refs = sc.sinkParams.get(k);
                            if (refs != null) for (SinkRef r : refs.values()) hitVia(r, t[k]);
                        }
                        if (k < 64 && (sc.retParams & (1L << k)) != 0) res = res.join(t[k]);
                    }
                    if (sc.retLevel > 0) res = res.join(Tv.real(sc.retLevel, sc.retSrc, shortKey(c), sc.retWeak, sc.retInternal));
                }
            }
            // 0.83.0 (FairEmail SimpleTask: `data = onExecute(...)` resolves to every task subclass, so ONE shared result field carried the
            // taint of all of them and 12 of 19 HIGH cards were unrelated sinks): the RESULT of a call that resolves to FANOUT_WEAK or more
            // targets is the union of that many bodies, so a link through it is a weak lead (LOW confidence, one level lower). Arguments still
            // reach the sinks of EVERY target: only the returned taint is weakened.
            if (callees != null && callees.size() >= FANOUT_WEAK && !res.isNone() && !res.weak)
                res = new Tv(res.params, res.level, res.src, FANOUT_MARK + (res.via == null ? "" : res.via), true, res.internal);
            if (app) {
                for (SsaForm.Value y : d) raise(y, res);
                return;
            }
            // framework / unresolved callee
            if (isSanitizer(owner, name)) return;
            // 0.68.1: Kotlin Intrinsics that return a reference (stringPlus = string concatenation) hand their arguments to the result
            if (owner.equals("Lkotlin/jvm/internal/Intrinsics;") && call.ret.startsWith("L")) {
                Tv all = Tv.NONE;
                for (Tv x : t) all = all.join(x);
                for (SsaForm.Value y : d) raise(y, all);
                return;
            }
            // 0.68.3: D8 / R8 desugaring companions ("...$-CC") hold synthetic static helpers; the NewPipe measurement showed the string-concatenation
            // ones (m / mm: String ... -> String, a StringBuilder inside) as the biggest real loss. They are never framework APIs, so the
            // result carries the taint of every String / char / int argument.
            if (isStatic && owner.endsWith("$-CC;") && sig.endsWith(")Ljava/lang/String;") && onlyTextParams(sig)) {
                Tv all = Tv.NONE;
                for (Tv x : t) all = all.join(x);
                for (SsaForm.Value y : d) raise(y, all);
                return;
            }
            // 0.68.3: System.arraycopy(src, srcPos, dest, destPos, len) copies the elements, so the taint of src is also in dest
            if (owner.equals("Ljava/lang/System;") && name.equals("arraycopy") && isStatic && t.length == 5 && av.length == 5) {
                raiseObj(av[2], t[0]);
                return;
            }
            int kind = kindOf(owner);
            if (kind == 0) {
                // 0.66.7: a call that IS a sink was already reported above; its taint is consumed there, not lost
                if (collect && cands == null && !noLossDrop(owner, name, sig)) noteLibDrop(owner, t);
                return;
            }
            Tv args = Tv.NONE;
            for (int k = isStatic ? 0 : 1; k < t.length; k++) args = args.join(t[k]);
            if (!isStatic && (name.equals("<init>") || kind == 2) && !args.isNone()) raiseObj(av[0], args);
            if (name.equals("<init>")) return;
            res = args;
            if (!isStatic) res = res.join(t[0]);
            for (SsaForm.Value y : d) raise(y, res);
        }

        /** 0.67.0: the string literal an SSA value holds (const-string, followed through moves), with its quotes, or null. */
        String constString(SsaForm.Value v) {
            for (int i = 0; i < 8; i++) {
                if (v == null || v.entry || v.phi != null || v.def == null) return null;
                Insn d = v.def;
                if (d.kind == Insn.Kind.CONST) return d.op.startsWith("const-string") ? d.ref : null;
                if (d.kind != Insn.Kind.MOVE) return null;
                SsaForm.Value[] us = ssa.usesOf(d);
                if (us.length == 0) return null;
                v = us[0];
            }
            return null;
        }

        /**
         * 0.68.5: an {@code Object}-typed field of a class in the default package (an R8 / ProGuard name such as {@code aq3}). R8 merges several
         * unrelated classes (Kotlin sequence iterators, Compose state holders) into one class with ONE shared {@code Object} field, and taint is
         * kept per field, so one tainted write taints every read. A taint read from such a field is marked weak (shown as LOW confidence).
         */
        static boolean isMergedObjectField(String ref) {
            if (ref == null || !ref.endsWith(":Ljava/lang/Object;")) return false;
            int a = ref.indexOf("->");
            if (a < 2 || ref.charAt(0) != 'L') return false;
            if (ref.indexOf('/') < 0 || ref.indexOf('/') > a) return true;
            // 0.80.0 (Ivy Wallet `LG2/m;->r:Ljava/lang/Object;`): R8 also moves merged classes into short renamed packages; every
            // segment of the type (package and class) is 1-3 characters, so this is an obfuscated name, not a readable app package
            String type = ref.substring(1, a - 1);
            for (String seg : type.split("/")) if (seg.isEmpty() || seg.length() > 3) return false;
            return true;
        }

        private static final Set<String> STRING_SUPERS = new HashSet<>(Arrays.asList("Ljava/lang/String;", "Ljava/lang/Object;", "Ljava/lang/CharSequence;",
                "Ljava/lang/Comparable;", "Ljava/io/Serializable;", "Ljava/lang/constant/Constable;", "Ljava/lang/constant/ConstantDesc;"));

        /** 0.105.0: the value is statically a String (String is final: the object IS a String): a string constant, a cast to String, a String-returning call or field, a move of one. */
        static boolean isString(SsaForm.Value v, int depth) {
            if (v == null || v.def == null || depth > 8) return false;
            Insn d = v.def;
            switch (d.kind) {
                case CONST: return d.op.startsWith("const-string");
                case CHECK_CAST: return d.ref.equals("Ljava/lang/String;");
                case INVOKE: return d.hasResult && d.targetSig().endsWith(")Ljava/lang/String;");
                case FIELD_GET: return d.ref.endsWith(":Ljava/lang/String;");
                default: return false;
            }
        }

        private Map<SsaForm.Value, List<Insn>> users;
        private Map<Insn, Integer> putTags;
        private Map<Insn, Object[]> readTagCache;

        /** 1.0.0: class id of the object an iput on a field of an R8-merged class writes to (MergeTags), or UNKNOWN. */
        int putTag(Insn in, SsaForm.Value obj) {
            if (!MERGE_TAGS) return MergeTags.UNKNOWN;
            if (putTags == null) putTags = new IdentityHashMap<>();
            Integer c = putTags.get(in);
            if (c != null) return c;
            String owner = in.ref.substring(0, Math.max(0, in.ref.indexOf("->")));
            String disc = run.tags().discriminatorOf(owner);
            int t = disc == null || disc.equals(in.ref) ? MergeTags.UNKNOWN : run.tags().tagOf(m, ssa, obj, owner, in);
            putTags.put(in, t);
            return t;
        }

        /** 1.0.0: the class ids whose writes this iget can see (null = no tagged write, the plain field key). */
        Set<Integer> readTags(Insn in, SsaForm.Value obj) {
            Set<Integer> written = run.tagsWritten.get(in.ref);
            if (written == null) return null;
            if (readTagCache == null) readTagCache = new IdentityHashMap<>();
            Object[] c = readTagCache.get(in);
            if (c != null && (Integer) c[0] == written.size()) return (Set<Integer>) c[1];
            String owner = in.ref.substring(0, in.ref.indexOf("->"));
            Set<Integer> ok = run.tags().compatible(m, ssa, obj, owner, written, users(), in);
            Set<Integer> r = ok == null ? new HashSet<>(written) : ok;
            readTagCache.put(in, new Object[]{written.size(), r});
            return r;
        }


        /** 0.105.0: every use of [v] (through plain moves) is a check-cast to a type that no String can have; false when [v] meets a phi, any other use, or no use. */
        /** value -> the instructions that use it (null = a phi). */
        Map<SsaForm.Value, List<Insn>> users() {
            if (users == null) {
                users = new IdentityHashMap<>();
                for (Insn in : m.insns) for (SsaForm.Value u : ssa.usesOf(in)) if (u != null) users.computeIfAbsent(u, x -> new ArrayList<>()).add(in);
                for (List<SsaForm.Phi> ps : ssa.phis) for (SsaForm.Phi p : ps) for (SsaForm.Value o : p.operands) if (o != null) users.computeIfAbsent(o, x -> new ArrayList<>()).add(null);
            }
            return users;
        }

        boolean castsAwayFromString(SsaForm.Value v) {
            users();
            ArrayDeque<SsaForm.Value> q = new ArrayDeque<>();
            Set<SsaForm.Value> seen = Collections.newSetFromMap(new IdentityHashMap<>());
            q.add(v);
            seen.add(v);
            boolean cast = false;
            while (!q.isEmpty()) {
                List<Insn> us = users.get(q.poll());
                if (us == null) continue;
                for (Insn in : us) {
                    if (in == null) return false;                                    // a phi: followed nowhere, keep the taint
                    if (in.kind == Insn.Kind.MOVE) {
                        for (SsaForm.Value y : ssa.defsOf(in)) if (y != null && seen.add(y)) q.add(y);
                    } else if (in.kind == Insn.Kind.CHECK_CAST) {
                        if (STRING_SUPERS.contains(in.ref)) return false;
                        cast = true;
                    } else {
                        return false;
                    }
                }
            }
            return cast;
        }

        /** 0.67.0: what Editor.put* stored for the key a SharedPreferences read asks for (av[0] = the preferences object, av[1] = the key). */
        Tv prefsHeap(String name, SsaForm.Value[] av) {
            String key = name.equals("getAll") || av.length < 2 ? null : constString(av[1]);
            // 0.78.0 (Markor: every key comes from a resource id inside a preferences wrapper, so no key is a literal and EVERY read saw
            // EVERY write, e.g. a caller's file path came back from getSnippetsDirectory()): a link that rests on a non-literal key on either
            // side is a weak lead (low confidence, one level lower); same literal key on both sides stays strong
            if (name.equals("getAll")) return readHeap(PREFS_ANY);          // getAll really returns every value: a sound link
            if (key == null) return readHeap(PREFS_ANY).asWeak();
            return readHeap(PREFS_PREFIX + key).join(readHeap(PREFS_UNKNOWN).asWeak());
        }

        private Tv readHeap(String ref) {
            Tv t = run.readHeap(HeapKey.global(ref), m.key());
            return t == null ? Tv.NONE : t;
        }

        /**
         * 0.66.9 (counter only, no result changes): calls that drop a tainted argument but lose nothing worth reporting. Kotlin
         * {@code Intrinsics} null checks / comparisons (they return void or boolean) and constructors of {@code java/lang} exceptions.
         * Other {@code Intrinsics} methods (for example one that returns a String) and every other library call stay counted.
         */
        static boolean noLossDrop(String owner, String name, String sig) {
            int r = sig.lastIndexOf(')');
            String ret = r >= 0 ? sig.substring(r + 1) : "";
            if (owner.equals("Lkotlin/jvm/internal/Intrinsics;")) return ret.equals("V") || ret.equals("Z");
            // 0.68.3: a primitive result (size, isEmpty, ordinal, getColor ...) cannot carry an injection, and a void call on a UI toolkit
            // class (TextView.setText, View / RecyclerView / Toolbar setters) only ends the taint on the screen. Counter only, results unchanged.
            if (ret.length() == 1 && "ZIJFDSBC".indexOf(ret.charAt(0)) >= 0) return true;
            if (ret.equals("V") && isUiToolkit(owner)) return true;
            if (owner.equals("Landroid/util/Log;")) return true;      // 0.67.1: logging ends the taint here, it returns only an int
            // 0.68.1: a number cannot carry an injection (Integer / Long ... are sanitizers already), and the taint handed to an Activity launch
            // is not lost: every Intent.getStringExtra on the other side is a level-2 source by itself
            if (owner.equals("Ljava/lang/Number;")) return name.endsWith("Value");
            if (owner.equals("Landroid/app/Activity;"))
                return name.equals("startActivity") || name.equals("startActivityForResult") || name.equals("setResult") || name.equals("setIntent");
            return name.equals("<init>") && owner.startsWith("Ljava/lang/") && (owner.endsWith("Exception;") || owner.endsWith("Error;"));
        }

        /** Every parameter is a String, CharSequence or a primitive (the shape of a string-concatenation helper). */
        private static boolean onlyTextParams(String sig) {
            List<String> ps = allParams(sig);
            if (ps.isEmpty()) return false;
            for (String p : ps) {
                if (p.equals("Ljava/lang/String;") || p.equals("Ljava/lang/CharSequence;")) continue;
                if (p.length() == 1 && "ZIJFDSBC".indexOf(p.charAt(0)) >= 0) continue;
                return false;
            }
            return true;
        }

        private static boolean isUiToolkit(String owner) {
            return owner.startsWith("Landroid/widget/") || owner.startsWith("Landroid/view/") || owner.startsWith("Landroidx/appcompat/")
                    || owner.startsWith("Landroidx/recyclerview/") || owner.startsWith("Lcom/google/android/material/")
                    || owner.startsWith("Landroidx/compose/runtime/");
        }

        /** 0.66.5: 0 = a real source is among the arguments, 1 = only parameter labels, -1 = nothing tainted. */
        private int taintKind(Tv[] t) {
            int k = -1;
            for (Tv x : t) {
                if (x.level > 0) return 0;
                if (!x.isNone()) k = 1;
            }
            return k;
        }

        private void noteLibDrop(String owner, Tv[] t) {
            int k = taintKind(t);
            if (k < 0) return;
            boolean app = run.isAppOwner(owner);
            (app ? dUnres : dLib)[k]++;
            if (k != 0) return;      // 0.66.6: the owner list is only for drops that carried a REAL source (parameter-only drops are the bulk and hide them)
            String shortOwner = owner.length() > 2 && owner.startsWith("L") && owner.endsWith(";") ? owner.substring(1, owner.length() - 1) : owner;
            if (libOwners == null) libOwners = new HashMap<>();
            libOwners.merge((app ? "app " : "") + shortOwner, 1, Integer::sum);
        }

        void hit(Sink s, Insn in, Tv tt) {
            String api = shortKey(s.owner + "->" + s.name);
            SinkRef r = new SinkRef(m.key(), in.index, api, s.title, s.sev, s.cwe, Collections.singletonList(m.key()));
            for (int k = 0; k < 64; k++) if ((tt.params & (1L << k)) != 0) sum.addSink(k, r);
            if (tt.level > 0) addFlow(tt, r, Collections.singletonList(m.key()));
        }

        /** A callee sends its parameter to a sink; the value held here is {@code tt}. */
        void hitVia(SinkRef r, Tv tt) {
            if (r.chain.size() + 1 > MAX_DEPTH) return;
            List<String> chain = new ArrayList<>(r.chain.size() + 1);
            chain.add(m.key());
            chain.addAll(r.chain);
            SinkRef nr = new SinkRef(r.method, r.insn, r.api, r.title, r.sev, r.cwe, chain);
            for (int k = 0; k < 64; k++) if ((tt.params & (1L << k)) != 0) sum.addSink(k, nr);
            if (tt.level > 0) addFlow(tt, nr, chain);
        }

        void addFlow(Tv tt, SinkRef r, List<String> chain) {
            if (r.title.equals(T_REDIRECT) && !REDIRECT_SOURCES.contains(tt.src)) return;      // 0.74.0: only the Intent object itself, not extras it carries
            String k = r.key() + "|" + tt.src;
            Flow o = flowByKey.get(k);
            if (o != null) {
                if (!o.weak && tt.weak) return;                                     // 0.68.5: a strong flow is never replaced by a weak one
                if (!(o.weak && !tt.weak) && o.chain.size() <= chain.size()) return;
            }
            // 0.83.0 (AnkiDroid: Intent.getData() reached evaluateJavascript through four type-erased hops, `(Object,Object)Object` coroutine /
            // lambda glue): a chain with ERASED_WEAK or more methods whose signature carries no type information joins unrelated values, so
            // the flow is a weak lead
            boolean weakNow = tt.weak;
            String viaNow = tt.via;
            if (!weakNow && tt.level > 0 && erasedHops(chain) >= ERASED_WEAK) { weakNow = true; viaNow = ERASED_MARK + (tt.via == null ? "" : tt.via); }
            // 0.83.0 (FairEmail: 9 HIGH cards from Parcelable EntityAttachment fields that only travel inside the app): a value read from a Parcel
            // in one method and used in ANOTHER needs the whole Parcelable to come from outside; used right where it is read (OVAA
            // MemoryCorruptionParcelable.<init> -> Class.forName) it is a weakness of the unmarshalling code itself and stays strong
            // via != null: the value came back from a callee or a field, it was not read right here
            else if (!weakNow && tt.src != null && tt.src.startsWith("Parcel.") && (chain.size() > 1 || tt.via != null)) { weakNow = true; viaNow = PARCEL_HELD_MARK + (tt.via == null ? "" : tt.via); }
            Flow f = new Flow(tt.src, tt.level, viaNow, weakNow, tt.internal, r, chain);
            if (o != null) flows.remove(o);
            flows.add(f);
            flowByKey.put(k, f);
        }
    }
}
