package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 0.75.0: SSA-based rules that look at ONE class at a time (no call graph, no taint solver, no shared state).
 * Each rule first checks the instruction list for its trigger API and builds the SSA form only for the methods that have it,
 * so a class without the trigger costs one linear pass over its instructions.
 *
 *  - {@link #intentSends}: sendBroadcast / startService / bindService with an Intent that is provably implicit (intent sniffing, CWE-927).
 *  - {@link #sqliteSensitive}: a sensitive column / value written to plain android.database.sqlite (CWE-312), else one INFO per SQLiteOpenHelper.
 *  - {@link #pluginState}: WebSettings.setPluginState(PluginState.ON / ON_DEMAND), setPluginsEnabled(true) (CWE-477).
 *
 * Precision policy: when a value cannot be traced to its origin inside the method (parameter, field, return value of another method,
 * an Intent that escapes to a helper), the rule stays QUIET. A miss is preferred to a guess.
 */
public final class IrRules {

    private IrRules() {}

    public static final class Hit {
        public final String rule, title, sev, conf, cwe, detail, method;
        public final int offset;

        Hit(String rule, String title, String sev, String conf, String cwe, String detail, String method, int offset) {
            this.rule = rule; this.title = title; this.sev = sev; this.conf = conf; this.cwe = cwe;
            this.detail = detail; this.method = method; this.offset = offset;
        }
    }

    static final int MAX_DEPTH = 24;
    static final String INTENT = "Landroid/content/Intent;";

    // ============================================================================================ helpers

    private static String strLit(Insn in) {
        if (in == null || in.kind != Insn.Kind.CONST) return null;
        String r = in.ref;
        if (r.length() >= 2 && r.startsWith("\"") && r.endsWith("\"")) return r.substring(1, r.length() - 1);
        return null;
    }

    private static boolean isNullConst(SsaForm.Value v) {
        if (v == null || v.def == null || v.def.kind != Insn.Kind.CONST) return false;
        String r = v.def.ref.trim();
        return r.equals("0x0") || r.equals("0") || r.equals("0x0L");
    }

    /** move / check-cast chain back to the value that really defines this one (phi and entry values are returned as they are). */
    private static SsaForm.Value strip(SsaForm ssa, SsaForm.Value v) {
        for (int i = 0; v != null && i < MAX_DEPTH; i++) {
            if (v.def != null && (v.def.kind == Insn.Kind.MOVE || v.def.kind == Insn.Kind.CHECK_CAST)) {
                SsaForm.Value[] us = ssa.usesOf(v.def);
                if (us == null || us.length == 0) return v;
                v = us[0];
            } else return v;
        }
        return v;
    }

    /** String constant held by v (through moves / casts), or null. */
    private static String constString(SsaForm ssa, SsaForm.Value v) {
        v = strip(ssa, v);
        return v == null ? null : strLit(v.def);
    }

    private static SsaForm.Value arg(SsaForm ssa, Insn in, int idx) {
        SsaForm.Value[] us = ssa.usesOf(in);
        return (us != null && idx < us.length) ? us[idx] : null;
    }

    private static boolean isPlatformName(String s) {
        return s.startsWith("android.") || s.startsWith("androidx.") || s.startsWith("com.android.");
    }

    private static boolean hasInvoke(MethodIr m, Set<String> names) {
        for (Insn in : m.insns) if (in.kind == Insn.Kind.INVOKE && names.contains(in.targetName())) return true;
        return false;
    }

    private static String desc(Insn in) {
        String s = in.targetSig();
        int p = s.indexOf('(');
        return p < 0 ? s : s.substring(p);
    }

    private static SsaForm ssaOf(MethodIr m) {
        try { return SsaForm.build(m); } catch (Throwable t) { return null; }
    }

    // ============================================================================================ 1. intent sniffing

    static final Set<String> SEND_NAMES = new HashSet<>(Arrays.asList(
            "sendBroadcast", "sendBroadcastAsUser", "sendOrderedBroadcast", "sendOrderedBroadcastAsUser", "sendStickyBroadcast",
            "sendStickyBroadcastAsUser", "sendStickyOrderedBroadcast", "startService", "startForegroundService", "bindService"));
    private static final Set<String> LOCAL_BROADCAST = new HashSet<>(Arrays.asList(
            "Landroidx/localbroadcastmanager/content/LocalBroadcastManager;", "Landroid/support/v4/content/LocalBroadcastManager;"));
    private static final Set<String> MAKES_EXPLICIT = new HashSet<>(Arrays.asList("setPackage", "setComponent", "setClass", "setClassName"));
    private static final Set<String> PAYLOAD = new HashSet<>(Arrays.asList(
            "putExtra", "putExtras", "putStringArrayListExtra", "putParcelableArrayListExtra", "setData", "setDataAndType",
            "setDataAndNormalize", "setClipData"));
    static final Pattern SENSITIVE = Pattern.compile(
            "(?i)(passw|passwd|pwd|pin\\b|token|secret|credential|session|otp|cookie|auth|api[_-]?key|card|cvv|iban|ssn|email|phone|location|latitude|longitude|imei|account)");

    /** What is known about one `new Intent` site after looking at every instruction that touches it. */
    private static final class IntentFacts {
        boolean explicit, unknown, payload;
        String action;
        final List<String> keys = new ArrayList<>(4);
    }

    /** Index of the permission argument (uses[] index, receiver = 0) or -1 when the call has no permission parameter. */
    private static int permissionArg(String name, String d) {
        switch (name) {
            case "sendBroadcast": return d.startsWith("(Landroid/content/Intent;Ljava/lang/String;") ? 2 : -1;
            case "sendOrderedBroadcast": return d.startsWith("(Landroid/content/Intent;Ljava/lang/String;") ? 2 : -1;
            case "sendBroadcastAsUser":
            case "sendOrderedBroadcastAsUser": return d.startsWith("(Landroid/content/Intent;Landroid/os/UserHandle;Ljava/lang/String;") ? 3 : -1;
            default: return -1;
        }
    }

    /**
     * Allocation sites (`new-instance Landroid/content/Intent;`) the value can come from, through moves, casts, phis and Intent builder
     * calls that return `this` (setAction(..), putExtra(..) ...). null = some origin is not an allocation in this method (parameter, field,
     * result of another method, copy constructor ...): the Intent cannot be judged and the rule stays quiet.
     */
    private static Set<SsaForm.Value> origins(SsaForm ssa, SsaForm.Value v, Set<SsaForm.Value> seen, int depth) {
        if (v == null || depth > MAX_DEPTH) return null;
        Set<SsaForm.Value> out = new LinkedHashSet<>();
        if (!seen.add(v)) return out;                           // loop through a phi: already handled
        if (v.phi != null) {
            if (v.phi.operands.length == 0) return null;
            for (SsaForm.Value o : v.phi.operands) {
                Set<SsaForm.Value> s = origins(ssa, o, seen, depth + 1);
                if (s == null) return null;
                out.addAll(s);
            }
            return out;
        }
        Insn d = v.def;
        if (d == null) return null;                             // parameter / undefined
        switch (d.kind) {
            case NEW_INSTANCE:
                if (!d.ref.equals(INTENT)) return null;
                out.add(v);
                return out;
            case MOVE: case CHECK_CAST: {
                SsaForm.Value[] us = ssa.usesOf(d);
                return (us == null || us.length == 0) ? null : origins(ssa, us[0], seen, depth + 1);
            }
            case INVOKE: {
                // Intent builder that returns the receiver (Intent.setAction / putExtra / addFlags ... all return `this`)
                if (d.targetOwner().equals(INTENT) && !d.invokeKind().equals("static") && d.targetSig().endsWith(")" + INTENT)) {
                    SsaForm.Value[] us = ssa.usesOf(d);
                    return (us == null || us.length == 0) ? null : origins(ssa, us[0], seen, depth + 1);
                }
                return null;
            }
            default:
                return null;
        }
    }

    /** Every SSA value that is the same object as the allocation [alloc] (moves, casts, builder results, phis fed by it). */
    private static Set<SsaForm.Value> aliases(MethodIr m, SsaForm ssa, SsaForm.Value alloc) {
        Set<SsaForm.Value> a = new HashSet<>();
        a.add(alloc);
        boolean grew = true;
        for (int round = 0; grew && round < 8; round++) {
            grew = false;
            for (Insn in : m.insns) {
                SsaForm.Value[] us = ssa.usesOf(in), ds = ssa.defsOf(in);
                if (us == null || ds == null || ds.length == 0 || us.length == 0) continue;
                boolean same = (in.kind == Insn.Kind.MOVE || in.kind == Insn.Kind.CHECK_CAST) && a.contains(us[0])
                        || in.kind == Insn.Kind.INVOKE && in.targetOwner().equals(INTENT) && !in.invokeKind().equals("static")
                           && in.targetSig().endsWith(")" + INTENT) && a.contains(us[0]);
                if (same && a.add(ds[0])) grew = true;
            }
            if (ssa.phis != null)
                for (List<SsaForm.Phi> ps : ssa.phis) {
                    if (ps == null) continue;
                    for (SsaForm.Phi p : ps) {
                        SsaForm.Value pv = phiValue(p);
                        if (pv == null || a.contains(pv)) continue;
                        for (SsaForm.Value o : p.operands) if (a.contains(o)) { a.add(pv); grew = true; break; }
                    }
                }
        }
        return a;
    }

    private static SsaForm.Value phiValue(SsaForm.Phi p) {
        return p.result;
    }

    private static IntentFacts facts(MethodIr m, SsaForm ssa, SsaForm.Value alloc, Insn send) {
        IntentFacts f = new IntentFacts();
        Set<SsaForm.Value> a = aliases(m, ssa, alloc);
        for (Insn in : m.insns) {
            SsaForm.Value[] us = ssa.usesOf(in);
            if (us == null) continue;
            int pos = -1;
            for (int i = 0; i < us.length; i++) if (us[i] != null && a.contains(us[i])) { pos = i; break; }
            if (pos < 0) continue;
            if (in == send) continue;
            switch (in.kind) {
                case MOVE: case CHECK_CAST: case MONITOR: case INSTANCE_OF:
                    continue;
                case INVOKE: {
                    String owner = in.targetOwner(), name = in.targetName();
                    if (owner.equals(INTENT) && pos == 0 && !in.invokeKind().equals("static")) {
                        if (name.equals("<init>")) {
                            String d = desc(in);
                            if (d.contains("Ljava/lang/Class;") || d.contains("Landroid/content/ComponentName;")) f.explicit = true;
                            else if (d.startsWith("(Landroid/content/Intent;")) f.unknown = true;       // copy of another Intent
                            if (d.startsWith("(Ljava/lang/String;")) {
                                String s = constString(ssa, arg(ssa, in, 1));
                                if (s != null) f.action = s;
                            }
                            if (d.contains("Landroid/net/Uri;")) f.payload = true;
                        } else if (MAKES_EXPLICIT.contains(name)) {
                            if (!isNullConst(arg(ssa, in, 1))) f.explicit = true;                       // setPackage(null) clears the package
                        } else if (name.equals("setAction")) {
                            String s = constString(ssa, arg(ssa, in, 1));
                            if (s != null) f.action = s;
                        } else if (PAYLOAD.contains(name)) {
                            f.payload = true;
                            String k = constString(ssa, arg(ssa, in, 1));
                            if (k != null && f.keys.size() < 8) f.keys.add(k);
                        } else if (name.equals("fillIn") || name.equals("setSelector")) {
                            f.unknown = true;
                        }
                        continue;
                    }
                    if (pos > 0 && owner.equals(INTENT) && (name.startsWith("put") || name.equals("createChooser"))) continue;   // carried as data
                    f.unknown = true;          // handed to another method: it may set a package / component there
                    continue;
                }
                default:
                    f.unknown = true;          // stored in a field / array, returned, thrown ...
            }
        }
        return f;
    }

    public static List<Hit> intentSends(ClassIr c) {
        List<Hit> out = new ArrayList<>();
        if (c == null) return out;
        for (MethodIr m : c.methods) {
            if (m.insns.isEmpty() || !hasInvoke(m, SEND_NAMES)) continue;
            SsaForm ssa = ssaOf(m);
            if (ssa == null) continue;
            for (Insn in : m.insns) {
                if (in.kind != Insn.Kind.INVOKE || !SEND_NAMES.contains(in.targetName()) || in.invokeKind().equals("static")) continue;
                String name = in.targetName(), d = desc(in), owner = in.targetOwner();
                if (!d.startsWith("(" + INTENT) || LOCAL_BROADCAST.contains(owner)) continue;
                if (owner.equals(c.type) && c.method(in.targetSig()) != null) continue;   // the class's own helper with the same name
                try {
                    int pa = permissionArg(name, d);
                    if (pa > 0 && !isNullConst(arg(ssa, in, pa))) continue;                     // receiver permission given
                    Set<SsaForm.Value> org = origins(ssa, arg(ssa, in, 1), new HashSet<>(), 0);
                    if (org == null || org.isEmpty()) continue;
                    boolean anyImplicit = false, unknown = false, payload = false;
                    String action = null;
                    List<String> keys = new ArrayList<>();
                    for (SsaForm.Value al : org) {
                        IntentFacts f = facts(m, ssa, al, in);
                        if (f.unknown) { unknown = true; break; }
                        if (!f.explicit) {
                            anyImplicit = true;
                            payload |= f.payload;
                            if (f.action != null) action = f.action;
                            keys.addAll(f.keys);
                        }
                    }
                    if (unknown || !anyImplicit) continue;
                    boolean service = name.equals("startService") || name.equals("startForegroundService") || name.equals("bindService");
                    boolean platform = action != null && isPlatformName(action);
                    List<String> sensitive = new ArrayList<>();
                    for (String k : keys) if (!isPlatformName(k) && SENSITIVE.matcher(k).find()) sensitive.add(k);   // android.media.extra.AUDIO_SESSION is API, not a secret
                    boolean sensAction = action != null && !platform && SENSITIVE.matcher(action).find();
                    if (platform && sensitive.isEmpty()) continue;                              // system action (media scanner ...), nothing private
                    boolean ownPayload = payload;                                   // extras that are all platform keys (AudioEffect sessions ...) are API, not app data
                    if (payload && !keys.isEmpty()) { ownPayload = false; for (String k : keys) if (!isPlatformName(k)) { ownPayload = true; break; } }
                    String sev = !sensitive.isEmpty() || sensAction ? "HIGH" : ownPayload ? "MEDIUM" : "LOW";
                    if (service) sev = sev.equals("HIGH") ? "MEDIUM" : "LOW";
                    String what = service
                            ? "This " + name + "() gets an Intent with no package or component. Since Android 5.0 such a call throws, but on older devices (and in apps with an old targetSdk) any app that declares a matching intent-filter receives it and can impersonate the service."
                            : "This " + name + "() sends an Intent with no package, no component and no receiver permission, so ANY installed app that registers a receiver for "
                              + (action != null ? "the action \"" + action + "\"" : "this Intent") + " receives it (intent sniffing).";
                    StringBuilder det = new StringBuilder(what);
                    if (!sensitive.isEmpty()) det.append(" It carries extras that look private: ").append(String.join(", ", sensitive)).append('.');
                    else if (ownPayload) det.append(" It carries extras or data.");
                    else if (payload) det.append(" Its extras are platform keys (").append(String.join(", ", keys)).append("), not app data.");
                    else det.append(" No extras were seen, so the leak is the event itself.");
                    det.append(" Traced in SSA: the Intent is built in this method and never handed to another method before the call.");
                    out.add(new Hit(service ? "implicit-service-intent" : "broadcast-unprotected-send",
                            service ? "Service started with an implicit Intent" : "Broadcast sent without a receiver permission",
                            sev, "HIGH", "CWE-927", det.toString(), m.key(), in.offset));
                } catch (Throwable ignored) {
                    // one bad call site never stops the class
                }
            }
        }
        return out;
    }

    // ============================================================================================ 2. plain SQLite

    private static final String DB = "Landroid/database/sqlite/SQLiteDatabase;";
    private static final String CV = "Landroid/content/ContentValues;";
    private static final String STMT = "Landroid/database/sqlite/SQLiteStatement;";
    static final Pattern SENSITIVE_COL = Pattern.compile(
            "(?i)(passw|passwd|\\bpwd\\b|_pwd|pwd_|\\bpin\\b|_pin\\b|pincode|token|secret|credential|otp|session_?id|cookie|api_?key|"
                    + "card_?(no|num)|cardnumber|credit_?card|cvv|iban|ssn|social_?security)");
    private static final Pattern CREATE_TABLE = Pattern.compile("(?is)^\\s*create\\s+table");
    /** Calls whose result is private data by itself (no column name needed). */
    private static final Map<String, String> PII_SOURCES = new HashMap<>();
    static {
        PII_SOURCES.put("Landroid/accounts/AccountManager;->getPassword", "AccountManager.getPassword()");
        PII_SOURCES.put("Landroid/accounts/AccountManager;->peekAuthToken", "AccountManager.peekAuthToken()");
        PII_SOURCES.put("Landroid/accounts/AccountManager;->blockingGetAuthToken", "AccountManager.blockingGetAuthToken()");
        PII_SOURCES.put("Landroid/telephony/TelephonyManager;->getDeviceId", "TelephonyManager.getDeviceId()");
        PII_SOURCES.put("Landroid/telephony/TelephonyManager;->getImei", "TelephonyManager.getImei()");
        PII_SOURCES.put("Landroid/telephony/TelephonyManager;->getSubscriberId", "TelephonyManager.getSubscriberId()");
        PII_SOURCES.put("Landroid/telephony/TelephonyManager;->getLine1Number", "TelephonyManager.getLine1Number()");
        PII_SOURCES.put("Landroid/telephony/TelephonyManager;->getSimSerialNumber", "TelephonyManager.getSimSerialNumber()");
        PII_SOURCES.put("Landroid/location/Location;->getLatitude", "Location.getLatitude()");
        PII_SOURCES.put("Landroid/location/Location;->getLongitude", "Location.getLongitude()");
    }
    private static final Set<String> STRINGY = new HashSet<>(Arrays.asList(
            "Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;", "Ljava/lang/String;", "Ljava/lang/Double;", "Ljava/lang/Long;",
            "Ljava/lang/Integer;", "Landroid/text/Editable;", "Ljava/lang/CharSequence;", "Ljava/lang/Object;"));
    private static final Pattern PROTECTS = Pattern.compile(
            "(?i)(MessageDigest|Cipher|Mac|SecretKeyFactory|BCrypt|Argon|scrypt|pbkdf|hash|digest|encrypt|cipher|keystore)");

    /**
     * Backward slice of v inside the method (moves, casts, phis, string building, boxing). Returns the name of a PII source call it reaches,
     * "protected" when a hash / cipher call is on the way (the stored value is not the plain secret), or null.
     */
    private static String sliceSource(SsaForm ssa, SsaForm.Value v, Set<SsaForm.Value> seen, int depth) {
        if (v == null || depth > MAX_DEPTH || !seen.add(v)) return null;
        if (v.phi != null) {
            String best = null;
            for (SsaForm.Value o : v.phi.operands) {
                String s = sliceSource(ssa, o, seen, depth + 1);
                if ("protected".equals(s)) return s;
                if (s != null) best = s;
            }
            return best;
        }
        Insn d = v.def;
        if (d == null) return null;
        SsaForm.Value[] us = ssa.usesOf(d);
        switch (d.kind) {
            case MOVE: case CHECK_CAST:
                return (us == null || us.length == 0) ? null : sliceSource(ssa, us[0], seen, depth + 1);
            case INVOKE: {
                String owner = d.targetOwner(), name = d.targetName();
                if (PROTECTS.matcher(owner + "->" + name).find()) return "protected";
                String src = PII_SOURCES.get(owner + "->" + name);
                if (src != null) return src;
                if (!STRINGY.contains(owner)) return null;              // another app / library method: not followed (stays quiet)
                String best = null;
                if (us != null) for (SsaForm.Value u : us) {
                    String s = sliceSource(ssa, u, seen, depth + 1);
                    if ("protected".equals(s)) return s;
                    if (s != null) best = s;
                }
                return best;
            }
            default:
                return null;
        }
    }

    /** Column name for a key value: a string constant, or the NAME of a constant field (COLUMN_PASSWORD) read with sget-object. */
    private static String keyName(SsaForm ssa, SsaForm.Value v) {
        v = strip(ssa, v);
        if (v == null || v.def == null) return null;
        String s = strLit(v.def);
        if (s != null) return s;
        if (v.def.kind == Insn.Kind.FIELD_GET && v.def.ref.contains("->")) {
            String f = v.def.ref.substring(v.def.ref.indexOf("->") + 2);
            int colon = f.indexOf(':');
            return colon > 0 ? f.substring(0, colon) : f;
        }
        return null;
    }

    /** The whole identifier (column name) around the first sensitive match in an SQL text, or null. */
    private static String sensitiveWord(String sql) {
        java.util.regex.Matcher mm = SENSITIVE_COL.matcher(sql);
        if (!mm.find()) return null;
        int a = mm.start(), b = mm.end();
        while (a > 0 && (Character.isLetterOrDigit(sql.charAt(a - 1)) || sql.charAt(a - 1) == '_')) a--;
        while (b < sql.length() && (Character.isLetterOrDigit(sql.charAt(b)) || sql.charAt(b) == '_')) b++;
        return sql.substring(a, b);
    }

    /** True when the class text shows an SQLCipher (or another encrypted SQLite) database. */
    public static boolean usesEncryptedSqlite(String classText) {
        return classText.contains("Lnet/sqlcipher/") || classText.contains("Lnet/zetetic/") || classText.contains("Lio/requery/android/database/sqlite/");
    }

    public static List<Hit> sqliteSensitive(ClassIr c, String classText) {
        List<Hit> out = new ArrayList<>();
        if (c == null || classText == null || usesEncryptedSqlite(classText)) return out;
        Set<String> seenCols = new HashSet<>();
        boolean helper = c.superType.equals("Landroid/database/sqlite/SQLiteOpenHelper;");
        int firstDbOffset = -1;
        for (MethodIr m : c.methods) {
            if (m.insns.isEmpty()) continue;
            boolean touchesDb = false;
            for (Insn in : m.insns)
                if (in.kind == Insn.Kind.INVOKE && (in.targetOwner().equals(DB) || in.targetOwner().equals(STMT) || in.targetOwner().equals(CV))) { touchesDb = true; break; }
            if (!touchesDb) continue;
            SsaForm ssa = ssaOf(m);
            if (ssa == null) continue;
            for (Insn in : m.insns) {
                if (in.kind != Insn.Kind.INVOKE) continue;
                String owner = in.targetOwner(), name = in.targetName();
                try {
                    if (owner.equals(DB) && firstDbOffset < 0) firstDbOffset = in.offset;
                    String col = null, src = null, why = null;
                    if (owner.equals(CV) && name.equals("put")) {
                        col = keyName(ssa, arg(ssa, in, 1));
                        src = sliceSource(ssa, arg(ssa, in, 2), new HashSet<>(), 0);
                        why = "ContentValues.put";
                    } else if (owner.equals(DB) && name.equals("execSQL")) {
                        String sql = constString(ssa, arg(ssa, in, 1));
                        if (sql != null && CREATE_TABLE.matcher(sql).find()) {
                            // 0.75.2: the column list (inside the parentheses) first; a sensitive TABLE name alone is said as such
                            int lp = sql.indexOf('('), rp = sql.lastIndexOf(')');
                            col = lp >= 0 && rp > lp ? sensitiveWord(sql.substring(lp + 1, rp)) : null;
                            if (col != null) why = "CREATE TABLE column";
                            else { col = sensitiveWord(lp >= 0 ? sql.substring(0, lp) : sql); if (col != null) why = "CREATE TABLE name"; }
                        } else if (sql != null && sql.trim().toLowerCase().startsWith("insert")) {
                            // 0.75.2 (Allsafe NoteDatabaseHelper FP): only the COLUMN LIST, never the VALUES text
                            // ("... values ('admin', '... still using 123456 as her password')" is note text, not a password column)
                            String low = sql.toLowerCase();
                            int lp = sql.indexOf('('), vi = low.indexOf("values");
                            if (lp >= 0 && (vi < 0 || lp < vi)) {
                                int rp = sql.indexOf(')', lp);
                                col = rp > lp ? sensitiveWord(sql.substring(lp + 1, rp)) : null;
                                if (col != null) why = "INSERT column";
                            }
                        }
                        if (desc(in).startsWith("(Ljava/lang/String;[Ljava/lang/Object;")) {
                            String s2 = sliceSource(ssa, arg(ssa, in, 1), new HashSet<>(), 0);
                            if (s2 != null) src = s2;
                        }
                    } else if (owner.equals(STMT) && name.startsWith("bind") && !name.equals("bindNull")) {
                        src = sliceSource(ssa, arg(ssa, in, 2), new HashSet<>(), 0);
                        why = "SQLiteStatement." + name;
                    } else continue;
                    if ("protected".equals(src)) continue;                                  // hashed / encrypted on the way: fine
                    boolean colHit = col != null && SENSITIVE_COL.matcher(col).find();
                    if (!colHit && src == null) continue;
                    String keyOfHit = (colHit ? col.toLowerCase() : "") + "|" + (src == null ? "" : src);
                    if (!seenCols.add(keyOfHit) || out.size() >= 3) continue;
                    String sev = colHit && src != null ? "HIGH" : colHit ? "MEDIUM" : "MEDIUM";
                    String conf = colHit && "CREATE TABLE column".equals(why) ? "HIGH" : "MEDIUM";
                    StringBuilder det = new StringBuilder("Private data is written to a plain (unencrypted) SQLite database");
                    if (colHit) det.append("CREATE TABLE name".equals(why) ? ": the table \"" : ": the column \"").append(col).append("\" (").append(why).append(")");
                    if (src != null) det.append(colHit ? " receives " : ": the value comes from ").append(src);
                    det.append(". The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image.")
                       .append(" No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).");
                    out.add(new Hit("sqlite-unencrypted", "Sensitive data stored in plain SQLite", sev, conf, "CWE-312", det.toString(), m.key(), in.offset));
                } catch (Throwable ignored) {
                }
            }
        }
        if (out.isEmpty() && helper && firstDbOffset < 0) {
            for (MethodIr m : c.methods) if (!m.insns.isEmpty()) { firstDbOffset = m.insns.get(0).offset; break; }
        }
        if (out.isEmpty() && helper && firstDbOffset >= 0)
            out.add(new Hit("sqlite-unencrypted", "SQLite database is not encrypted", "INFO", "LOW", "CWE-312",
                    "This SQLiteOpenHelper opens a plain SQLite database. No private column or value was proven to reach it, so this is hygiene only: if the database ever holds tokens, credentials or personal data, use SQLCipher (or encrypt the values with a Keystore key).",
                    "", firstDbOffset));
        return out;
    }

    // ============================================================================================ 3. setPluginState

    private static final String WS = "Landroid/webkit/WebSettings;";
    private static final String PS = "Landroid/webkit/WebSettings$PluginState;";

    /** The PluginState constant names (ON / ON_DEMAND / OFF) v can hold; "?" for an origin that cannot be told. */
    private static void pluginStates(SsaForm ssa, SsaForm.Value v, Set<String> out, Set<SsaForm.Value> seen, int depth) {
        if (v == null || depth > MAX_DEPTH || !seen.add(v)) return;
        if (v.phi != null) {
            for (SsaForm.Value o : v.phi.operands) pluginStates(ssa, o, out, seen, depth + 1);
            return;
        }
        Insn d = v.def;
        if (d == null) { out.add("?"); return; }
        if (d.kind == Insn.Kind.MOVE || d.kind == Insn.Kind.CHECK_CAST) {
            SsaForm.Value[] us = ssa.usesOf(d);
            if (us != null && us.length > 0) pluginStates(ssa, us[0], out, seen, depth + 1); else out.add("?");
            return;
        }
        if (d.kind == Insn.Kind.FIELD_GET && d.ref.startsWith(PS + "->")) {
            String f = d.ref.substring(PS.length() + 2);
            out.add(f.substring(0, Math.max(0, f.indexOf(':'))));
            return;
        }
        if (d.kind == Insn.Kind.INVOKE && d.targetOwner().equals(PS) && d.targetName().equals("valueOf")) {
            String s = constString(ssa, arg(ssa, d, 0));
            out.add(s == null ? "?" : s);
            return;
        }
        out.add("?");
    }

    public static List<Hit> pluginState(ClassIr c) {
        List<Hit> out = new ArrayList<>();
        if (c == null) return out;
        Set<String> names = new HashSet<>(Arrays.asList("setPluginState", "setPluginsEnabled"));
        for (MethodIr m : c.methods) {
            if (m.insns.isEmpty() || !hasInvoke(m, names)) continue;
            SsaForm ssa = ssaOf(m);
            if (ssa == null) continue;
            for (Insn in : m.insns) {
                if (in.kind != Insn.Kind.INVOKE || !in.targetOwner().equals(WS) || !names.contains(in.targetName())) continue;
                try {
                    SsaForm.Value v = arg(ssa, in, 1);
                    String state;
                    if (in.targetName().equals("setPluginsEnabled")) {
                        SsaForm.Value s = strip(ssa, v);
                        if (s == null || s.def == null || s.def.kind != Insn.Kind.CONST || isNullConst(s)) continue;   // false or unknown
                        state = "ON (setPluginsEnabled(true))";
                    } else {
                        Set<String> st = new LinkedHashSet<>();
                        pluginStates(ssa, v, st, new HashSet<>(), 0);
                        boolean on = st.contains("ON"), onDemand = st.contains("ON_DEMAND");
                        if (!on && !onDemand) continue;
                        state = on ? "ON" : "ON_DEMAND";
                        if (st.size() > 1) state += " on at least one path";
                    }
                    out.add(new Hit("webview-plugin-state", "WebView plugins enabled (deprecated setPluginState)",
                            state.startsWith("ON_DEMAND") ? "INFO" : "LOW", "HIGH", "CWE-477",
                            "WebSettings plugins are switched " + state + ". Plugins (Flash and other NPAPI) are not supported since Android 4.3 and the API was removed in API 24, so this matters only on very old devices, where a page could load a plugin with known remote-code bugs; it also shows the WebView setup was copied from old code: review the other WebSettings of this view.",
                            m.key(), in.offset));
                } catch (Throwable ignored) {
                }
            }
        }
        return out;
    }

    // ============================================================================================ 4. weak random (0.75.1)

    private static final String RANDOM = "Ljava/util/Random;";
    private static final Set<String> RANDOM_OUT = new HashSet<>(Arrays.asList(
            "nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean", "nextBytes", "nextGaussian", "ints", "longs"));
    static final Pattern SECURITY_NAME = Pattern.compile(
            "(?i)(token|session|nonce|otp|salt|secret|passw|pwd|pin\\b|pincode|csrf|apikey|api_key|key|iv\\b|crypt|auth|captcha|verif|reset|code)");
    private static final Set<String> KEY_SINKS = new HashSet<>(Arrays.asList(
            "Ljavax/crypto/spec/SecretKeySpec;", "Ljavax/crypto/spec/IvParameterSpec;", "Ljavax/crypto/spec/GCMParameterSpec;",
            "Ljavax/crypto/spec/PBEKeySpec;", "Ljavax/crypto/spec/PBEParameterSpec;"));
    private static final Set<String> DERIVE = new HashSet<>(Arrays.asList(
            "Ljava/lang/String;", "Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;", "Ljava/lang/Integer;", "Ljava/lang/Long;",
            "Ljava/lang/Character;", "Ljava/lang/Math;", "Landroid/util/Base64;", "Ljava/util/Base64$Encoder;", "Ljava/util/Arrays;",
            "Ljava/math/BigInteger;", "Ljava/util/UUID;"));

    /** Allocation type behind a Random receiver: "weak" (new Random / Math.random), "secure" (new SecureRandom), null (unknown). */
    private static String randomKind(SsaForm ssa, SsaForm.Value v, int depth) {
        v = strip(ssa, v);
        if (v == null || depth > MAX_DEPTH) return null;
        if (v.phi != null) {
            String k = null;
            for (SsaForm.Value o : v.phi.operands) {
                String x = randomKind(ssa, o, depth + 1);
                if (x == null) return null;
                if ("weak".equals(x)) k = "weak"; else if (k == null) k = x;
            }
            return k;
        }
        if (v.def != null && v.def.kind == Insn.Kind.NEW_INSTANCE) {
            if (v.def.ref.equals(RANDOM)) return "weak";
            if (v.def.ref.equals("Ljava/security/SecureRandom;")) return "secure";
        }
        return null;                         // field / parameter / factory: may be a SecureRandom held as Random -> quiet
    }

    /**
     * java.util.Random / Math.random whose OUTPUT reaches a security use inside the method: a key / IV / PBE spec, a field / column / extra /
     * preference named like a secret, or the return value of a method (or class) named like one, or of a class that uses javax.crypto.
     * The output is followed forward through moves, arithmetic, conversions, string building and arrays (nextBytes / aput).
     */
    public static List<Hit> weakRandom(ClassIr c, String classText) {
        List<Hit> out = new ArrayList<>();
        if (c == null) return out;
        boolean cryptoClass = classText != null && (classText.contains("Ljavax/crypto/") || classText.contains("Ljava/security/MessageDigest;"));
        // 0.108.0 (WE Wallet: DexGuard renames classes and methods with dictionary words, e.g. "getKeyTemplate$values", "isEnableSecuringAccountPin", "registerEncoder"):
        // in a class renamed into the root package, class / method / field NAMES are not evidence; the code's own evidence (crypto use, key sinks, string keys) still is
        boolean renamed = c.type.indexOf('/') < 0;
        boolean classNamed = !renamed && SECURITY_NAME.matcher(c.type.substring(c.type.lastIndexOf('/') + 1)).find();
        for (MethodIr m : c.methods) {
            if (m.insns.isEmpty()) continue;
            boolean has = false;
            for (Insn in : m.insns)
                if (in.kind == Insn.Kind.INVOKE && (in.targetOwner().equals(RANDOM) && RANDOM_OUT.contains(in.targetName())
                        || in.targetOwner().equals("Ljava/lang/Math;") && in.targetName().equals("random"))) { has = true; break; }
            if (!has) continue;
            SsaForm ssa = ssaOf(m);
            if (ssa == null) continue;
            for (Insn src : m.insns) {
                if (src.kind != Insn.Kind.INVOKE) continue;
                boolean math = src.targetOwner().equals("Ljava/lang/Math;") && src.targetName().equals("random");
                if (!math && !(src.targetOwner().equals(RANDOM) && RANDOM_OUT.contains(src.targetName()))) continue;
                try {
                    String seeded = null;
                    if (!math) {
                        SsaForm.Value recv = arg(ssa, src, 0);
                        if (!"weak".equals(randomKind(ssa, recv, 0))) continue;
                        SsaForm.Value r = strip(ssa, recv);
                        for (Insn in : m.insns)            // new Random(<constant>) = the same numbers on every run
                            if (in.kind == Insn.Kind.INVOKE && in.targetOwner().equals(RANDOM) && in.targetName().equals("<init>")
                                    && desc(in).startsWith("(J)") && r != null && arg(ssa, in, 0) == r) {
                                SsaForm.Value sd = strip(ssa, arg(ssa, in, 1));
                                if (sd != null && sd.def != null && sd.def.kind == Insn.Kind.CONST) seeded = sd.def.ref;
                            }
                    }
                    Set<SsaForm.Value> d = new HashSet<>();
                    SsaForm.Value[] ds = ssa.defsOf(src);
                    if (ds != null) for (SsaForm.Value x : ds) if (x != null) d.add(x);
                    if (src.targetName().equals("nextBytes")) { SsaForm.Value a = arg(ssa, src, 1); if (a != null) d.add(a); }
                    String why = null;
                    for (int round = 0; why == null && round < 4; round++) {
                        int before = d.size();
                        for (Insn in : m.insns) {
                            if (why != null) break;
                            SsaForm.Value[] us = ssa.usesOf(in);
                            if (us == null) continue;
                            boolean hit = false;
                            for (SsaForm.Value u : us) if (u != null && d.contains(u)) { hit = true; break; }
                            if (!hit) continue;
                            SsaForm.Value[] dd = ssa.defsOf(in);
                            switch (in.kind) {
                                case MOVE: case CHECK_CAST: case BINOP: case UNOP:
                                    if (dd != null) for (SsaForm.Value x : dd) if (x != null) d.add(x);
                                    break;
                                case ARRAY_PUT:
                                    if (us.length >= 2 && us[us.length - 2] != null && d.contains(us[0])) d.add(us[us.length - 2]);     // the array now holds random bytes
                                    break;
                                case FIELD_PUT: {
                                    String f = in.ref.contains("->") ? in.ref.substring(in.ref.indexOf("->") + 2) : in.ref;
                                    if (!renamed && d.contains(us[0]) && SECURITY_NAME.matcher(f.substring(0, Math.max(0, f.indexOf(':')))).find())
                                        why = "is stored in the field " + f.substring(0, Math.max(0, f.indexOf(':')));
                                    break;
                                }
                                case RETURN:
                                    if ((!renamed && SECURITY_NAME.matcher(m.name).find()) || classNamed || cryptoClass)
                                        why = "is returned by " + m.name + "() of " + c.type.substring(c.type.lastIndexOf('/') + 1, c.type.length() - 1)
                                              + (cryptoClass ? " (a class that uses javax.crypto / MessageDigest)" : "");
                                    break;
                                case INVOKE: {
                                    String owner = in.targetOwner(), name = in.targetName();
                                    if (KEY_SINKS.contains(owner) && name.equals("<init>")) { why = "becomes key / IV material (" + owner.substring(owner.lastIndexOf('/') + 1, owner.length() - 1) + ")"; break; }
                                    if (name.startsWith("put") && (owner.equals("Landroid/content/ContentValues;") || owner.equals("Landroid/content/SharedPreferences$Editor;") || owner.equals(INTENT))) {
                                        String k = keyName(ssa, arg(ssa, in, 1));
                                        if (k != null && SECURITY_NAME.matcher(k).find()) { why = "is saved / sent under the name \"" + k + "\""; break; }
                                    }
                                    if (DERIVE.contains(owner) && dd != null) for (SsaForm.Value x : dd) if (x != null) d.add(x);
                                    if ((owner.equals("Ljava/lang/StringBuilder;") || owner.equals("Ljava/lang/StringBuffer;")) && us.length > 0 && us[0] != null) d.add(us[0]);
                                    if (!renamed && !DERIVE.contains(owner) && owner.equals(c.type) && SECURITY_NAME.matcher(name).find())
                                        why = "is passed to " + name + "()";
                                    break;
                                }
                                default:
                                    break;
                            }
                        }
                        if (d.size() == before) break;
                    }
                    if (why == null) continue;
                    String api = math ? "Math.random()" : "java.util.Random." + src.targetName() + "()";
                    out.add(new Hit("weak-random", "Predictable random value used for security", seeded != null ? "HIGH" : "MEDIUM", "HIGH", "CWE-338",
                            "The output of " + api + " " + why + ". java.util.Random is a linear congruential generator: after a few outputs (or from the seed) every next value can be computed, so a token / PIN / key built from it can be guessed."
                                    + (seeded != null ? " It is even created with the constant seed " + seeded + ", so it gives the same numbers on every run." : "")
                                    + " Traced in SSA inside " + m.name + "(); the receiver is a new java.util.Random (a SecureRandom held in a Random variable is not reported).",
                            m.key(), src.offset));
                    break;            // one finding per method
                } catch (Throwable ignored) {
                }
            }
        }
        return out;
    }
}
