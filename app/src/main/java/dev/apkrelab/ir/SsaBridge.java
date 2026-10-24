package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 0.56.0 (P1 step 2): the bridge between {@link TaintIr} and the scanner.
 *
 * The Kotlin scanner stays the primary engine. This class takes the flows of the SSA engine and returns, as PLAIN DATA (no Kotlin type,
 * so it can be unit-tested on a plain JVM), only the flows the old engine did not report (same sink method + title). The Kotlin side
 * turns each {@link Item} into a `taint-flow` finding. Nothing the old engine found is removed or changed.
 *
 * Confidence follows the Kotlin engine so both kinds of finding read the same:
 *   real source (level 2) with no validation-like call on the chain = HIGH, passed through unknown code (level 1) = MEDIUM,
 *   a validation-like call on the chain lowers one step, SharedPreferences sources are LOW, a flow no entry reaches lowers one more step.
 * Severity drops one level when the confidence ends up LOW (same rule as the Kotlin engine).
 */
public final class SsaBridge {

    private SsaBridge() {
    }

    /** One flow to report. All fields are final and plain. */
    public static final class Item {
        public final String classType;   // "Lcom/x/Y;" of the sink method
        public final String method;      // key of the sink method
        public final int at;             // char offset of the sink instruction inside the class text (same coordinate as Finding.at)
        public final String title, cwe, sev, confidence, fix;
        public final String detail;      // starts with "Data from <source> ..." (FindingPolish.applyReach relies on that)
        public final boolean reachable;
        public final String entry;       // first method of the entry path, "" when not reachable
        public final String path;        // short names joined with " -> ", "" when not reachable
        public final int count;          // flows of this title in this method
        /** 0.82.0 (AI triage): key of the method where the untrusted value is held first (chain head), "" when it is the sink method itself. */
        public final String sourceMethod;
        /** 0.82.0 (AI triage): the data path source -> ... -> sink as short method names, "" when there is only the sink method. */
        public final String dataPath;

        Item(String classType, String method, int at, String title, String cwe, String sev, String confidence, String fix,
             String detail, boolean reachable, String entry, String path, int count, String sourceMethod, String dataPath) {
            this.sourceMethod = sourceMethod;
            this.dataPath = dataPath;
            this.classType = classType;
            this.method = method;
            this.at = at;
            this.title = title;
            this.cwe = cwe;
            this.sev = sev;
            this.confidence = confidence;
            this.fix = fix;
            this.detail = detail;
            this.reachable = reachable;
            this.entry = entry;
            this.path = path;
            this.count = count;
        }
    }

    public static final int MAX_ITEMS = 40;

    // same idea as TaintEngine.validationRe in the Kotlin engine
    private static final Pattern VALIDATION = Pattern.compile(
            "Ljava/lang/String;->(startsWith|endsWith|matches|contains)\\(|Ljava/util/(List|Set|Collection|ArrayList|HashSet);->contains\\(|"
                    + "->(getHost|getScheme|getAuthority|getCanonicalPath|getCanonicalFile|normalize|sqlEscapeString|isDigitsOnly|isHttpsUrl|isValidUrl)\\(|"
                    // 0.83.0 (FairEmail Helper.sanitizeFilename before the File is built): a call to an app method whose NAME says it cleans or checks a value
                    + "->[A-Za-z0-9_$]*(?i:sanitiz|sanitis|normaliz|canonical|escape|validat|isSafe|isValid|checkPath|safeName)[A-Za-z0-9_$]*\\(|"
                    + "Ljava/util/regex/|const-string [vp]\\d+, \"\\.\\.\"");

    private static final Map<String, String> FIX = new HashMap<>();

    static {
        FIX.put(TaintIr.T_WEB, "Allow-list the scheme and host before loading (https and your own domains only), or map a small id to a fixed URL. Never pass an Intent extra straight to the WebView.");
        FIX.put(TaintIr.T_JS, "Do not build JavaScript from outside input. Pass data as JSON through a fixed function (JSON.stringify on a value you control) and validate it first.");
        FIX.put(TaintIr.T_SQL, "Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.");
        FIX.put(TaintIr.T_CMD, "Do not build shell commands from input. Call an API instead, or pass fixed arguments and validate each one against an allow-list.");
        FIX.put(TaintIr.T_FILE, "Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.");
        FIX.put(TaintIr.T_REDIRECT, "Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.");
        FIX.put(TaintIr.T_REFL, "Look the name up in an explicit allow-list (a map of known keys to classes) instead of passing it to Class.forName / getMethod.");
        FIX.put(TaintIr.T_CODE, "Load code only from the app's own read-only locations (assets, code cache created by the app); never from a path or name given by the caller.");
        FIX.put(TaintIr.T_URI, "Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.");
        FIX.put(TaintIr.T_SSRF, "Allow-list the host (and use https) before opening the connection; resolve a small id to a fixed URL on your side.");
    }

    /**
     * Builds the call graph, runs the SSA taint and returns the flows the old engine missed.
     *
     * @param app         every non-library class of the app, parsed
     * @param entryTypes  smali types of the exported components (the entries of the call graph)
     * @param old         the old engine's findings. Only the class part of the method key and the title are used: the scanner merges
     *                    findings with the same title inside one class into one card (scanSmali), so "the class already has this title"
     *                    is the finest question the old list can answer. {@code new TaintIr.Old("Lcom/x/Y;->", title)} is enough.
     */
    public static List<Item> newFlows(Collection<ClassIr> app, Collection<String> entryTypes, Collection<TaintIr.Old> old) {
        return newFlows(app, entryTypes, old, null);
    }

    /** 0.66.5: same, and the measurement of the taint run (losses, caps, slowest methods) is added to {@code statsOut} when it is not null. */
    public static List<Item> newFlows(Collection<ClassIr> app, Collection<String> entryTypes, Collection<TaintIr.Old> old, TaintIr.Stats statsOut) {
        return newFlows(app, entryTypes, old, statsOut, null);
    }

    /** 0.69.1: {@code guarded} = exported components protected by a signature-level permission (may be null), see CallGraph.setGuardedComponents. */
    public static List<Item> newFlows(Collection<ClassIr> app, Collection<String> entryTypes, Collection<TaintIr.Old> old, TaintIr.Stats statsOut,
                                      Collection<String> guarded) {
        CallGraph g = CallGraph.build(app, entryTypes, CallGraph.Mode.RTA, null);
        if (guarded != null && !guarded.isEmpty()) g.setGuardedComponents(guarded);
        return newFlows(g, old, statsOut);
    }

    public static List<Item> newFlows(CallGraph g, Collection<TaintIr.Old> old) {
        return newFlows(g, old, null);
    }

    public static List<Item> newFlows(CallGraph g, Collection<TaintIr.Old> old, TaintIr.Stats statsOut) {
        TaintIr.Result res = TaintIr.analyze(g, false, null);
        if (statsOut != null) statsOut.merge(res.stats);
        Set<String> oldKeys = new HashSet<>();
        if (old != null) for (TaintIr.Old o : old) oldKeys.add(TaintIr.classOf(o.method) + "|" + o.title);
        Map<String, List<TaintIr.Flow>> byKey = new LinkedHashMap<>();
        for (TaintIr.Flow f : res.flows) {
            if (oldKeys.contains(TaintIr.classOf(f.sink.method) + "|" + f.sink.title)) continue;
            byKey.computeIfAbsent(f.key(), k -> new ArrayList<>()).add(f);
        }
        // 0.79.0 (Markor: one caller-chosen file reached isFileOutOfThisFormat and isContentsPlainText from DocumentActivity.handleLaunchingIntent,
        // two cards for one cause): sink groups whose head flow has the same sink kind, source, first method of the chain and reachability are
        // ONE root cause: one card (the first group), the other sinks listed in it
        Map<String, List<List<TaintIr.Flow>>> byRoot = new LinkedHashMap<>();
        for (List<TaintIr.Flow> group : byKey.values()) {
            TaintIr.Flow h = group.get(0);
            String root = h.chain.isEmpty() ? "solo|" + h.key()
                    : h.sink.title + "|" + h.source + "|" + h.chain.get(0) + "|" + h.reachable + "|" + h.weak;
            byRoot.computeIfAbsent(root, k -> new ArrayList<>()).add(group);
        }
        List<Item> out = new ArrayList<>();
        for (List<List<TaintIr.Flow>> roots : byRoot.values()) {
            if (out.size() >= MAX_ITEMS) break;
            String also = null;
            if (roots.size() > 1) {
                StringBuilder sb = new StringBuilder(" The same input, read in ").append(TaintIr.shortKey(roots.get(0).get(0).chain.get(0)))
                        .append(", also reaches this kind of API in: ");
                for (int i = 1; i < roots.size() && i <= 6; i++) sb.append(i == 1 ? "" : ", ").append(TaintIr.shortKey(roots.get(i).get(0).sink.method));
                if (roots.size() > 7) sb.append(", ...");
                also = sb.append(" (one root cause, one card).").toString();
            }
            Item it = toItem(g, roots.get(0), also);
            if (it != null) out.add(it);
        }
        return out;
    }

    private static Item toItem(CallGraph g, List<TaintIr.Flow> group) {
        return toItem(g, group, null);
    }

    private static Item toItem(CallGraph g, List<TaintIr.Flow> group, String also) {
        // flows come sorted (severity, reachable first); the first one of the group is the one to show
        TaintIr.Flow f = group.get(0);
        if (f.weak) for (TaintIr.Flow x : group) if (!x.weak) { f = x; break; }      // 0.68.5: show a strong flow of the group when there is one
        MethodIr sinkM = g.methods.get(f.sink.method);
        if (sinkM == null || f.sink.insn < 0 || f.sink.insn >= sinkM.insns.size()) return null;
        int at = sinkM.insns.get(f.sink.insn).offset;
        boolean validation = hasValidation(g, f);

        // 0.84.0 (OpenTracks KMZ importer, FairEmail processUri): a file-name flow whose path cleans the name (a basename: substring after
        // lastIndexOf('/') with the '/' constant in the same method, or a call named sanitize* / safeName / baseName) is not a path traversal
        boolean cleaned = f.sink.title.equals(TaintIr.T_FILE) && cleansFileName(g, f);

        String conf = f.level >= 2 ? "HIGH" : "MEDIUM";
        if (validation) conf = step(conf);
        if (cleaned) conf = "LOW";
        boolean prefs = f.source.startsWith("SharedPreferences.");
        if (prefs || f.weak) conf = "LOW";
        if (!f.reachable) conf = step(conf);
        String sev = f.sink.sev;
        if (conf.equals("LOW")) sev = lowerOne(sev);
        // 0.84.0: the app's own provider that the manifest does not export: nothing but the app itself calls it, so one more level
        if (f.internal && f.source.startsWith("a ContentProvider")) sev = lowerOne(sev);

        StringBuilder sb = new StringBuilder();
        sb.append("Data from ").append(f.source);
        if (f.via != null && !TaintIr.shortRef(f.via).isEmpty()) sb.append(" (through ").append(TaintIr.shortRef(f.via)).append(")");
        sb.append(" reaches ").append(f.sink.api).append("() in method ").append(TaintIr.shortKey(f.sink.method))
                .append(". Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way.");
        if (f.chain.size() > 1) sb.append(" The value travels through ").append(f.chain.size()).append(" methods.");
        if (cleaned) sb.append(" A step on the path takes the base name of the value (substring after the last '/'), which removes directory parts: low confidence, check that it covers this value.");
        if (f.source.startsWith("Intent.") && !f.source.endsWith(TaintIr.ACTIVITY_RESULT_SUFFIX)) sb.append(" An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.");
        if (f.source.endsWith(TaintIr.ACTIVITY_RESULT_SUFFIX))
            sb.append(" The Intent is the result that an activity this app started handed back to onActivityResult (a file picker, the camera, one of its own screens), not an input that another app sends to a component of this app. It is attacker-controlled only if the app starts an implicit Intent that another app can answer, or the activity it calls is untrusted (low confidence); check which activity is started and whether the Intent is explicit.");
        else if (f.internal && !f.chain.isEmpty() && g.isGuardedComponent(TaintIr.classOf(f.chain.get(0))))
            sb.append(" The Intent is read in an exported component that is protected by a signature-level permission, so only apps signed with the same key can start it directly, and no unprotected exported component of this app was seen forwarding an Intent to it (low confidence). It stays a lead: a rooted device, a pre-installed privileged app or a forwarder the graph cannot follow can still deliver the value.");
        else if (f.internal && f.source.startsWith("a ContentProvider")) sb.append(" This ContentProvider is not exported by the manifest (no exported=true, no intent filter), so another app cannot call it directly: it is reached only by this app itself or through a URI the app grants (grantUriPermissions): low confidence, check how the app uses its provider;");
        else if (f.internal) sb.append(" The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence).");
        else if (f.weak && f.via != null && f.via.contains("prefs:"))
            sb.append(" The value went through SharedPreferences with a key that is not a literal (built at run time, e.g. from a resource id), so the engine cannot tell whether the value read is the one written: low confidence, check the keys.");
        else if (f.weak && f.via != null && f.via.startsWith(TaintIr.PARCEL_HELD_MARK)) sb.append(" The value is read from a Parcel in one method and used in another, so this is a problem only if the whole Parcelable is received from another app (an Intent extra or a Binder call); if it only travels inside this app it is not attacker input: low confidence, check where this class is unmarshalled;");
        else if (f.weak && f.via != null && f.via.startsWith(TaintIr.ERASED_MARK)) sb.append(" The path goes through " + TaintIr.ERASED_WEAK + " or more methods whose signature carries no type information (all parameters java.lang.Object: coroutine / lambda glue), where unrelated values meet: low confidence, check that this path really exists;");
        else if (f.weak && f.via != null && f.via.startsWith(TaintIr.FANOUT_MARK)) sb.append(" The value passed the RESULT of a call with many possible targets (" + TaintIr.FANOUT_WEAK + " or more implementations or overrides, e.g. a generic task / callback holder), so it may come from an unrelated one: low confidence, check that this path really exists;");
        else if (f.weak) sb.append(" The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.");
        if (f.source.startsWith("Parcel.")) sb.append(" The value is read from a Parcel inside an unmarshalling method (a Parcelable constructor, createFromParcel, readFromParcel or a Binder onTransact). The Parcel is filled by another app when the object is received through an Intent extra or an exported service: check where this class is read from an Intent or Binder call.");
        if (f.source.startsWith("ZipEntry.")) sb.append(" The value is the name of an archive entry. When the archive comes from outside the app (a download, a file another app shares) a name such as ../../x makes the extraction write outside the target folder (Zip Slip): the target path must be checked with getCanonicalPath() against the extraction folder.");
        if (prefs) sb.append(" The source is SharedPreferences, which only an attacker with root or a tampered backup can change: treat this as a lead, not as a confirmed flaw.");
        if (validation) sb.append(" The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.");
        if (!f.reachable) sb.append(" No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.");
        if (group.size() > 1) sb.append(" ").append(group.size()).append(" flows of this kind end in this method.");
        if (also != null) sb.append(also);

        String entry = "", path = "";
        if (f.reachable && !f.entryPath.isEmpty()) {
            entry = TaintIr.shortKey(f.entryPath.get(0));
            StringBuilder p = new StringBuilder();
            for (int i = 0; i < f.entryPath.size(); i++) p.append(i == 0 ? "" : " -> ").append(TaintIr.shortKey(f.entryPath.get(i)));
            path = p.toString();
        }
        String fix = FIX.containsKey(f.sink.title) ? FIX.get(f.sink.title) : "Validate the value against an allow-list before it reaches this API.";
        String srcMethod = "", dataPath = "";
        if (!f.chain.isEmpty() && !f.chain.get(0).equals(f.sink.method)) {
            srcMethod = f.chain.get(0);
            StringBuilder dp = new StringBuilder();
            for (int i = 0; i < f.chain.size() && i < 12; i++) dp.append(i == 0 ? "" : " -> ").append(TaintIr.shortKey(f.chain.get(i)));
            if (!f.chain.get(f.chain.size() - 1).equals(f.sink.method)) dp.append(" -> ").append(TaintIr.shortKey(f.sink.method));
            dataPath = dp.toString();
        }
        return new Item(sinkM.owner, f.sink.method, at, f.sink.title, f.sink.cwe, sev, conf, fix, sb.toString(), f.reachable, entry, path, group.size(), srcMethod, dataPath);
    }

    /**
     * 0.84.0: a method of the path (or the sink method) takes the base name: lastIndexOf of the separator ('/' or File.separatorChar) + substring(int), or String.replace(char, char) of the separator, in the SAME method.
     * Structural evidence only: a helper merely NAMED sanitize* is weaker (names can lie) and keeps the one-step confidence drop of hasValidation.
     */
    private static boolean cleansFileName(CallGraph g, TaintIr.Flow f) {
        Set<String> seen = new HashSet<>();
        List<String> keys = new ArrayList<>(f.chain);
        keys.add(f.sink.method);
        // the helper that returns the cleaned name is usually a CALLEE of a method of the path (OpenTracks KMZTrackImporter.importNameForFilename),
        // not a method the value is "held" in: look one call down too, in app methods that return a String
        List<String> more = new ArrayList<>();
        for (String k : keys) {
            MethodIr m = g.methods.get(k);
            if (m == null) continue;
            for (Insn in : m.insns)
                if (in.kind == Insn.Kind.INVOKE && in.targetSig().endsWith(")Ljava/lang/String;")) {
                    String ck = in.targetOwner() + "->" + in.targetSig();
                    if (g.methods.containsKey(ck)) more.add(ck);
                }
        }
        keys.addAll(more);
        for (String k : keys) {
            if (!seen.add(k)) continue;
            MethodIr m = g.methods.get(k);
            if (m == null) continue;
            boolean lastIndex = false, substring = false, slash = false, replaceChar = false;
            for (Insn in : m.insns) {
                String t = in.text;
                if (t.contains("Ljava/lang/String;->lastIndexOf(")) lastIndex = true;
                else if (t.contains("Ljava/lang/String;->substring(I)Ljava/lang/String;")) substring = true;
                else if (t.contains("Ljava/lang/String;->replace(CC)Ljava/lang/String;")) replaceChar = true;
                // the separator: the constant '/', or File.separatorChar (OpenTracks KMZTrackImporter.importNameForFilename)
                else if (t.contains(", 0x2f") && t.startsWith("const")) slash = true;
                else if (t.startsWith("sget-char") && t.contains("Ljava/io/File;->separatorChar:C")) slash = true;
            }
            // basename (substring after the last separator) or the separators replaced by another character: no directory part is left
            if (slash && ((lastIndex && substring) || replaceChar)) return true;
        }
        return false;
    }

    private static boolean hasValidation(CallGraph g, TaintIr.Flow f) {
        Set<String> seen = new HashSet<>();
        List<String> keys = new ArrayList<>(f.chain);
        keys.add(f.sink.method);
        for (String k : keys) {
            if (!seen.add(k)) continue;
            MethodIr m = g.methods.get(k);
            if (m == null) continue;
            for (Insn in : m.insns) if (VALIDATION.matcher(in.text).find()) return true;
        }
        return false;
    }

    private static String step(String conf) {
        return conf.equals("HIGH") ? "MEDIUM" : "LOW";
    }

    private static String lowerOne(String sev) {
        switch (sev) {
            case "CRITICAL": return "HIGH";
            case "HIGH": return "MEDIUM";
            case "MEDIUM": return "LOW";
            default: return sev;
        }
    }
}
