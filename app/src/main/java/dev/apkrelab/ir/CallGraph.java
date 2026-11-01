package dev.apkrelab.ir;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 0.53.0 (P0): call graph of the APP classes on top of {@link ClassIr}.
 *
 * Resolution: static / direct / super calls are exact. virtual / interface calls are resolved with CHA ({@link Mode#CHA}: every
 * concrete app subtype of the receiver type) or, by default, RTA ({@link Mode#RTA}: only subtypes that are instantiated by
 * reachable code, found with new-instance, plus the component classes the framework creates). A call site that RTA could not
 * link to anything (object made by reflection, XML inflation, a field filled elsewhere) is linked by CHA at the end; those edges
 * get a "~" after their kind so a report can tell them apart.
 *
 * Entry points: every component class passed in (Activity, Service, Receiver, Provider, Application) is instantiated by the
 * framework, and its lifecycle / callback methods ({@link #ENTRY_NAMES}) are the roots, found through the class chain.
 *
 * Implicit edges (small tables, not a model of the whole framework): Thread.start -> run, AsyncTask.execute -> doInBackground...,
 * and "callback" edges: when a method creates an app object (new-instance) and passes some object to a framework method whose
 * parameter type is a known callback type (Runnable, OnClickListener ...), the caller gets an edge to that object's callback.
 * Static initialisers are linked from the first method that creates / calls / reads the class.
 *
 * Explicit ICC (const-class + Intent/ComponentName builder in the same method) is modelled since 0.54.1. Not modelled: reflection, native code, implicit Intents, string-built ComponentNames, callbacks whose
 * object is created in another method than the registration.
 */
public final class CallGraph {

    public enum Mode {CHA, RTA}

    /** One call site -> one callee. {@code external} = the callee is not an app method (framework / library). */
    public static final class Edge {
        public final String caller;
        public final int insn;
        public final String callee;
        public final String kind;
        public final boolean external;

        Edge(String caller, int insn, String callee, String kind, boolean external) {
            this.caller = caller;
            this.insn = insn;
            this.callee = callee;
            this.kind = kind;
            this.external = external;
        }

        @Override
        public String toString() {
            return caller + " -" + kind + "@" + insn + "-> " + callee;
        }
    }

    private static final class Site {
        final String caller, owner, sig, kind;
        final int insn;
        boolean linked;

        Site(String caller, int insn, String owner, String sig, String kind) {
            this.caller = caller;
            this.insn = insn;
            this.owner = owner;
            this.sig = sig;
            this.kind = kind;
        }
    }

    /** Methods the framework calls on a component (names only: any descriptor). */
    public static final Set<String> ENTRY_NAMES = new HashSet<>(Arrays.asList(
            "<init>", "<clinit>", "attachBaseContext", "onCreate", "onStart", "onRestart", "onResume", "onPause", "onStop",
            "onDestroy", "onNewIntent", "onActivityResult", "onRequestPermissionsResult", "onSaveInstanceState",
            "onRestoreInstanceState", "onConfigurationChanged", "onCreateOptionsMenu", "onOptionsItemSelected", "onCreateView",
            "onViewCreated", "onAttach", "onLowMemory", "onTrimMemory", "onReceive", "onBind", "onUnbind", "onRebind",
            "onStartCommand", "onHandleIntent", "onHandleWork", "onStartJob", "onStopJob", "doWork",
            "query", "insert", "update", "delete", "openFile", "openAssetFile", "call", "getType", "bulkInsert"));

    private static final Map<String, List<String>> CALLBACKS = new HashMap<>();
    private static final Map<String, List<String>> TRIGGERS = new HashMap<>();

    static {
        CALLBACKS.put("Ljava/lang/Runnable;", Arrays.asList("run()V"));
        CALLBACKS.put("Ljava/util/concurrent/Callable;", Arrays.asList("call()Ljava/lang/Object;"));
        CALLBACKS.put("Landroid/view/View$OnClickListener;", Arrays.asList("onClick(Landroid/view/View;)V"));
        CALLBACKS.put("Landroid/content/DialogInterface$OnClickListener;",
                Arrays.asList("onClick(Landroid/content/DialogInterface;I)V"));
        CALLBACKS.put("Landroid/os/Handler$Callback;", Arrays.asList("handleMessage(Landroid/os/Message;)Z"));
        CALLBACKS.put("Landroid/content/BroadcastReceiver;",
                Arrays.asList("onReceive(Landroid/content/Context;Landroid/content/Intent;)V"));
        CALLBACKS.put("Landroid/content/ServiceConnection;", Arrays.asList(
                "onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V",
                "onServiceDisconnected(Landroid/content/ComponentName;)V"));
        CALLBACKS.put("Landroid/content/SharedPreferences$OnSharedPreferenceChangeListener;",
                Arrays.asList("onSharedPreferenceChanged(Landroid/content/SharedPreferences;Ljava/lang/String;)V"));
        TRIGGERS.put("Ljava/lang/Thread;->start()V", Arrays.asList("run()V"));
        TRIGGERS.put("Landroid/os/AsyncTask;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;", Arrays.asList(
                "onPreExecute()V", "doInBackground([Ljava/lang/Object;)Ljava/lang/Object;", "onPostExecute(Ljava/lang/Object;)V"));
    }

    // ---------- results ----------

    public final Mode mode;
    public final Map<String, MethodIr> methods = new LinkedHashMap<>();       // key -> method (app code only)
    /** 1.0.0: R8 class-merge facts over the whole app (set for one group of a big app, see SsaGroups); null = this graph's classes are the program. */
    MergeFacts mergeFacts;
    public final Set<String> entries = new LinkedHashSet<>();
    public final Set<String> reachable = new LinkedHashSet<>();
    public final Set<String> instantiated = new LinkedHashSet<>();
    public final Map<String, List<Edge>> out = new HashMap<>();               // caller key -> edges
    public final Map<String, List<Edge>> in = new HashMap<>();                // callee key -> edges
    public final Set<String> externalCalls = new TreeSet<>();                 // framework methods the reachable code calls
    /**
     * 0.66.7: edges out of methods that NO entry reaches, for the taint engine only. They are kept apart from {@link #out} /
     * {@link #in} on purpose: {@link #reachable}, {@link #pathTo}, {@link #stats} and every other query stay exactly as before.
     * Without them a source -> sink chain that passes through code the graph does not reach (callbacks, DI, Compose, reflection)
     * lost its taint at the first call out of that code.
     */
    public final Map<String, List<Edge>> taintOut = new HashMap<>();
    public final Map<String, List<Edge>> taintIn = new HashMap<>();
    /** Max CHA targets kept per virtual / interface call site in a method no entry reaches; sites over it are counted in {@link #taintChaCapped}. */
    public static final int TAINT_CHA_MAX = 64;
    public int taintOnlyEdges, taintChaCapped;

    // ---------- state ----------

    private final Map<String, ClassIr> classes = new HashMap<>();
    private final Set<String> componentTypes = new LinkedHashSet<>();            // 0.68.6: the exported components the graph was built with
    private Set<String> exportedClosure;                                       // 2.0.1: the exported entries and every superclass of one
    private boolean openRedirector;                                          // 0.68.6: an exported component launches an Intent it received (intent redirection): any component can be started
    private Set<String> guardedComponents = Collections.emptySet();               // 0.69.1: exported components protected by a SIGNATURE-level permission: not attacker seeds
    private Set<String> attackerReach;                                           // 0.68.6: exported components, their app superclasses, and the components they hand an Intent to
    private final Map<String, Map<String, MethodIr>> sigIndex = new HashMap<>();
    private final Map<String, List<String>> supersCache = new HashMap<>();
    private final Map<String, List<String>> subsAll = new HashMap<>();          // type -> all app classes that have it as a super
    private final Map<String, Set<String>> instBySuper = new HashMap<>();       // type -> instantiated app classes below it
    private final Map<String, List<Site>> sites = new HashMap<>();              // owner type -> virtual / interface sites
    private final List<Site> allSites = new ArrayList<>();
    // 0.101.0 (speed and memory, the result is the same): the old test kept a "caller|insn|callee" String per candidate edge (a concatenation and a hash on every call, and ~150 bytes
    // alive per edge); now each method key gets a small int and each edge is one long in a LongSet. Out-of-range ids or instruction indexes (never seen) use the old string set.
    private final Map<String, Integer> methodIds = new HashMap<>();
    private final LongSet edgeSeen = new LongSet();
    private final Set<String> edgeSeenSlow = new HashSet<>();
    private int idOf(String key) {
        Integer i = methodIds.get(key);
        if (i == null) { i = methodIds.size(); methodIds.put(key, i); }
        return i;
    }
    private boolean newEdge(String caller, int insn, String callee) {
        int a = idOf(caller), b = idOf(callee);
        if (a >= (1 << 22) || b >= (1 << 22) || insn < 0 || insn >= (1 << 20)) return edgeSeenSlow.add(caller + "|" + insn + "|" + callee);
        return edgeSeen.add(((long) a << 42) | ((long) b << 20) | insn);
    }
    private final Set<String> inited = new HashSet<>();
    private final Deque<String> work = new ArrayDeque<>();

    private CallGraph(Mode mode) {
        this.mode = mode;
    }

    /**
     * @param app          parsed app classes (library classes may be left out: their calls become external edges)
     * @param components   class types the framework instantiates (manifest components, the Application class)
     * @param extraEntries extra method keys that must count as roots (a finding's sink method, for example); may be null
     */
    public static CallGraph build(Collection<ClassIr> app, Collection<String> components, Mode mode,
                                  Collection<String> extraEntries) {
        CallGraph g = new CallGraph(mode == null ? Mode.RTA : mode);
        g.index(app);
        g.run(components == null ? Collections.<String>emptyList() : components, extraEntries);
        g.addTaintOnlyEdges();
        g.addLazyEdges();
        if (ASYNC_EDGES) g.addAsyncEdges();
        java.util.function.Consumer<CallGraph> hook = buildHook;
        if (hook != null) hook.accept(g);
        return g;
    }

    /** 0.101.1: measurement only (tools/sandbox/MeasureReuse.java sets it): called with every finished graph. Null in the app. */
    public static volatile java.util.function.Consumer<CallGraph> buildHook;

    // ---------- queries ----------

    public List<Edge> edgesFrom(String key) {
        List<Edge> l = out.get(key);
        return l == null ? Collections.<Edge>emptyList() : l;
    }

    public List<Edge> edgesTo(String key) {
        List<Edge> l = in.get(key);
        return l == null ? Collections.<Edge>emptyList() : l;
    }

    public Set<String> calleesOf(String key) {
        Set<String> s = new LinkedHashSet<>();
        for (Edge e : edgesFrom(key)) if (!e.external) s.add(e.callee);
        return s;
    }

    public Set<String> callersOf(String key) {
        Set<String> s = new LinkedHashSet<>();
        for (Edge e : edgesTo(key)) s.add(e.caller);
        return s;
    }

    /** Edges the taint engine follows out of {@code key}: the graph's own edges, or (method no entry reaches) the taint-only ones. */
    public List<Edge> taintEdgesFrom(String key) {
        List<Edge> l = out.get(key);
        if (l != null) return l;
        l = taintOut.get(key);
        return l == null ? Collections.<Edge>emptyList() : l;
    }

    /** Callers of {@code key} for the taint engine: the graph's callers plus the unreachable methods that call it. */
    public Set<String> taintCallersOf(String key) {
        Set<String> s = callersOf(key);
        List<Edge> l = taintIn.get(key);
        if (l != null) for (Edge e : l) s.add(e.caller);
        return s;
    }

    public boolean isReachable(String key) {
        return reachable.contains(key);
    }

    /** Shortest chain of app methods from some entry point to {@code key} (entry first), or an empty list. */
    public List<String> pathTo(String key) {
        if (!reachable.contains(key)) return Collections.emptyList();
        Map<String, String> parent = new HashMap<>();
        Deque<String> q = new ArrayDeque<>();
        for (String e : entries) {
            if (methods.containsKey(e) && parent.put(e, "") == null) q.add(e);
        }
        while (!q.isEmpty()) {
            String cur = q.poll();
            if (cur.equals(key)) break;
            for (Edge e : edgesFrom(cur)) {
                if (e.external || parent.containsKey(e.callee)) continue;
                parent.put(e.callee, cur);
                q.add(e.callee);
            }
        }
        if (!parent.containsKey(key)) return Collections.emptyList();
        ArrayList<String> p = new ArrayList<>();
        for (String c = key; !c.isEmpty(); c = parent.get(c)) p.add(c);
        Collections.reverse(p);
        return p;
    }

    /**
     * 2.0.1 (device reports, Axis Pay: MainActivity.onActivityResult -> im2.success -> f51.run -> 7 unrelated SDK classes; 3.0.1: ga8.a -> Closeable.close -> wx0.close -> ni2.run ...):
     * a call site on a FRAMEWORK interface method (Closeable.close, Runnable.run, Callable.call, a Flutter / Play Services callback) whose receiver the graph does not know
     * resolves to every app class that implements it, and R8 merges dozens of lambdas into one such class. A path through that hop is real syntax but proves little.
     * True when the edge's call site has {@link #HUB_FANOUT} or more app targets and its declared owner is not an app class.
     */
    public boolean isHubEdge(Edge e) {
        if (e == null || e.external) return false;
        MethodIr m = methods.get(e.caller);
        if (m == null || e.insn < 0 || e.insn >= m.insns.size()) return false;
        Insn in = m.insns.get(e.insn);
        if (in.kind != Insn.Kind.INVOKE || classes.containsKey(in.targetOwner())) return false;
        int n = 0;
        for (Edge o : edgesFrom(e.caller)) if (o.insn == e.insn && !o.external) n++;
        return n >= HUB_FANOUT;
    }

    /** 2.0.1: call sites with at least this many app targets are "hubs" (same figure as the taint engine's FANOUT_WEAK). */
    public static final int HUB_FANOUT = 8;

    /** 2.0.1: switch for the mutation check of the hub-avoiding evidence path. */
    public static boolean HUB_AWARE = !Boolean.getBoolean("apkrelab.noHubAware");

    /** Shortest entry path that uses no hub edge, or an empty list when every path to {@code key} goes through one. */
    public List<String> pathToAvoidingHubs(String key) {
        if (!reachable.contains(key)) return Collections.emptyList();
        Map<String, String> parent = new HashMap<>();
        Deque<String> q = new ArrayDeque<>();
        for (String e : entries) if (methods.containsKey(e) && parent.put(e, "") == null) q.add(e);
        while (!q.isEmpty()) {
            String cur = q.poll();
            if (cur.equals(key)) break;
            for (Edge e : edgesFrom(cur)) {
                if (e.external || parent.containsKey(e.callee) || isHubEdge(e)) continue;
                parent.put(e.callee, cur);
                q.add(e.callee);
            }
        }
        if (!parent.containsKey(key)) return Collections.emptyList();
        ArrayList<String> p = new ArrayList<>();
        for (String c = key; !c.isEmpty(); c = parent.get(c)) p.add(c);
        Collections.reverse(p);
        return p;
    }

    public String stats() {
        int edges = 0, ext = 0, approx = 0;
        for (List<Edge> l : out.values()) {
            for (Edge e : l) {
                edges++;
                if (e.external) ext++;
                if (e.kind.endsWith("~")) approx++;
            }
        }
        return mode + ": " + methods.size() + " methods, " + reachable.size() + " reachable, " + entries.size() + " entries, "
                + instantiated.size() + " instantiated types, " + edges + " edges (" + ext + " external, " + approx + " CHA-fallback)"
                + (taintOnlyEdges > 0 ? ", " + taintOnlyEdges + " taint-only edges from unreachable methods" + (taintChaCapped > 0 ? " (" + taintChaCapped + " CHA sites capped at " + TAINT_CHA_MAX + ")" : "") : "");
    }

    /** Graphviz DOT of the given methods and the app edges between them. */
    public String toDot(Collection<String> keys) {
        Set<String> set = new LinkedHashSet<>(keys);
        StringBuilder sb = new StringBuilder("digraph callgraph {\n  node [shape=box,fontname=monospace];\n");
        for (String k : set) {
            sb.append("  \"").append(esc(k)).append('"').append(entries.contains(k) ? " [style=filled,fillcolor=lightyellow]" : "")
                    .append(";\n");
        }
        for (String k : set) {
            for (Edge e : edgesFrom(k)) {
                if (e.external || !set.contains(e.callee)) continue;
                sb.append("  \"").append(esc(k)).append("\" -> \"").append(esc(e.callee)).append("\" [label=\"").append(e.kind)
                        .append("\"];\n");
            }
        }
        return sb.append("}\n").toString();
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ---------- build ----------

    private void index(Collection<ClassIr> app) {
        for (ClassIr c : app) {
            if (c.type.isEmpty() || classes.containsKey(c.type)) continue;
            classes.put(c.type, c);
            Map<String, MethodIr> mm = new HashMap<>();
            for (MethodIr m : c.methods) {
                mm.put(m.sig(), m);
                methods.put(m.key(), m);
            }
            sigIndex.put(c.type, mm);
        }
        for (ClassIr c : classes.values()) {
            for (String s : supers(c.type)) subsAll.computeIfAbsent(s, k -> new ArrayList<>()).add(c.type);
        }
    }

    private void run(Collection<String> components, Collection<String> extraEntries) {
        componentTypes.addAll(components);
        if (mode == Mode.CHA) {
            for (ClassIr c : classes.values()) if (!c.isAbstract()) instantiate(c.type);
        }
        for (String comp : components) {
            ClassIr c = classes.get(comp);
            if (c == null) continue;
            instantiate(comp);
            entries.addAll(lifecycleKeys(comp, ENTRY_NAMES));
            entries.addAll(clickHandlerKeys(comp));
        }
        if (extraEntries != null) for (String k : extraEntries) if (methods.containsKey(k)) entries.add(k);
        for (String e : entries) reach(e);
        boolean again;
        do {
            drain();
            again = fallback();
        } while (again);
    }


    /** Lifecycle methods (names in {@code names}) that the app defines for {@code comp} or its app superclasses, as dispatched keys. */
    private Set<String> lifecycleKeys(String comp, Set<String> names) {
        Set<String> sigs = new LinkedHashSet<>(), keys = new LinkedHashSet<>();
        for (String t : supers(comp)) {
            ClassIr sc = classes.get(t);
            if (sc == null) continue;
            for (MethodIr m : sc.methods) if (names.contains(m.name)) sigs.add(m.sig());
        }
        for (String sig : sigs) {
            String k = dispatch(comp, sig);
            if (methods.containsKey(k)) keys.add(k);
        }
        return keys;
    }

    /**
     * 0.68.6: the class (or the class it is nested in) is an ACTIVITY or SERVICE that the manifest does NOT export and that no exported
     * component hands an Intent to. An Intent read there was built by the app itself, not by an outside app. The engine counts every
     * Intent getter as an attacker source because an exported component can forward its Intent (intent redirection: OVAA, InsecureShop),
     * so the rule keeps such targets strong: an explicit launch (const-class + Intent builder, the "icc" edges) from a class that is
     * exported or already reached that way AND reads Intent data itself, repeated until nothing new is added. False when no component list
     * was given, when the base class is not a readable framework / androidx class (R8 renamed it), for plain helper classes (they get
     * their Intent from a caller) and for receivers / providers (a dynamic receiver is exported by default: InjuredAndroid).
     */
    /**
     * 0.69.1: exported components whose android:permission is signature-level (only apps signed with the same key can start them).
     * They stay entries of the graph (reach labels, entry paths) but are no longer seeds of the attacker-reach set, so an Intent read
     * in one of them is "internal" (LOW) UNLESS an unguarded exported component forwards an Intent to it: that forwarder runs with the
     * app's own identity and walks straight through the permission check (confused deputy), which the existing forwarding closure and
     * the open-redirector rule already model. Call before the first analysis; resets the cached reach.
     */
    public synchronized void setGuardedComponents(Collection<String> types) {
        guardedComponents = types == null ? Collections.<String>emptySet() : new HashSet<>(types);
        attackerReach = null;
        openRedirector = false;
    }

    /** 0.69.1: the class (or the class it is nested in) is an exported component that setGuardedComponents() marked as signature-guarded. */
    public synchronized boolean isGuardedComponent(String type) {
        if (guardedComponents.isEmpty() || type == null) return false;
        return guardedComponents.contains(type) || guardedComponents.contains(outerOf(type));
    }

    /**
     * 0.84.0 (Orbot / OpenTracks providers with exported=false): the class (or the class it is nested in) is one of the exported components the graph
     * was built with. false for every class when no component list was given (unit tests, apps without a manifest): then nothing is judged internal.
     */
    public synchronized boolean isExportedEntry(String type) {
        if (componentTypes.isEmpty() || type == null) return false;
        return componentTypes.contains(type) || componentTypes.contains(outerOf(type));
    }

    public synchronized boolean hasComponentList() {
        return !componentTypes.isEmpty();
    }

    public synchronized boolean isInternalComponent(String type) {
        if (componentTypes.isEmpty() || type == null || type.isEmpty()) return false;
        if (attackerReach == null) attackerReach = computeAttackerReach();
        if (openRedirector) return false;
        String t = type;
        for (int i = 0; i < 2; i++) {
            if (classes.containsKey(t) && !attackerReach.contains(t) && isComponentBase(frameworkBase(t))) return true;
            int d = t.indexOf('$');
            if (d < 0) break;
            t = t.substring(0, d) + ";";
        }
        return false;
    }

    /**
     * 2.0.1 (WE Wallet SignUpWebViewActivity, device report): a component the manifest DOES NOT export (the graph was built with a component list, the class is
     * not one of its entries) that is an Activity / Service. {@link #isInternalComponent} also asks "no exported class that reads an Intent getter launches it,
     * directly or through a chain": a class-level guess that makes almost every screen of a wallet look attacker-reached. The taint engine uses this method
     * instead: such a component's Intent is the app's own unless an exported component's tainted value was proven to flow into the Intent that launches it
     * (TaintIr ICC_EXTRAS) or an open redirector exists (false then, as for isInternalComponent).
     */
    public synchronized boolean isPrivateComponent(String type) {
        if (componentTypes.isEmpty() || type == null || type.isEmpty()) return false;
        if (attackerReach == null) attackerReach = computeAttackerReach();
        if (openRedirector) return false;
        if (exportedClosure == null) {
            Set<String> cl = new HashSet<>();
            for (String c : componentTypes) cl.addAll(supers(c));
            exportedClosure = cl;
        }
        String t = type;
        for (int i = 0; i < 2; i++) {
            // an abstract base of an exported component runs as part of it: not private
            if (classes.containsKey(t) && !isExportedEntry(t) && !exportedClosure.contains(t) && isComponentBase(frameworkBase(t))) return true;
            int d = t.indexOf('$');
            if (d < 0) break;
            t = t.substring(0, d) + ";";
        }
        return false;
    }

    private static boolean isComponentBase(String b) {
        if (!(b.startsWith("Landroid/") || b.startsWith("Landroidx/") || b.startsWith("Lcom/google/android/"))) return false;
        return b.endsWith("Activity;") || b.endsWith("Service;");
    }

    private static String outerOf(String type) {
        int d = type.indexOf('$');
        return d < 0 ? type : type.substring(0, d) + ";";
    }

    private Set<String> computeAttackerReach() {
        Set<String> reach = new HashSet<>();
        for (String c : componentTypes) if (!guardedComponents.contains(c)) reach.addAll(supers(c));      // 0.69.1: guarded entries are not seeds
        Set<String> readers = new HashSet<>();                       // outer classes that call an Intent getter
        for (MethodIr m : methods.values()) {
            String owner = TaintIr.classOf(m.key());
            for (Insn in : m.insns) {
                if (in.kind == Insn.Kind.INVOKE && in.targetOwner().equals("Landroid/content/Intent;") && TaintIr.INTENT_SOURCES.contains(in.targetName())) {
                    readers.add(outerOf(owner));
                    break;
                }
            }
        }
        List<String[]> launches = new ArrayList<>();                 // {launcher outer class, target outer class}
        for (List<Edge> es : out.values())
            for (Edge e : es)
                if ("icc".equals(e.kind)) launches.add(new String[]{outerOf(TaintIr.classOf(e.caller)), outerOf(TaintIr.classOf(e.callee))});
        boolean grew = true;
        for (int guard = 0; grew && guard < 64; guard++) {
            grew = false;
            for (String[] l : launches)
                if (reach.contains(l[0]) && readers.contains(l[0]) && !reach.contains(l[1])) {
                    reach.addAll(supers(l[1]));
                    grew = true;
                }
        }
        for (MethodIr m : methods.values()) {
            if (!reach.contains(outerOf(TaintIr.classOf(m.key())))) continue;
            boolean takesIntent = false, launchesIntent = false;
            for (Insn in : m.insns) {
                if (in.kind != Insn.Kind.INVOKE) continue;
                String o = in.targetOwner(), n = in.targetName();
                if ((o.equals("Landroid/content/Intent;") || o.equals("Landroid/os/Bundle;")) && (n.equals("getParcelableExtra") || n.equals("getParcelable"))) takesIntent = true;
                if (n.startsWith("startActivit") || n.equals("startService") || n.equals("startForegroundService") || n.equals("sendBroadcast") || n.equals("bindService")) launchesIntent = true;
            }
            if (takesIntent && launchesIntent) openRedirector = true;
        }
        return reach;
    }

    /** The framework class at the end of the app's superclass chain ("" when the chain is broken or cyclic). */
    private String frameworkBase(String type) {
        String t = type;
        for (int guard = 0; t != null && !t.isEmpty() && guard < 256; guard++) {
            ClassIr c = classes.get(t);
            if (c == null) return t;
            t = c.superType;
        }
        return "";
    }

    /** "A -> B -> Landroidx/appcompat/app/AppCompatActivity;": the superclass chain through the app classes up to the first framework class. */
    public String superChain(String type) {
        StringBuilder sb = new StringBuilder();
        String t = type;
        for (int guard = 0; t != null && !t.isEmpty() && guard < 32; guard++) {
            if (sb.length() > 0) sb.append(" -> ");
            sb.append(t);
            ClassIr c = classes.get(t);
            if (c == null) return sb.toString();
            t = c.superType;
        }
        return sb.toString();
    }

    /**
     * Not an activity for sure: the chain ends in a Service / Receiver / Provider / Application / Fragment base. Anything else
     * (including a chain we cannot read) counts as an activity, because android:onClick handlers are only a few extra entries
     * while a missed one loses real paths (0.54.2 asked "ends in ...Activity" and still lost InjuredAndroid's handler).
     */
    private boolean isActivityLike(String type) {
        String b = frameworkBase(type);
        return !(b.endsWith("Service;") || b.endsWith("Receiver;") || b.endsWith("Provider;") || b.endsWith("Application;")
                || b.endsWith("Fragment;") || b.endsWith("Worker;"));
    }

    /**
     * android:onClick handlers from layout XML: public instance methods {@code name(Landroid/view/View;)V} of an activity (the
     * framework finds them by reflection, so no invoke edge exists). Over-approximates a little: any such public method counts.
     */
    private Set<String> clickHandlerKeys(String comp) {
        Set<String> keys = new LinkedHashSet<>();
        if (!isActivityLike(comp)) return keys;
        for (String t : supers(comp)) {
            ClassIr sc = classes.get(t);
            if (sc == null) continue;
            for (MethodIr m : sc.methods) {
                String sig = m.sig();
                if (!sig.endsWith("(Landroid/view/View;)V") || m.name.startsWith("<") || m.name.startsWith("lambda$")
                        || m.name.startsWith("access$") || m.isAbstract() || !m.hasFlag("public") || m.isStatic) continue;
                String k = dispatch(comp, sig);
                if (methods.containsKey(k)) keys.add(k);
            }
        }
        return keys;
    }

    /** Methods the framework runs when a component is started by an Intent (startActivity / startService / sendBroadcast). */
    static final Set<String> LAUNCH_NAMES = new HashSet<>(Arrays.asList(
            "<init>", "attachBaseContext", "onCreate", "onStart", "onResume", "onNewIntent", "onStartCommand", "onBind",
            "onHandleIntent", "onHandleWork", "onReceive"));

    /** Intent / ComponentName builders that take an explicit target class: {@code new Intent(ctx, X.class)}, setClass, ComponentName. */
    /** 2.0.0: switch for the mutation check of class-name string targets (Intent.setClassName, ComponentName(..., String)). */
    public static boolean ICC_BY_NAME = !Boolean.getBoolean("apkrelab.noIccByName");

    /** 2.0.0: a builder that names its target class by a String: Intent.setClassName(Context | String, String), ComponentName(Context | String, String). */
    static boolean isNamedTargetCall(Insn in) {
        String o = in.targetOwner(), n = in.targetName(), sig = in.targetSig();
        if (!sig.endsWith("Ljava/lang/String;)Landroid/content/Intent;") && !sig.endsWith("Ljava/lang/String;)V")) return false;
        if (o.equals("Landroid/content/Intent;")) return n.equals("setClassName");
        return o.equals("Landroid/content/ComponentName;") && n.equals("<init>") && !sig.startsWith("<init>(Landroid/os/Parcel;");
    }

    private static boolean isExplicitTargetCall(Insn in) {
        String o = in.targetOwner(), n = in.targetName(), sig = in.targetSig();
        if (ICC_BY_NAME && isNamedTargetCall(in)) return true;
        if (!sig.contains("Ljava/lang/Class;")) return false;
        if (o.equals("Landroid/content/Intent;")) return n.equals("<init>") || n.equals("setClass");
        return o.equals("Landroid/content/ComponentName;") && n.equals("<init>");
    }

    /**
     * Explicit ICC: a method that loads the class constant of an app component and passes it to an Intent / ComponentName builder
     * launches that component, so the builder call gets an "icc" edge to the target's launch methods. Same-method pairing only
     * (the Kotlin graph does the same); targets built in another method or from strings are not modelled.
     */
    private void iccEdges(MethodIr m) {
        List<Insn> builders = null;
        Set<String> targets = null;
        for (Insn in : m.insns) {
            if (in.kind == Insn.Kind.CONST && in.op.equals("const-class") && classes.containsKey(in.ref)) {
                if (targets == null) targets = new LinkedHashSet<>();
                targets.add(in.ref);
            } else if (ICC_BY_NAME && in.kind == Insn.Kind.CONST && in.op.startsWith("const-string") && classes.containsKey(classTypeOfName(in.ref))) {
                if (targets == null) targets = new LinkedHashSet<>();
                targets.add(classTypeOfName(in.ref));                        // 2.0.0: "com.x.B" names an app class
            } else if (in.kind == Insn.Kind.INVOKE && isExplicitTargetCall(in)) {
                if (builders == null) builders = new ArrayList<>();
                builders.add(in);
            }
        }
        if (builders == null || targets == null) return;
        String caller = m.key();
        for (String t : targets) {
            Set<String> keys = lifecycleKeys(t, LAUNCH_NAMES);
            keys.addAll(clickHandlerKeys(t));
            if (keys.isEmpty()) continue;
            instantiate(t);
            for (Insn b : builders) for (String k : keys) addEdge(caller, b.index, k, "icc");
        }
    }

    /** 2.0.0: "\"com.x.B\"" (a const-string literal, quotes kept) -> "Lcom/x/B;"; "" when it is not a dotted class name. */
    static String classTypeOfName(String lit) {
        String v = lit.length() >= 2 && lit.startsWith("\"") && lit.endsWith("\"") ? lit.substring(1, lit.length() - 1) : lit;
        if (v.isEmpty() || !v.contains(".") || v.contains("/") || v.contains(" ")) return "";
        return "L" + v.replace('.', '/') + ";";
    }

    private void drain() {
        while (!work.isEmpty()) {
            MethodIr m = methods.get(work.poll());
            if (m != null) visit(m);
        }
    }

    private void reach(String key) {
        if (methods.containsKey(key) && reachable.add(key)) work.add(key);
    }

    private void visit(MethodIr m) {
        Set<String> localNew = new LinkedHashSet<>();
        for (Insn in : m.insns) if (in.kind == Insn.Kind.NEW_INSTANCE && classes.containsKey(in.ref)) localNew.add(in.ref);
        String caller = m.key();
        iccEdges(m);
        for (Insn in : m.insns) {
            switch (in.kind) {
                case NEW_INSTANCE:
                    instantiate(in.ref);
                    classInit(caller, in.index, in.ref);
                    break;
                case FIELD_GET:
                case FIELD_PUT:
                    if (in.op.startsWith("sget") || in.op.startsWith("sput")) {
                        int i = in.ref.indexOf("->");
                        if (i > 0) classInit(caller, in.index, in.ref.substring(0, i));
                    }
                    break;
                case INVOKE:
                    invoke(m, in, localNew);
                    break;
                default:
                    break;
            }
        }
    }

    private void invoke(MethodIr m, Insn in, Set<String> localNew) {
        String owner = in.targetOwner(), sig = in.targetSig(), kind = in.invokeKind();
        if (owner.isEmpty() || owner.charAt(0) == '[') return;
        String caller = m.key();
        if (ASYNC_EDGES) {                                                     // 2.0.0: the dispatched Runnable runs: its run() is reached through this site
            String at = asyncTarget(m, in);
            if (at != null && newEdge(caller, in.index, at)) {
                Edge e = new Edge(caller, in.index, at, "async", false);
                out.computeIfAbsent(caller, k -> new ArrayList<>()).add(e);
                in_(at).add(e);
                reach(at);
                asyncEdges++;
            }
        }
        switch (kind) {
            case "static":
                classInit(caller, in.index, owner);
                addEdge(caller, in.index, exact(owner, sig), kind);
                break;
            case "direct":
                addEdge(caller, in.index, exact(owner, sig), kind);
                break;
            case "super":
                addEdge(caller, in.index, dispatch(owner, sig), kind);
                break;
            case "virtual":
            case "interface": {
                Site s = new Site(caller, in.index, owner, sig, kind);
                allSites.add(s);
                sites.computeIfAbsent(owner, k -> new ArrayList<>()).add(s);
                if (!classes.containsKey(owner)) addEdge(caller, in.index, owner + "->" + sig, kind);
                Set<String> inst = instBySuper.get(owner);
                if (inst != null) for (String c : new ArrayList<>(inst)) link(s, c, kind);
                break;
            }
            default:
                return;
        }
        if (classes.containsKey(owner) || localNew.isEmpty()) return;
        for (String p : paramTypes(sig)) {
            List<String> cb = CALLBACKS.get(p);
            if (cb == null) continue;
            for (String c : localNew) {
                if (!supers(c).contains(p)) continue;
                for (String cs : cb) {
                    String t = dispatch(c, cs);
                    if (methods.containsKey(t)) addEdge(caller, in.index, t, "callback");
                }
            }
        }
    }

    private void instantiate(String type) {
        if (!classes.containsKey(type) || !instantiated.add(type)) return;
        for (String s : supers(type)) {
            instBySuper.computeIfAbsent(s, k -> new LinkedHashSet<>()).add(type);
            List<Site> l = sites.get(s);
            if (l != null) for (Site site : new ArrayList<>(l)) link(site, type, site.kind);
        }
    }

    private void link(Site s, String recvType, String kind) {
        s.linked = true;
        String callee = dispatch(recvType, s.sig);
        addEdge(s.caller, s.insn, callee, kind);
        if (!methods.containsKey(callee)) {
            List<String> ts = TRIGGERS.get(callee);
            if (ts == null) return;
            for (String t : ts) {
                String k = dispatch(recvType, t);
                if (methods.containsKey(k)) addEdge(s.caller, s.insn, k, "trigger");
            }
        }
    }

    /** CHA for the call sites RTA left without a target. Returns true when it linked something. */
    private boolean fallback() {
        boolean any = false;
        for (Site s : new ArrayList<>(allSites)) {
            if (s.linked || !reachable.contains(s.caller)) continue;
            List<String> subs = subsAll.get(s.owner);
            if (subs == null) continue;
            s.linked = true;
            for (String c : subs) {
                ClassIr cc = classes.get(c);
                if (cc == null || cc.isAbstract()) continue;
                any = true;
                String callee = dispatch(c, s.sig);
                addEdge(s.caller, s.insn, callee, s.kind + "~");
            }
        }
        return any && !work.isEmpty();
    }

    private void classInit(String caller, int insn, String type) {
        for (String t = type; t != null && classes.containsKey(t); t = classes.get(t).superType) {
            if (!inited.add(t)) continue;
            MethodIr ci = sigIndex.get(t).get("<clinit>()V");
            if (ci != null) addEdge(caller, insn, ci.key(), "clinit");
        }
    }

    private void addEdge(String caller, int insn, String callee, String kind) {
        if (!newEdge(caller, insn, callee)) return;
        boolean app = methods.containsKey(callee);
        Edge e = new Edge(caller, insn, callee, kind, !app);
        out.computeIfAbsent(caller, k -> new ArrayList<>()).add(e);
        in.computeIfAbsent(callee, k -> new ArrayList<>()).add(e);
        if (app) reach(callee);
        else externalCalls.add(callee);
    }

    // ---------- taint-only edges (0.66.7) ----------

    /**
     * For every app method with a body that no entry reaches: static / direct / super calls get their exact target, virtual and
     * interface calls get every concrete app class below the owner (CHA, at most {@link #TAINT_CHA_MAX} per site). Nothing here
     * calls {@link #reach}, adds to {@link #out} / {@link #in}, or touches {@link #externalCalls}: reachability does not change.
     */
    private void addTaintOnlyEdges() {
        Set<String> seen = new HashSet<>();
        for (MethodIr m : methods.values()) {
            String caller = m.key();
            if (reachable.contains(caller) || m.insns.isEmpty() || m.isAbstract() || m.isNative()) continue;
            for (Insn in : m.insns) {
                if (in.kind != Insn.Kind.INVOKE) continue;
                String owner = in.targetOwner(), sig = in.targetSig(), kind = in.invokeKind();
                if (owner.isEmpty() || owner.charAt(0) == '[') continue;
                seen.clear();                // 1.0.0: one caller, one call site at a time: the callees of this site are the only duplicates (was a "caller|insn|callee" string per edge)
                switch (kind) {
                    case "static":
                    case "direct":
                        taintEdge(seen, caller, in.index, exact(owner, sig), kind);
                        break;
                    case "super":
                        taintEdge(seen, caller, in.index, dispatch(owner, sig), kind);
                        break;
                    case "virtual":
                    case "interface": {
                        if (!classes.containsKey(owner)) {
                            taintEdge(seen, caller, in.index, owner + "->" + sig, kind);
                            break;
                        }
                        Set<String> targets = new LinkedHashSet<>();
                        List<String> subs = subsAll.get(owner);
                        if (subs != null) {
                            for (String c : subs) {
                                ClassIr cc = classes.get(c);
                                if (cc == null || cc.isAbstract()) continue;
                                targets.add(dispatch(c, sig));
                            }
                        }
                        if (targets.isEmpty()) targets.add(dispatch(owner, sig));
                        int n = 0;
                        for (String t : targets) {
                            if (n++ >= TAINT_CHA_MAX) {
                                taintChaCapped++;
                                break;
                            }
                            taintEdge(seen, caller, in.index, t, kind);
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }
    }

    // ---------- 0.76.0: Kotlin `by lazy { ... }` ----------

    /** Number of `lazy { }` call sites linked to their lambda's invoke() (measurement). */
    public int lazyEdges;

    /**
     * Kotlin `val x by lazy { intent.getStringExtra("K") }` compiles to `LazyKt.lazy(new Lambda())` and a later `Lazy.getValue()`.
     * The lambda's invoke() runs inside the library, so no call edge led to it and its result never reached the getter
     * (Password Store: BasePGPActivity FILE_PATH from an exported activity's Intent was lost). This links the `lazy(...)` call site to
     * `<lambda type>->invoke()Ljava/lang/Object;` so the taint engine gives the site the lambda's return taint (TaintIr treats kotlin/Lazy as a
     * container: getValue() returns it). The lambda type is the `new-instance` or the `sget-object T->INSTANCE` that defines the LAST argument
     * register within 12 instructions back. Reachability is not changed.
     */
    private void addLazyEdges() {
        for (MethodIr m : methods.values()) {
            if (m.insns.isEmpty()) continue;
            String caller = m.key();
            for (Insn in : m.insns) {
                // by SHAPE, not by name: R8 moves kotlin.LazyKt.lazy / unsafeLazy into other kotlin classes
                // (Password Store: `Lkotlin/ExceptionsKt;->unsafeLazy(Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;`)
                if (in.kind != Insn.Kind.INVOKE || !in.invokeKind().equals("static")
                        || !in.targetSig().endsWith("Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;")) continue;
                if (in.uses.length == 0) continue;
                int fnReg = in.uses[in.uses.length - 1];
                String type = null;
                for (int i = in.index - 1, n = 0; i >= 0 && n < 12; i--, n++) {
                    Insn d = m.insns.get(i);
                    boolean defines = false;
                    for (int r : d.defs) if (r == fnReg) { defines = true; break; }
                    if (!defines) continue;
                    if (d.kind == Insn.Kind.NEW_INSTANCE) type = d.ref;
                    else if (d.kind == Insn.Kind.FIELD_GET && d.ref.contains("->INSTANCE:")) type = d.ref.substring(0, d.ref.indexOf("->"));
                    break;
                }
                if (type == null) continue;
                String callee = type + "->invoke()Ljava/lang/Object;";
                if (!methods.containsKey(callee)) continue;
                Edge e = new Edge(caller, in.index, callee, "virtual", false);
                if (reachable.contains(caller)) {
                    if (!newEdge(caller, in.index, callee)) continue;
                    out.computeIfAbsent(caller, k -> new ArrayList<>()).add(e);
                    in_(callee).add(e);
                } else {
                    taintOut.computeIfAbsent(caller, k -> new ArrayList<>()).add(e);
                    taintIn.computeIfAbsent(callee, k -> new ArrayList<>()).add(e);
                }
                lazyEdges++;
            }
        }
    }

    /** 2.0.0: switch for the mutation check of the async dispatch edges. */
    public static boolean ASYNC_EDGES = !Boolean.getBoolean("apkrelab.noAsyncEdges");
    public int asyncEdges;
    /** Framework dispatch methods that run their Runnable / Callable argument later (name + descriptor; the owner is any framework or inherited type). */
    static final Map<String, String> ASYNC_SIGS = new HashMap<>();
    static {
        ASYNC_SIGS.put("execute(Ljava/lang/Runnable;)V", "run()V");
        ASYNC_SIGS.put("submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;", "run()V");
        ASYNC_SIGS.put("submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;", "call()Ljava/lang/Object;");
        ASYNC_SIGS.put("post(Ljava/lang/Runnable;)Z", "run()V");
        ASYNC_SIGS.put("postDelayed(Ljava/lang/Runnable;J)Z", "run()V");
        ASYNC_SIGS.put("postAtFrontOfQueue(Ljava/lang/Runnable;)Z", "run()V");
        ASYNC_SIGS.put("runOnUiThread(Ljava/lang/Runnable;)V", "run()V");
    }

    /**
     * 2.0.0 (Axis Pay: java.util.concurrent.Executor was among the top owners of real taint drops): a call to a framework dispatch method of {@link #ASYNC_SIGS}
     * gets an "async" edge to run() / call() of each CANDIDATE class of its Runnable argument: the type of the new-instance, check-cast or field read that
     * last defines that register within 12 instructions. The candidate is only a candidate: the taint engine follows the edge only when the SSA value
     * resolves to that one concrete class (TaintIr.concreteClassOf). Reachability is not changed.
     */
    private void addAsyncEdges() {
        for (MethodIr m : methods.values()) {
            if (m.insns.isEmpty() || reachable.contains(m.key())) continue;      // reached callers got theirs in invoke() (and made the target reachable)
            String caller = m.key();
            for (Insn in : m.insns) {
                String callee = asyncTarget(m, in);
                if (callee == null) continue;
                Edge e = new Edge(caller, in.index, callee, "async", false);
                taintOut.computeIfAbsent(caller, k -> new ArrayList<>()).add(e);
                taintIn.computeIfAbsent(callee, k -> new ArrayList<>()).add(e);
                asyncEdges++;
            }
        }
    }

    /** 2.0.0: run() / call() of the candidate class of a dispatch call's Runnable argument (see addAsyncEdges), or null. */
    private String asyncTarget(MethodIr m, Insn in) {
        if (in.kind != Insn.Kind.INVOKE || in.uses.length < 2) return null;
        String sig = in.targetSig(), target = ASYNC_SIGS.get(sig);
        if (target == null || methods.containsKey(dispatch(in.targetOwner(), sig))) return null;   // an app override is an ordinary call
        int argReg = in.uses[1];
        String type = null;
        for (int i = in.index - 1, n = 0; i >= 0 && n < 12; i--, n++) {
            Insn d = m.insns.get(i);
            boolean defines = false;
            for (int r : d.defs) if (r == argReg) { defines = true; break; }
            if (!defines) continue;
            if (d.kind == Insn.Kind.MOVE && d.uses.length > 0) { argReg = d.uses[0]; continue; }      // follow a move to its source register
            if (d.kind == Insn.Kind.NEW_INSTANCE || d.kind == Insn.Kind.CHECK_CAST) type = d.ref;
            else if (d.kind == Insn.Kind.FIELD_GET && d.ref.contains(":")) type = d.ref.substring(d.ref.lastIndexOf(':') + 1);
            break;
        }
        if (type == null || !classes.containsKey(type)) return null;
        String callee = dispatch(type, target);
        return methods.containsKey(callee) ? callee : null;
    }

    /** 2.0.0: the method key a call with [sig] reaches on a receiver of exactly [type] (TaintIr's devirtualisation of async / lambda calls). */
    String dispatchOf(String type, String sig) {
        return dispatch(type, sig);
    }

    /** 2.0.0: an app class that is neither an interface nor abstract and that no other app class extends or implements. */
    boolean isConcreteLeaf(String type) {
        ClassIr c = classes.get(type);
        if (c == null || c.isInterface() || c.isAbstract()) return false;
        List<String> subs = subsAll.get(type);
        return subs == null || subs.size() <= 1 && (subs.isEmpty() || subs.get(0).equals(type));
    }

    private List<Edge> in_(String callee) {
        return in.computeIfAbsent(callee, k -> new ArrayList<>());
    }

    private void taintEdge(Set<String> seen, String caller, int insn, String callee, String kind) {
        if (!seen.add(callee)) return;
        Edge e = new Edge(caller, insn, callee, kind, !methods.containsKey(callee));
        taintOut.computeIfAbsent(caller, k -> new ArrayList<>()).add(e);
        if (!e.external) taintIn.computeIfAbsent(callee, k -> new ArrayList<>()).add(e);
        taintOnlyEdges++;
    }

    // ---------- hierarchy ----------

    /** 1.0.0: the parsed class of an app type of this graph, or null. */
    ClassIr classIr(String type) {
        return classes.get(type);
    }

    /** 1.0.0: every app class of this graph. */
    Collection<ClassIr> classList() {
        return classes.values();
    }

    /** The type, its superclasses and all interfaces, as far as the app classes tell (framework supertypes are not expanded). */
    List<String> supers(String type) {
        List<String> r = supersCache.get(type);
        if (r != null) return r;
        LinkedHashSet<String> s = new LinkedHashSet<>();
        Deque<String> q = new ArrayDeque<>();
        q.add(type);
        while (!q.isEmpty()) {
            String x = q.poll();
            if (x == null || x.isEmpty() || !s.add(x)) continue;
            ClassIr c = classes.get(x);
            if (c == null) continue;
            q.add(c.superType);
            q.addAll(c.interfaces);
        }
        r = new ArrayList<>(s);
        supersCache.put(type, r);
        return r;
    }

    /** Declared in {@code owner} itself when it is an app class (constructors, private, static), else the key as an external one. */
    private String exact(String owner, String sig) {
        if (sig.startsWith("<init>")) return owner + "->" + sig;
        return dispatch(owner, sig);
    }

    // 0.101.0 (speed, the result is the same): the class tables are filled once in the constructor, so what a (type, signature) pair dispatches to never changes during a build;
    // a big app asked the same question again and again (dispatch was 18% of the CPU), and the returned string is now one instance with a cached hash.
    private final Map<String, Map<String, String>> dispatchMemo = new HashMap<>();

    /** Method key that a call with this signature reaches when the receiver's class is exactly {@code type}. */
    private String dispatch(String type, String sig) {
        Map<String, String> m = dispatchMemo.computeIfAbsent(type, k -> new HashMap<>());
        String r = m.get(sig);
        if (r == null) { r = dispatchUncached(type, sig); m.put(sig, r); }
        return r;
    }

    private String dispatchUncached(String type, String sig) {
        String t = type, ext = null;
        for (int guard = 0; t != null && !t.isEmpty() && guard < 256; guard++) {
            Map<String, MethodIr> mm = sigIndex.get(t);
            if (mm == null) {
                ext = t;
                break;
            }
            MethodIr m = mm.get(sig);
            if (m != null && !m.isAbstract()) return m.key();
            t = classes.get(t).superType;
        }
        for (String s : supers(type)) { // default methods of interfaces
            ClassIr c = classes.get(s);
            if (c == null || !c.isInterface()) continue;
            MethodIr m = sigIndex.get(s).get(sig);
            if (m != null && !m.isAbstract()) return m.key();
        }
        return (ext != null ? ext : type) + "->" + sig;
    }

    /** Object types in the parameter list of "name(IJLx/Y;[Lz;)V". */
    static List<String> paramTypes(String sig) {
        List<String> out = new ArrayList<>();
        int open = sig.indexOf('('), close = sig.indexOf(')');
        if (open < 0 || close < open) return out;
        for (int i = open + 1; i < close; ) {
            char ch = sig.charAt(i);
            if (ch == '[') {
                while (i < close && sig.charAt(i) == '[') i++;
                if (i < close && sig.charAt(i) == 'L') i = sig.indexOf(';', i);
                if (i < 0) break;
                i++;
            } else if (ch == 'L') {
                int semi = sig.indexOf(';', i);
                if (semi < 0) break;
                out.add(sig.substring(i, semi + 1));
                i = semi + 1;
            } else {
                i++;
            }
        }
        return out;
    }
}
