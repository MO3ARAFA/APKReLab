package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 1.0.0: which ORIGINAL class an object of an R8 horizontally merged class is.
 *
 * R8's horizontal class merger puts several unrelated classes into one (Axis Pay's m42 holds Firebase Installations' token object and Crashlytics' user-metadata object,
 * among 17 class ids) and lets them share fields: the installation token's String lives in m42.c, and so does Crashlytics' session id. A taint written into m42.c by one
 * origin is then read by the other, a flow the original program never had. R8 keeps one synthetic int / short / byte field (the class id, {@link ClassIr#discriminator})
 * that each merged constructor sets: to a constant, or to a constructor argument that every allocation site passes as a constant. That id is the TAG computed here.
 *
 * The tag of an object value is first a symbolic expression of the method that holds it ({@link Ex}), then solved over every class that names the merged class:
 *  - an allocation in this method: the constructor's constant id, or the constant the site passes for it;
 *  - {@code this} in a constructor: the constructor's constant id; in another method of the merged class: the common tag of the receivers of every call of that method
 *    (R8 keeps each original class's own methods apart, so their callers tell which origin they belong to: Signal C, method partition);
 *  - a value read from a field (a holder): the common tag of every value stored into that field, constructor arguments expanded at each allocation of the holder
 *    (Signal B, holder provenance);
 *  - a call result: the common tag of what the called method returns.
 * Anything else, or two different tags, is unknown.
 *
 * Per merged class, the PROFILE lists per shared object field and tag the static types stored there (a constructor's stores expanded at each allocation site). A store
 * whose object's tag is unknown counts for EVERY tag. A reader whose object's tag is unknown but whose method casts the object's other fields (Crashlytics' reader casts
 * m42.d to g34) excludes the tags whose every store into such a field has a type the cast cannot accept (Signal A, constructor tag through the field shapes).
 *
 * Only the classes the {@link Program} holds are seen (one analysis group, or the whole app read on demand by {@link MergeFacts}). TaintIr keeps every write whose tag
 * is unknown visible to every reader, so a tag is only ever excluded with evidence on both sides.
 */
final class MergeTags {
    static final int UNKNOWN = Integer.MIN_VALUE;
    private static final int NOT_SET = Integer.MIN_VALUE + 1;
    private static final int MAX_SOLVE_DEPTH = 12;
    /** final JDK classes and the only types (besides themselves) a value of theirs can be cast to. */
    private static final Map<String, Set<String>> FINAL_JDK = new HashMap<>();

    static {
        Set<String> num = new HashSet<>(List.of("Ljava/lang/Object;", "Ljava/lang/Number;", "Ljava/lang/Comparable;", "Ljava/io/Serializable;", "Ljava/lang/constant/Constable;", "Ljava/lang/constant/ConstantDesc;"));
        for (String t : new String[]{"Ljava/lang/Long;", "Ljava/lang/Integer;", "Ljava/lang/Double;", "Ljava/lang/Float;", "Ljava/lang/Short;", "Ljava/lang/Byte;"}) FINAL_JDK.put(t, num);
        Set<String> other = new HashSet<>(List.of("Ljava/lang/Object;", "Ljava/lang/Comparable;", "Ljava/io/Serializable;", "Ljava/lang/constant/Constable;", "Ljava/lang/constant/ConstantDesc;"));
        FINAL_JDK.put("Ljava/lang/Boolean;", other);
        FINAL_JDK.put("Ljava/lang/Character;", other);
        Set<String> str = new HashSet<>(other);
        str.add("Ljava/lang/CharSequence;");
        FINAL_JDK.put("Ljava/lang/String;", str);
    }

    /** What the tags are computed over: one analysis group's call graph ({@link #of}), or the whole app's classes read on demand ({@link MergeFacts}). */
    interface Program {
        /** "name:I" of the class-id field of a merged app class, else null. */
        String discriminator(String type);

        ClassIr cls(String type);

        MethodIr method(String key);

        /** The class [type] itself and every class that may invoke its methods or store into its fields. */
        Iterable<ClassIr> namers(String type);

        /** Method keys a call site may reach. */
        List<String> callees(MethodIr m, Insn in);

        List<String> supers(String type);
    }

    static Program of(CallGraph g) {
        return new Program() {
            private Map<String, List<ClassIr>> namers;      // type -> the classes that invoke it or store into its fields (and itself), built in one pass


            public String discriminator(String type) {
                ClassIr c = g.classIr(type);
                return c == null ? null : c.discriminator;
            }

            public ClassIr cls(String type) {
                return g.classIr(type);
            }

            public MethodIr method(String key) {
                return g.methods.get(key);
            }

            public Iterable<ClassIr> namers(String type) {
                if (namers == null) {
                    namers = new HashMap<>();
                    Set<String> seen = new HashSet<>();
                    for (ClassIr c : g.classList()) {
                        seen.clear();
                        seen.add(c.type);
                        for (MethodIr m : c.methods) {
                            for (Insn in : m.insns) {
                                if (in.kind != Insn.Kind.FIELD_PUT && in.kind != Insn.Kind.INVOKE) continue;
                                int a = in.ref.indexOf("->");
                                if (a > 0) seen.add(in.ref.substring(0, a));
                            }
                        }
                        for (String t : seen) namers.computeIfAbsent(t, k -> new ArrayList<>()).add(c);
                    }
                }
                List<ClassIr> l = namers.get(type);
                return l == null ? Collections.<ClassIr>emptyList() : l;
            }

            public List<String> callees(MethodIr m, Insn in) {
                List<String> out = new ArrayList<>();
                for (CallGraph.Edge e : g.taintEdgesFrom(m.key())) if (e.insn == in.index && !e.external) out.add(e.callee);
                if (out.isEmpty()) out.add(in.ref);
                return out;
            }

            public List<String> supers(String type) {
                return g.supers(type);
            }
        };
    }

    /** A symbolic tag: C = constant, U = unknown, T = this of a method, H = value of a holder field, R = result of a method, A = any of [alts]. */
    static final class Ex {
        static final Ex UNK = new Ex('U', UNKNOWN, null, null);
        final char k;
        final int tag;
        final String ref;
        final Ex[] alts;

        Ex(char k, int tag, String ref, Ex[] alts) {
            this.k = k;
            this.tag = tag;
            this.ref = ref;
            this.alts = alts;
        }

        static Ex c(int t) {
            return t == UNKNOWN ? UNK : new Ex('C', t, null, null);
        }

        @Override public String toString() {
            return k == 'C' ? "#" + tag : k == 'U' ? "?" : k == 'A' ? java.util.Arrays.toString(alts) : k + "(" + ref + ")";
        }
    }

    /** Everything the solver needs about one merged class, from one pass over the classes that name it. */
    private static final class Facts {
        final String type, disc;
        final List<Object[]> stores = new ArrayList<>();                 // {field, Ex object, String value type}
        final Map<String, List<Ex>> calls = new HashMap<>();              // method key of the merged class -> receivers of its call sites
        final Map<String, Integer> solved = new HashMap<>();              // "T|key", "H|field", "R|key" -> tag (NOT_SET while being solved)
        Map<String, Map<Integer, Set<String>>> profile;

        Facts(String type, String disc) {
            this.type = type;
            this.disc = disc;
        }
    }

    private final Program g;
    private final Map<String, Integer> ctorTag = new HashMap<>();            // constructor key -> tag >= 0, -2-k = the class id is constructor argument k, UNKNOWN
    private final Map<String, Facts> facts = new HashMap<>();
    private final Map<String, List<Ex>> holderValues = new HashMap<>();      // "type|holder field" -> the tags of the values stored in it
    private final Map<String, List<Ex>> returnValues = new HashMap<>();      // "type|method key" -> the tags of what it returns
    int profilesBuilt, tagsExcluded, tagsKnown;                               // measurement only
    private final List<String> hits = new ArrayList<>();                     // keys found still being solved, since the current top-level solve began

    MergeTags(Program g) {
        this.g = g;
    }

    /** The discriminator field reference ("Lm42;->b:I") of an app class R8 merged horizontally, else null. */
    synchronized String discriminatorOf(String type) {
        String d = g.discriminator(type);
        return d == null ? null : type + "->" + d;
    }

    // ------------------------------------------------------------------------------------------ entry points

    /** Tag of the object value [v] of the merged class [type] in method [m]; {@link #UNKNOWN} when no evidence. */
    synchronized int tagOf(MethodIr m, SsaForm ssa, SsaForm.Value v, String type) {
        return tagOf(m, ssa, v, type, null);
    }

    /** Same, for the object used by instruction [at]: when the solve has no answer, a switch or an if on the object's class id that [at] sits under (see {@link #cases}). */
    synchronized int tagOf(MethodIr m, SsaForm ssa, SsaForm.Value v, String type, Insn at) {
        Facts f = facts(type);
        if (f == null) return UNKNOWN;
        hits.clear();
        int t = solve(f, expr(m, ssa, v, type, new HashSet<>()), 0);
        if (t < 0 && at != null) {
            long[][] c = cases(m, ssa, at, v, f.disc);
            if (c != null && c[0] != null && c[0].length == 1 && c[0][0] >= 0 && c[0][0] <= Integer.MAX_VALUE) t = (int) c[0][0];
        }
        if (t >= 0) tagsKnown++;
        return t < 0 ? UNKNOWN : t;
    }

    /**
     * Tags the object [recv] (of merged class [type], read in method [m]) can still have, out of [written]: its own tag when known, else the tags its other fields' casts
     * allow; null = no evidence (every tag).
     */
    synchronized Set<Integer> compatible(MethodIr m, SsaForm ssa, SsaForm.Value recv, String type, Set<Integer> written, Map<SsaForm.Value, List<Insn>> users) {
        return compatible(m, ssa, recv, type, written, users, null);
    }

    /** Same, for the read [at]: a switch or an if on the object's class id that [at] sits under narrows the tags, and only casts that always run before [at] count. */
    synchronized Set<Integer> compatible(MethodIr m, SsaForm ssa, SsaForm.Value recv, String type, Set<Integer> written, Map<SsaForm.Value, List<Insn>> users, Insn at) {
        Facts f = facts(type);
        if (f == null) return null;
        hits.clear();
        int own = solve(f, expr(m, ssa, recv, type, new HashSet<>()), 0);
        if (own >= 0) { tagsKnown++; return Collections.singleton(own); }
        Set<Integer> cand = new HashSet<>(written);
        boolean evidence = false;
        if (at != null) {
            long[][] c = cases(m, ssa, at, recv, f.disc);
            if (c != null) {
                evidence = true;
                if (c[0] != null) { Set<Integer> only = new HashSet<>(); for (long k : c[0]) if (k >= 0 && k <= Integer.MAX_VALUE) only.add((int) k); cand.retainAll(only); }
                if (c[1] != null) for (long k : c[1]) if (k >= 0 && k <= Integer.MAX_VALUE) cand.remove((int) k);
            }
        }
        SsaForm.Value root = root(ssa, recv);
        String prefix = type + "->";
        Cfg.BasicBlock atBlock = at == null ? null : ssa.cfg.blockOfInsn(at.index);
        List<String[]> obs = new ArrayList<>();      // {field, cast type}
        for (Insn in : m.insns) {
            if (in.kind != Insn.Kind.FIELD_GET || !in.op.startsWith("iget-object") || !in.ref.startsWith(prefix)) continue;
            SsaForm.Value[] u = ssa.usesOf(in), d = ssa.defsOf(in);
            if (u.length == 0 || d.length != 1 || root(ssa, u[0]) != root) continue;
            // a cast on another path (another case of a class-id switch) says nothing about this object: only reads that always run before [at] count
            if (atBlock != null) {
                Cfg.BasicBlock b = ssa.cfg.blockOfInsn(in.index);
                if (b == null || !ssa.cfg.dominates(b.id, atBlock.id) || (b == atBlock && in.index > at.index)) continue;
            }
            String cast = castOf(ssa, d[0], users);
            if (cast != null) obs.add(new String[]{in.ref, cast});
        }
        if (obs.isEmpty()) return evidence ? cand : null;
        Map<String, Map<Integer, Set<String>>> p = profile(type);
        Set<Integer> out = new HashSet<>();
        for (int t : cand) {
            boolean ok = true;
            for (String[] o : obs) {
                Map<Integer, Set<String>> byTag = p.get(o[0]);
                if (byTag == null || !byTag.containsKey(t)) continue;          // no store of this tag seen: no evidence
                Set<String> types = byTag.get(t);
                if (types == null || byTag.containsKey(UNKNOWN) && byTag.get(UNKNOWN) == null) continue;
                Set<String> all = new HashSet<>(types);
                if (byTag.get(UNKNOWN) != null) all.addAll(byTag.get(UNKNOWN));
                boolean anyFits = false;
                for (String s : all) if (!disjoint(s, o[1])) { anyFits = true; break; }
                if (!anyFits) { ok = false; break; }
            }
            if (ok) out.add(t); else tagsExcluded++;
        }
        return out;
    }

    /** field ref -> tag (UNKNOWN = a store whose object's tag is unknown) -> static types stored (null = any type). */
    synchronized Map<String, Map<Integer, Set<String>>> profile(String type) {
        Facts f = facts(type);
        if (f == null) return Collections.emptyMap();
        if (f.profile != null) return f.profile;
        Map<String, Map<Integer, Set<String>>> p = new HashMap<>();
        for (Object[] s : f.stores) {
            hits.clear();
            int t = solve(f, (Ex) s[1], 0);
            add(p, (String) s[0], t < 0 ? UNKNOWN : t, (String) s[2]);
        }
        profilesBuilt++;
        return f.profile = p;
    }

    /**
     * The class ids under which instruction [at] can run, when every path to it passes a test of the class id of [obj] (R8's dispatch methods switch on it:
     * {@code iget v0, p0, disc; packed-switch v0}; a merged Kotlin lambda's invoke() holds every origin's body, one per case):
     * {only, except} (either may be null), or null when no such test decides it.
     */
    long[][] cases(MethodIr m, SsaForm ssa, Insn at, SsaForm.Value obj, String disc) {
        if (disc == null || ssa.cfg == null) return null;
        Cfg.BasicBlock target = ssa.cfg.blockOfInsn(at.index);
        if (target == null) return null;
        SsaForm.Value root = root(ssa, obj);
        long[] only = null;
        Set<Long> except = null;
        for (Insn in : m.insns) {
            if (in.kind != Insn.Kind.SWITCH && in.kind != Insn.Kind.IF) continue;
            SsaForm.Value[] u = ssa.usesOf(in);
            if (u.length == 0 || !isDisc(ssa, u[0], root, disc)) continue;
            Cfg.BasicBlock sb = ssa.cfg.blockOfInsn(in.index);
            if (sb == null || sb.last != in.index) continue;
            // which successor of the test leads (alone) to [at], and which keys go there
            for (Cfg.Edge e : sb.succs) {
                if (e.isException() || e.to.preds.size() != 1 || !ssa.cfg.dominates(e.to.id, target.id)) continue;
                long[] keys = null;
                Set<Long> notKeys = null;
                if (in.kind == Insn.Kind.SWITCH) {
                    List<String> labels = m.payloads.get(in.labels.length > 0 ? in.labels[0] : "");
                    long[] ks = m.switchKeys == null ? null : m.switchKeys.get(in.labels.length > 0 ? in.labels[0] : "");
                    if (labels == null || ks == null) continue;
                    if ((e.kinds & Cfg.K_SWITCH) != 0) {
                        List<Long> l = new ArrayList<>();
                        for (int i = 0; i < labels.size(); i++) {
                            Integer idx = m.labels.get(labels.get(i));
                            Cfg.BasicBlock lb = idx == null ? null : ssa.cfg.blockOfInsn(idx);
                            if (lb == e.to) l.add(ks[i]);
                        }
                        if (l.isEmpty() || (e.kinds & ~Cfg.K_SWITCH) != 0) continue;   // also the default path: not decided
                        keys = new long[l.size()];
                        for (int i = 0; i < keys.length; i++) keys[i] = l.get(i);
                    } else {
                        notKeys = new HashSet<>();
                        for (long k : ks) notKeys.add(k);
                    }
                } else {
                    Long k;
                    if (in.op.endsWith("z")) k = 0L;
                    else k = u.length > 1 ? constOf(u[1]) : null;
                    if (k == null) continue;
                    boolean eq = in.op.startsWith("if-eq");                       // if-eq / if-eqz jump when equal, if-ne / if-nez when not
                    if (!eq && !in.op.startsWith("if-ne")) continue;
                    boolean taken = (e.kinds & Cfg.K_TRUE) != 0, fall = (e.kinds & (Cfg.K_FALSE | Cfg.K_FALL)) != 0;
                    if (taken == fall) continue;
                    if (taken == eq) keys = new long[]{k};
                    else notKeys = new HashSet<>(Collections.singleton(k));
                }
                if (keys != null) {
                    if (only == null) only = keys;
                    else {
                        List<Long> l = new ArrayList<>();
                        for (long a : only) for (long b : keys) if (a == b) l.add(a);
                        only = new long[l.size()];
                        for (int i = 0; i < only.length; i++) only[i] = l.get(i);
                    }
                }
                if (notKeys != null) {
                    if (except == null) except = new HashSet<>();
                    except.addAll(notKeys);
                }
            }
        }
        if (only == null && except == null) return null;
        long[] ex = null;
        if (except != null) {
            ex = new long[except.size()];
            int i = 0;
            for (long k : except) ex[i++] = k;
        }
        return new long[][]{only, ex};
    }

    /** True when [v] is the class id read from [root] (through moves). */
    private static boolean isDisc(SsaForm ssa, SsaForm.Value v, SsaForm.Value root, String disc) {
        for (int i = 0; v != null && i < 8; i++) {
            if (v.def == null) return false;
            if (v.def.kind == Insn.Kind.MOVE) {
                SsaForm.Value[] u = ssa.usesOf(v.def);
                v = u.length > 0 ? u[0] : null;
                continue;
            }
            if (v.def.kind != Insn.Kind.FIELD_GET || !v.def.ref.equals(disc)) return false;
            SsaForm.Value[] u = ssa.usesOf(v.def);
            return u.length > 0 && root(ssa, u[0]) == root;
        }
        return false;
    }

    // ------------------------------------------------------------------------------------------ one pass per merged class

    private Facts facts(String type) {
        if (facts.containsKey(type)) return facts.get(type);
        String disc = discriminatorOf(type);
        Facts f = disc == null ? null : new Facts(type, disc);
        facts.put(type, f);
        if (f == null) return null;
        String prefix = type + "->";
        for (ClassIr c : g.namers(type)) {
            for (MethodIr m : c.methods) {
                if (m.insns.isEmpty()) continue;
                boolean touches = false;
                for (Insn in : m.insns) {
                    if ((in.kind == Insn.Kind.FIELD_PUT || in.kind == Insn.Kind.INVOKE) && in.ref.startsWith(prefix)) { touches = true; break; }
                }
                if (touches) scan(f, m, SsaForm.buildCached(m));
            }
        }
        return f;
    }

    private void scan(Facts f, MethodIr m, SsaForm ssa) {
        String type = f.type, prefix = type + "->";
        boolean ownCtor = "<init>".equals(m.name) && m.owner.equals(type);
        int own = ownCtor ? ctorTag(m.key()) : UNKNOWN;
        boolean siteTagged = ownCtor && own < 0 && own != UNKNOWN;     // the class id is an argument: every store belongs to the caller's id
        for (Insn in : m.insns) {
            if (in.kind == Insn.Kind.FIELD_PUT && in.op.startsWith("iput-object") && in.ref.startsWith(prefix) && !in.ref.equals(f.disc)) {
                SsaForm.Value[] u = ssa.usesOf(in);
                if (u.length < 2) continue;
                // a constructor storing its own argument, or any store of a constructor whose class id is an argument: expanded at each allocation site below
                // (the declared type is Object for R8's synthetic constructors; Axis Pay's m42.<init>(I) stores HashMaps for id 0x10 only)
                if (ownCtor && isThis(m, u[1]) && (isArg(m, u[0]) || siteTagged)) continue;
                Ex obj = expr(m, ssa, u[1], type, new HashSet<>());
                if (obj.k == 'T' || obj.k == 'U') {
                    long[][] c = cases(m, ssa, in, u[1], f.disc);
                    if (c != null && c[0] != null && c[0].length == 1 && c[0][0] >= 0 && c[0][0] <= Integer.MAX_VALUE) obj = Ex.c((int) c[0][0]);
                }
                f.stores.add(new Object[]{in.ref, obj, typeOf(m, ssa, u[0], 0)});
            } else if (in.kind == Insn.Kind.INVOKE && in.ref.startsWith(prefix)) {
                SsaForm.Value[] u = ssa.usesOf(in);
                if (u.length == 0 || in.invokeKind().equals("static")) continue;
                if ("<init>".equals(in.targetName())) {
                    MethodIr ctor = g.method(in.ref);
                    if (ctor == null) continue;
                    Ex site = ownCtor && isThis(m, u[0]) ? Ex.c(own >= 0 ? own : UNKNOWN)
                            : u[0].def != null && u[0].def.kind == Insn.Kind.NEW_INSTANCE ? Ex.c(allocTag(m, ssa, u[0])) : Ex.UNK;
                    SsaForm cs = SsaForm.buildCached(ctor);
                    int ct = ctorTag(ctor.key());
                    boolean ctorSiteTagged = ct < 0 && ct != UNKNOWN;
                    for (Insn ci : ctor.insns) {
                        if (ci.kind != Insn.Kind.FIELD_PUT || !ci.op.startsWith("iput-object") || !ci.ref.startsWith(prefix) || ci.ref.equals(f.disc)) continue;
                        SsaForm.Value[] cu = cs.usesOf(ci);
                        if (cu.length < 2 || !isThis(ctor, cu[1])) continue;
                        if (isArg(ctor, cu[0])) f.stores.add(new Object[]{ci.ref, site, typeOf(m, ssa, argValue(ssa, in, argIndex(ctor, cu[0].reg)), 0)});
                        else if (ctorSiteTagged) f.stores.add(new Object[]{ci.ref, site, typeOf(ctor, cs, cu[0], 0)});
                    }
                } else {
                    f.calls.computeIfAbsent(in.ref, k -> new ArrayList<>()).add(expr(m, ssa, u[0], type, new HashSet<>()));
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------ symbolic tags

    /** The symbolic tag of object value [v] of merged class [type] in method [m]: no other method is read here. */
    Ex expr(MethodIr m, SsaForm ssa, SsaForm.Value v, String type, Set<SsaForm.Phi> seen) {
        for (int hops = 0; v != null && hops < 16; hops++) {
            if (v.def == null) {
                if (v.phi != null) {
                    if (!seen.add(v.phi)) return new Ex('A', 0, null, new Ex[0]);
                    Ex[] a = new Ex[v.phi.operands.length];
                    for (int i = 0; i < a.length; i++) a[i] = v.phi.operands[i] == null ? Ex.UNK : expr(m, ssa, v.phi.operands[i], type, seen);
                    return new Ex('A', 0, null, a);
                }
                if (v.param && !m.isStatic && argIndex(m, v.reg) == 0 && m.owner.equals(type)) {
                    if ("<init>".equals(m.name)) {
                        int t = ctorTag(m.key());
                        return Ex.c(t >= 0 ? t : UNKNOWN);
                    }
                    return new Ex('T', 0, m.key(), null);
                }
                return Ex.UNK;
            }
            Insn d = v.def;
            switch (d.kind) {
                case MOVE:
                case CHECK_CAST: {
                    SsaForm.Value[] u = ssa.usesOf(d);
                    v = u.length > 0 ? u[0] : null;
                    continue;
                }
                case NEW_INSTANCE:
                    return d.ref.equals(type) ? Ex.c(allocTag(m, ssa, v)) : Ex.UNK;
                case FIELD_GET:
                    return new Ex('H', 0, d.ref, null);
                case INVOKE: {
                    if (!d.hasResult) return Ex.UNK;
                    List<String> cs = g.callees(m, d);
                    Ex[] a = new Ex[cs.size()];
                    for (int i = 0; i < a.length; i++) a[i] = new Ex('R', 0, cs.get(i), null);
                    return a.length == 1 ? a[0] : new Ex('A', 0, null, a);
                }
                default:
                    return Ex.UNK;
            }
        }
        return Ex.UNK;
    }

    /** Solves a symbolic tag: a tag >= 0, UNKNOWN, or NOT_SET (only a cycle back to what is being solved). */
    private int solve(Facts f, Ex e, int depth) {
        switch (e.k) {
            case 'C':
                return e.tag;
            case 'U':
                return UNKNOWN;
            case 'A': {
                int common = NOT_SET;
                for (Ex x : e.alts) {
                    int t = solve(f, x, depth);
                    if (t == NOT_SET) continue;
                    if (t == UNKNOWN || (common != NOT_SET && common != t)) return UNKNOWN;
                    common = t;
                }
                return common;
            }
            default: {
                if (depth > MAX_SOLVE_DEPTH) return UNKNOWN;
                String key = e.k + "|" + e.ref;
                Integer c = f.solved.get(key);
                if (c != null) {
                    if (c == NOT_SET) hits.add(key);
                    return c;
                }
                f.solved.put(key, NOT_SET);
                int mark = hits.size();
                List<Ex> from = e.k == 'T' ? f.calls.getOrDefault(e.ref, Collections.emptyList()) : e.k == 'H' ? holderValues(f.type, e.ref) : returnValues(f.type, e.ref);
                int common = NOT_SET;
                for (Ex x : from) {
                    int t = solve(f, x, depth + 1);
                    if (t == NOT_SET) continue;
                    if (t == UNKNOWN || (common != NOT_SET && common != t)) { common = UNKNOWN; break; }
                    common = t;
                }
                int r = common == NOT_SET ? UNKNOWN : common;
                // a value computed while an OUTER key was still being solved is partial (that key's values were skipped): it is not kept, the outer solve decides
                boolean partial = false;
                for (int i = mark; i < hits.size(); i++) if (!hits.get(i).equals(key)) { partial = true; break; }
                if (partial) f.solved.remove(key);
                else {
                    f.solved.put(key, r);
                    while (hits.size() > mark) hits.remove(hits.size() - 1);
                }
                return r;
            }
        }
    }

    /** What is stored into holder field [field] that can be an object of [type] (every store in the classes that name the holder; constructor arguments per site). */
    private List<Ex> holderValues(String type, String field) {
        String key = type + "|" + field;
        List<Ex> l = holderValues.get(key);
        if (l != null) return l;
        l = new ArrayList<>();
        holderValues.put(key, l);
        int a = field.indexOf("->"), colon = field.lastIndexOf(':');
        if (a <= 0 || colon < a) { l.add(Ex.UNK); return l; }
        String owner = field.substring(0, a), ftype = field.substring(colon + 1);
        if (!ftype.equals(type) && !ftype.equals("Ljava/lang/Object;")) { l.add(Ex.UNK); return l; }   // an interface or super type: other classes' objects too
        boolean found = false;
        for (ClassIr c : g.namers(owner)) {
            for (MethodIr m : c.methods) {
                boolean touches = false;
                for (Insn in : m.insns) {
                    if ((in.kind == Insn.Kind.FIELD_PUT && in.ref.equals(field)) || (in.kind == Insn.Kind.INVOKE && in.ref.startsWith(owner + "-><init>("))) { touches = true; break; }
                }
                if (!touches) continue;
                SsaForm ssa = SsaForm.buildCached(m);
                for (Insn in : m.insns) {
                    if (in.kind == Insn.Kind.FIELD_PUT && in.ref.equals(field)) {
                        SsaForm.Value[] u = ssa.usesOf(in);
                        if (u.length == 0) continue;
                        if ("<init>".equals(m.name) && m.owner.equals(owner) && isArg(m, u[0]) && u.length > 1 && isThis(m, u[1])) continue;   // per allocation site below
                        found = true;
                        addValue(l, m, ssa, u[0], type);
                    } else if (in.kind == Insn.Kind.INVOKE && in.ref.startsWith(owner + "-><init>(")) {
                        MethodIr ctor = g.method(in.ref);
                        if (ctor == null) continue;
                        SsaForm cs = SsaForm.buildCached(ctor);
                        for (Insn ci : ctor.insns) {
                            if (ci.kind != Insn.Kind.FIELD_PUT || !ci.ref.equals(field)) continue;
                            SsaForm.Value[] cu = cs.usesOf(ci);
                            if (cu.length < 2 || !isThis(ctor, cu[1]) || !isArg(ctor, cu[0])) continue;
                            found = true;
                            addValue(l, m, ssa, argValue(ssa, in, argIndex(ctor, cu[0].reg)), type);
                        }
                    }
                }
            }
        }
        if (!found) l.add(Ex.UNK);
        return l;
    }

    private void addValue(List<Ex> l, MethodIr m, SsaForm ssa, SsaForm.Value v, String type) {
        String t = typeOf(m, ssa, v, 0);
        if ("null".equals(t)) return;                                       // null holds no object
        if (t != null && !t.equals(type) && (!t.startsWith("L") || disjoint(t, type))) return;   // never an object of the merged class
        l.add(expr(m, ssa, v, type, new HashSet<>()));
    }

    private List<Ex> returnValues(String type, String key) {
        String k = type + "|" + key;
        List<Ex> l = returnValues.get(k);
        if (l != null) return l;
        l = new ArrayList<>();
        returnValues.put(k, l);
        MethodIr m = g.method(key);
        if (m == null || m.insns.isEmpty() || m.isAbstract() || m.isNative()) { l.add(Ex.UNK); return l; }
        SsaForm ssa = SsaForm.buildCached(m);
        for (Insn in : m.insns) {
            if (in.kind != Insn.Kind.RETURN) continue;
            SsaForm.Value[] u = ssa.usesOf(in);
            if (u.length == 0) l.add(Ex.UNK);
            else addValue(l, m, ssa, u[0], type);
        }
        return l;
    }

    // ------------------------------------------------------------------------------------------ constructors and allocations

    /** Tag of a fresh object: the constructor called on it in this method, its constant id or the constant it passes for the id. */
    private int allocTag(MethodIr m, SsaForm ssa, SsaForm.Value obj) {
        Insn init = initOf(m, ssa, obj);
        if (init == null) return UNKNOWN;
        int t = ctorTag(init.targetOwner() + "->" + init.targetSig());
        if (t >= 0 || t == UNKNOWN) return t;
        Long c = constOf(argValue(ssa, init, -2 - t + 1));
        return c == null || c < 0 || c > Integer.MAX_VALUE ? UNKNOWN : (int) (long) c;
    }

    private static Insn initOf(MethodIr m, SsaForm ssa, SsaForm.Value obj) {
        for (int i = obj.def.index + 1; i < m.insns.size(); i++) {
            Insn in = m.insns.get(i);
            if (in.kind != Insn.Kind.INVOKE || !"<init>".equals(in.targetName())) continue;
            SsaForm.Value[] u = ssa.usesOf(in);
            if (u.length > 0 && u[0] == obj) return in;
        }
        return null;
    }

    /** Class id a constructor of a merged class stores: a constant (>= 0), -2-k when it stores its argument k, else UNKNOWN. */
    synchronized int ctorTag(String key) {
        Integer c = ctorTag.get(key);
        if (c != null) return c;
        int r = UNKNOWN;
        MethodIr m = g.method(key);
        String disc = m == null ? null : discriminatorOf(m.owner);
        if (disc != null) {
            SsaForm ssa = SsaForm.buildCached(m);
            int common = NOT_SET;
            for (Insn in : m.insns) {
                if (in.kind != Insn.Kind.FIELD_PUT || !in.ref.equals(disc)) continue;
                SsaForm.Value[] u = ssa.usesOf(in);
                if (u.length < 2 || !isThis(m, u[1])) continue;
                int t;
                Long k = constOf(u[0]);
                if (k != null && k >= 0 && k <= Integer.MAX_VALUE) t = (int) (long) k;
                else if (isArg(m, u[0])) t = -2 - (argIndex(m, u[0].reg) - 1);
                else t = UNKNOWN;
                if (t == UNKNOWN || (common != NOT_SET && common != t)) { common = UNKNOWN; break; }
                common = t;
            }
            r = common == NOT_SET ? UNKNOWN : common;
        }
        ctorTag.put(key, r);
        return r;
    }

    // ------------------------------------------------------------------------------------------ types

    private static void add(Map<String, Map<Integer, Set<String>>> p, String field, int tag, String type) {
        if ("null".equals(type)) return;                 // a null store fits every cast
        Map<Integer, Set<String>> byTag = p.computeIfAbsent(field, k -> new HashMap<>());
        if (byTag.containsKey(tag) && byTag.get(tag) == null) return;
        if (type == null) { byTag.put(tag, null); return; }
        byTag.computeIfAbsent(tag, k -> new HashSet<>()).add(type);
    }

    /** Static type of a value: "null" for the null constant, null when not known or Object. */
    static String typeOf(MethodIr m, SsaForm ssa, SsaForm.Value v, int depth) {
        if (v == null || depth > 8) return null;
        if (v.def == null) {
            if (v.phi != null || !v.param) return null;
            int a = argIndex(m, v.reg);
            List<String> pt = paramTypes(m.desc);
            int k = a - (m.isStatic ? 0 : 1);
            return known(a < 0 ? null : !m.isStatic && a == 0 ? m.owner : k < pt.size() ? pt.get(k) : null);
        }
        Insn d = v.def;
        switch (d.kind) {
            case CONST:
                if (d.op.startsWith("const-string")) return "Ljava/lang/String;";
                if (d.op.startsWith("const-class")) return "Ljava/lang/Class;";
                Long c = constOf(v);
                return c != null && c == 0 ? "null" : null;
            case NEW_INSTANCE:
            case CHECK_CAST:
            case NEW_ARRAY:
                return known(d.ref);
            case FIELD_GET: {
                int i = d.ref.lastIndexOf(':');
                return i < 0 ? null : known(d.ref.substring(i + 1));
            }
            case INVOKE: {
                if (!d.hasResult) return null;
                String s = d.targetSig();
                int i = s.lastIndexOf(')');
                return i < 0 ? null : known(s.substring(i + 1));
            }
            case MOVE: {
                SsaForm.Value[] u = ssa.usesOf(d);
                return u.length == 0 ? null : typeOf(m, ssa, u[0], depth + 1);
            }
            default:
                return null;
        }
    }

    private static String known(String t) {
        return t == null || t.equals("Ljava/lang/Object;") || !(t.startsWith("L") || t.startsWith("[")) ? null : t;
    }

    private static SsaForm.Value root(SsaForm ssa, SsaForm.Value v) {
        for (int i = 0; v != null && v.def != null && i < 16 && (v.def.kind == Insn.Kind.MOVE || v.def.kind == Insn.Kind.CHECK_CAST); i++) {
            SsaForm.Value[] u = ssa.usesOf(v.def);
            if (u.length == 0) break;
            v = u[0];
        }
        return v;
    }

    /** The one type every use of [v] (through plain moves) casts it to, else null. */
    private static String castOf(SsaForm ssa, SsaForm.Value v, Map<SsaForm.Value, List<Insn>> users) {
        String cast = null;
        List<SsaForm.Value> q = new ArrayList<>();
        q.add(v);
        Set<SsaForm.Value> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        seen.add(v);
        for (int i = 0; i < q.size(); i++) {
            List<Insn> us = users.get(q.get(i));
            if (us == null) continue;
            for (Insn in : us) {
                if (in == null) return null;                                   // a phi: the value mixes with others
                if (in.kind == Insn.Kind.MOVE) {
                    for (SsaForm.Value y : ssa.defsOf(in)) if (seen.add(y)) q.add(y);
                } else if (in.kind == Insn.Kind.CHECK_CAST) {
                    if (cast != null && !cast.equals(in.ref)) return null;
                    cast = in.ref;
                } else return null;
            }
        }
        return cast == null || cast.equals("Ljava/lang/Object;") ? null : cast;
    }

    /** True only when no value of static type [s] can be cast to [t]. */
    boolean disjoint(String s, String t) {
        if (s.equals(t)) return false;
        Set<String> sf = FINAL_JDK.get(s), tf = FINAL_JDK.get(t);
        if (sf != null) return !sf.contains(t);
        if (tf != null) return !tf.contains(s);
        boolean sa = s.startsWith("["), ta = t.startsWith("[");
        if (sa != ta) {
            String o = sa ? t : s;
            return !(o.equals("Ljava/lang/Object;") || o.equals("Ljava/lang/Cloneable;") || o.equals("Ljava/io/Serializable;"));
        }
        if (sa) return false;
        ClassIr cs = g.cls(s), ct = g.cls(t);
        if (cs == null || ct == null || cs.isInterface() || ct.isInterface()) return false;
        return !g.supers(s).contains(t) && !g.supers(t).contains(s);
    }

    // ------------------------------------------------------------------------------------------ helpers

    private static boolean isThis(MethodIr m, SsaForm.Value v) {
        return v != null && v.def == null && v.phi == null && v.param && !m.isStatic && argIndex(m, v.reg) == 0;
    }

    private static boolean isArg(MethodIr m, SsaForm.Value v) {
        return v != null && v.def == null && v.phi == null && v.param && argIndex(m, v.reg) > (m.isStatic ? -1 : 0);
    }

    static Long constOf(SsaForm.Value v) {
        if (v == null || v.def == null || v.def.kind != Insn.Kind.CONST || v.def.op.startsWith("const-string") || v.def.op.startsWith("const-class")
                || v.def.op.startsWith("const/high16") || v.def.op.startsWith("const-wide/high16")) return null;
        String s = v.def.ref.trim();
        if (s.endsWith("L") || s.endsWith("l") || s.endsWith("t") || s.endsWith("s")) s = s.substring(0, s.length() - 1);
        try {
            return Long.decode(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static List<String> paramTypes(String desc) {
        List<String> out = new ArrayList<>();
        int i = desc.indexOf('(') + 1, e = desc.indexOf(')');
        while (i > 0 && i < e) {
            int s = i;
            while (desc.charAt(i) == '[') i++;
            if (desc.charAt(i) == 'L') i = desc.indexOf(';', i);
            i++;
            out.add(desc.substring(s, i));
        }
        return out;
    }

    /** Logical argument (0 = this for an instance method) held in register [reg] at entry, or -1. */
    static int argIndex(MethodIr m, int reg) {
        int slot = reg - m.locals;
        if (slot < 0) return -1;
        int at = 0, idx = 0;
        if (!m.isStatic) {
            if (slot == 0) return 0;
            at = 1;
            idx = 1;
        }
        for (String t : paramTypes(m.desc)) {
            if (slot == at) return idx;
            at += t.equals("J") || t.equals("D") ? 2 : 1;
            idx++;
        }
        return -1;
    }

    /** The SSA value passed as logical argument [arg] (0 = receiver) of an invoke. */
    static SsaForm.Value argValue(SsaForm ssa, Insn invoke, int arg) {
        SsaForm.Value[] u = ssa.usesOf(invoke);
        boolean isStatic = invoke.invokeKind().equals("static");
        int at = 0, idx = 0;
        if (!isStatic) {
            if (arg == 0) return u.length > 0 ? u[0] : null;
            at = 1;
            idx = 1;
        }
        for (String t : paramTypes(invoke.targetSig())) {
            if (idx == arg) return at < u.length ? u[at] : null;
            at += t.equals("J") || t.equals("D") ? 2 : 1;
            idx++;
        }
        return null;
    }
}
