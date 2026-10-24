package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 0.54.0 (P0): compares the OLD reach answer of each finding (Kotlin SecurityScanner.trace: YES / YES~ / NO) with the NEW
 * {@link CallGraph} (RTA, entries = lifecycle methods of the exported components). Nothing in the scanner is changed by it.
 *
 * Disagreements are split into causes that are expected (the old trace counts the exported class itself and its inner classes as
 * reached at depth 0, the new graph needs a real call chain from a lifecycle method) and the ones that need a look.
 */
public final class CgCompare {
    private CgCompare() {
    }

    public static final class Item {
        public final String key, old, label, chain;

        public Item(String key, String old, String label, String chain) {
            this.key = key;
            this.old = old == null ? "" : old;
            this.label = label == null ? "" : label;
            this.chain = chain == null ? "" : chain;
        }
    }

    public static String run(Collection<ClassIr> app, Collection<String> entryTypes, List<Item> items) {
        long t0 = System.nanoTime();
        CallGraph g = CallGraph.build(app, entryTypes, CallGraph.Mode.RTA, null);
        long t1 = System.nanoTime();
        CallGraph cha = CallGraph.build(app, entryTypes, CallGraph.Mode.CHA, null);
        long t2 = System.nanoTime();
        Set<String> entryClasses = new HashSet<>(entryTypes);

        int[][] tab = new int[3][3];                  // [old YES, YES~, NO][new reachable, not reachable, not in graph]
        int chaReach = 0;
        List<String> oldYesNewNo = new ArrayList<>(), oldYesNewNoEntry = new ArrayList<>(), oldNoNewYes = new ArrayList<>(),
                approxList = new ArrayList<>();
        for (Item it : items) {
            int o = it.old.equals("YES") ? 0 : it.old.equals("YES~") ? 1 : it.old.equals("NO") ? 2 : -1;
            if (o < 0) continue;
            boolean known = g.methods.containsKey(it.key);
            int n = !known ? 2 : g.isReachable(it.key) ? 0 : 1;
            tab[o][n]++;
            if (known && cha.isReachable(it.key)) chaReach++;
            String line = it.label + "\n      " + it.key;
            if (o == 0 && n != 0) {
                if (inEntryClass(it.key, entryClasses)) oldYesNewNoEntry.add(line);
                else oldYesNewNo.add(line + (it.chain.isEmpty() ? "" : "\n      old: " + one(it.chain)) + (n == 2 ? "\n      (method not in the new graph)" : "")
                        + diagnose(g, it.chain, allCallers(g), entryClasses));
            } else if (o == 2 && n == 0) {
                oldNoNewYes.add(line + "\n      new: " + path(g, it.key));
            } else if (o == 1) {
                approxList.add(line + "\n      new: " + (n == 0 ? path(g, it.key) : "no path"));
            }
        }
        StringBuilder sb = new StringBuilder("CALL GRAPH COMPARE (old Kotlin trace vs new IR CallGraph)\n===============================================\n");
        sb.append("new graph RTA: ").append(g.stats()).append(" in ").append((t1 - t0) / 1_000_000).append(" ms\n");
        sb.append("new graph CHA: ").append(cha.stats()).append(" in ").append((t2 - t1) / 1_000_000).append(" ms\n");
        sb.append("findings compared: ").append(count(tab)).append("  (CHA reaches ").append(chaReach).append(" of them)\n\n");
        sb.append("old \\ new        reachable   not reachable   not in graph\n");
        String[] rows = {"YES  (exact)  ", "YES~ (approx) ", "NO            "};
        for (int i = 0; i < 3; i++) {
            sb.append(rows[i]).append(pad(tab[i][0])).append(pad(tab[i][1])).append(pad(tab[i][2])).append('\n');
        }
        section(sb, "OLD YES, NEW NO - sink is in the exported class itself or an inner class (expected: the old trace counts it at depth 0)",
                oldYesNewNoEntry, 8);
        section(sb, "OLD YES, NEW NO - NEEDS A LOOK (the new graph lost a path)", oldYesNewNo, 25);
        section(sb, "OLD NO, NEW YES (the new graph found a path the old one missed)", oldNoNewYes, 25);
        section(sb, "OLD YES~ (approximate) and what the new graph says", approxList, 15);
        return sb.toString();
    }

    // ---------- 0.54.3: where did the new graph lose the old path? ----------

    /** Old path hops ("pkg.Cls.m()") -> status in the new graph, and what the last reached hop does around the break. */
    private static String diagnose(CallGraph g, String chain, Map<String, List<String>> all, Set<String> entryClasses) {
        int p = chain.indexOf("Path:");
        if (p < 0) return "";
        String[] hops = chain.substring(p + 5).trim().split("\\s*->\\s*");
        StringBuilder sb = new StringBuilder("\n      why (hop by hop in the NEW graph):");
        String lastReached = null;
        for (String hop : hops) {
            String h = hop.trim();
            int paren = h.indexOf('(');
            if (paren > 0) h = h.substring(0, paren);
            int dot = h.lastIndexOf('.');
            if (dot <= 0) continue;
            String owner = "L" + h.substring(0, dot).replace('.', '/') + ";", name = h.substring(dot + 1);
            List<String> found = new ArrayList<>();
            boolean reached = false;
            for (String k : g.methods.keySet()) {
                if (k.startsWith(owner + "->" + name + "(")) {
                    found.add(k);
                    if (g.isReachable(k)) reached = true;
                }
            }
            String st = found.isEmpty() ? "NOT IN GRAPH" : reached ? "reached" : "NOT REACHED";
            sb.append("\n        ").append(shortName(owner + "->" + name)).append(": ").append(st);
            if (!reached) {
                // exact signatures and flags that exist under this name (or a similar one), so a signature mismatch shows up
                List<String> shown = new ArrayList<>();
                for (String k : g.methods.keySet()) {
                    if (!k.startsWith(owner + "->")) continue;
                    String nm = k.substring(owner.length() + 2);
                    if (nm.startsWith(name + "(") || nm.contains(name)) {
                        MethodIr mi = g.methods.get(k);
                        shown.add(nm + " [" + mi.flags + "]");
                    }
                }
                sb.append("\n          defined: ").append(shown.isEmpty() ? "nothing like it in " + shortType(owner) : joinShort(shown, 6));
                sb.append("\n          class ").append(shortType(owner)).append(g.instantiated.contains(owner) ? " is instantiated" : " is NOT instantiated")
                        .append(", ").append(entryHasOwner(g, owner) ? "has a reached method" : "has NO reached method")
                        .append("\n          entry component: ").append(entryClasses.contains(owner) ? "yes" : "no")
                        .append("; super chain: ").append(g.superChain(owner));
            }
            if (reached) {
                lastReached = found.get(0);
                for (String k : found) if (g.isReachable(k)) { lastReached = k; break; }
            } else {
                if (!found.isEmpty()) {
                    Set<String> callers = new LinkedHashSet<>();
                    for (String k : found) callers.addAll(g.callersOf(k));
                    sb.append(" (callers in new graph: ").append(callers.isEmpty() ? "none" : joinShort(callers, 4)).append(")");
                    for (String k : found) sb.append(callerChain(g, all, k));
                }
                if (lastReached != null) sb.append(summary(g, lastReached));
                return sb.toString();
            }
        }
        return sb.toString();
    }

    private static boolean entryHasOwner(CallGraph g, String owner) {
        for (String k : g.reachable) if (k.startsWith(owner + "->")) return true;
        return false;
    }

    /** name+desc -> keys of methods that contain an invoke of that name+desc on any owner (the owner is checked when printing). */
    private static Map<String, List<String>> allCallers(CallGraph g) {
        Map<String, List<String>> m = new HashMap<>();
        for (MethodIr mi : g.methods.values()) {
            for (Insn in : mi.insns) {
                if (in.kind != Insn.Kind.INVOKE) continue;
                m.computeIfAbsent(in.ref, k -> new ArrayList<>()).add(mi.key());
            }
        }
        return m;
    }

    /** Who calls this method in the code at all (reached or not), and who calls those, up to 3 levels: finds the first link nobody reaches. */
    private static String callerChain(CallGraph g, Map<String, List<String>> all, String key) {
        StringBuilder sb = new StringBuilder();
        Set<String> seen = new HashSet<>();
        List<String> level = new ArrayList<>();
        level.add(key);
        seen.add(key);
        for (int depth = 1; depth <= 3 && !level.isEmpty(); depth++) {
            List<String> next = new ArrayList<>();
            for (String k : level) {
                List<String> cs = all.get(k);
                if (cs == null || cs.isEmpty()) {
                    sb.append("\n          ").append(indent(depth)).append(shortName(k)).append(" <- no caller in the app code (framework / XML / reflection / listener object?)");
                    continue;
                }
                for (String c : cs) {
                    if (!seen.add(c)) continue;
                    boolean r = g.isReachable(c);
                    sb.append("\n          ").append(indent(depth)).append(shortName(k)).append(" <- ").append(shortName(c)).append(r ? " (reached)" : " (NOT reached)");
                    if (!r) next.add(c);
                    if (sb.length() > 1800) return sb.toString() + "\n          ...";
                }
            }
            level = next;
        }
        return sb.toString();
    }

    private static String indent(int d) {
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < d; i++) sb.append("  ");
        return sb.toString();
    }

    /** What the last reached method touches: class constants, framework calls, objects it creates or loads. Enough to see the missing link. */
    private static String summary(CallGraph g, String key) {
        MethodIr m = g.methods.get(key);
        if (m == null) return "";
        Set<String> consts = new LinkedHashSet<>(), fw = new LinkedHashSet<>(), app = new LinkedHashSet<>(), objs = new LinkedHashSet<>();
        for (Insn in : m.insns) {
            if (in.kind == Insn.Kind.CONST && in.op.equals("const-class")) consts.add(in.ref);
            else if (in.kind == Insn.Kind.NEW_INSTANCE) objs.add("new " + shortType(in.ref));
            else if (in.kind == Insn.Kind.FIELD_GET && in.op.startsWith("sget")) objs.add("sget " + in.ref);
            else if (in.kind == Insn.Kind.INVOKE) {
                String o = in.targetOwner();
                String t = shortType(o) + "." + in.targetName() + (in.targetSig().contains("Ljava/lang/Class;") ? "(..Class..)" : "");
                if (o.startsWith("Landroid/") || o.startsWith("Ljava/") || o.startsWith("Landroidx/") || o.startsWith("Lkotlin/")) fw.add(t);
                else app.add(t);
            }
        }
        StringBuilder sb = new StringBuilder("\n      last reached hop ").append(shortName(key)).append(" has:");
        sb.append("\n        const-class: ").append(consts.isEmpty() ? "none" : joinShort(consts, 8));
        sb.append("\n        creates/loads: ").append(objs.isEmpty() ? "none" : joinShort(objs, 8));
        sb.append("\n        app calls: ").append(app.isEmpty() ? "none" : joinShort(app, 10));
        sb.append("\n        framework calls: ").append(fw.isEmpty() ? "none" : joinShort(fw, 14));
        return sb.toString();
    }

    private static String shortType(String t) {
        if (t == null) return "";
        String c = t.startsWith("L") && t.endsWith(";") ? t.substring(1, t.length() - 1) : t;
        int s = c.lastIndexOf('/');
        return s < 0 ? c : c.substring(s + 1);
    }

    private static String joinShort(Collection<String> c, int max) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String x : c) {
            if (n++ >= max) { sb.append(", ... +").append(c.size() - max); break; }
            if (sb.length() > 0) sb.append(", ");
            sb.append(x.contains("->") ? shortName(x) : x.startsWith("L") && x.endsWith(";") && !x.contains(" ") ? shortType(x) : x);
        }
        return sb.toString();
    }

    private static boolean inEntryClass(String key, Set<String> entryClasses) {
        int i = key.indexOf("->");
        if (i < 0) return false;
        String t = key.substring(0, i);
        if (entryClasses.contains(t)) return true;
        int d = t.indexOf('$');
        return d > 0 && entryClasses.contains(t.substring(0, d) + ";");
    }

    private static String path(CallGraph g, String key) {
        List<String> p = g.pathTo(key);
        if (p.isEmpty()) return "(reachable, path not found)";
        StringBuilder sb = new StringBuilder();
        for (String k : p) {
            if (sb.length() > 0) sb.append(" -> ");
            sb.append(shortName(k));
        }
        return sb.toString();
    }

    private static String shortName(String key) {
        int i = key.indexOf("->");
        if (i < 0) return key;
        String c = key.substring(1, i).replace(";", "");
        int s = c.lastIndexOf('/');
        int p = key.indexOf('(', i);
        return (s < 0 ? c : c.substring(s + 1)) + "." + key.substring(i + 2, p < 0 ? key.length() : p);
    }

    private static String one(String s) {
        String t = s.replace('\n', ' ');
        return t.length() > 240 ? t.substring(0, 240) + "..." : t;
    }

    private static int count(int[][] t) {
        int c = 0;
        for (int[] r : t) for (int v : r) c += v;
        return c;
    }

    private static String pad(int v) {
        String s = String.valueOf(v);
        StringBuilder sb = new StringBuilder();
        for (int i = s.length(); i < 14; i++) sb.append(' ');
        return sb.append(s).toString();
    }

    private static void section(StringBuilder sb, String title, List<String> lines, int max) {
        sb.append("\n").append(title).append(": ").append(lines.size()).append('\n');
        for (int i = 0; i < lines.size() && i < max; i++) sb.append("  - ").append(lines.get(i)).append('\n');
        if (lines.size() > max) sb.append("  ... ").append(lines.size() - max).append(" more\n");
    }
}
