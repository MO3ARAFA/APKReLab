package dev.apkrelab.ir;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 0.58.0 (P1 step 4, part 1): a LIGHT class-level call graph of the whole app. Nothing but small int arrays stays in memory.
 *
 * One pass over the text of every class (the text is read through {@link ScopePlanner.Source} and dropped right after) records:
 * flags (taint source / sink inside the class), the app classes it calls, and its super / interface types. From that:
 *   callees[i]  classes that class i calls. Edges come from invoke owners and from const-class (explicit ICC: Intent(ctx, X.class)).
 *               An invoke on type X also links X's app ANCESTORS (the method may be inherited) and its app DESCENDANTS
 *               (virtual / interface call: CHA at class level; skipped when X has more than {@link #MAX_DESCENDANTS}).
 *               Every class also has an edge to its direct supertypes (it needs them to resolve inherited methods).
 *   callers[i]  the reverse edges.
 * Over-approximation is intended: the skeleton only decides WHICH classes get parsed, so an extra edge costs a few classes, a missing one
 * can lose a flow. The precise (method level, RTA) graph is still built by {@link CallGraph} over the selected classes.
 *
 * Memory: about 4 bytes per edge + 16 bytes per class. 42k classes with 20 edges each is a few MB.
 */
public final class CallSkeleton {

    public static final int SRC = 1, SINK = 2;
    /** A type with more app descendants than this is not expanded (a huge base class would link half of the app). */
    public static final int MAX_DESCENDANTS = 64;

    private static final Pattern INVOKE = Pattern.compile("invoke-[\\w/-]+\\s+\\{[^}]*\\},\\s*(L[^;\\s]+;)->([^(\\s]+)\\(");
    private static final Pattern CONST_CLASS = Pattern.compile("const-class\\s+[vp]\\d+,\\s*(L[^;\\s]+;)");
    private static final Pattern SUPER = Pattern.compile("^\\.super (L[^;\\s]+;)", Pattern.MULTILINE);
    private static final Pattern IFACE = Pattern.compile("^\\.implements (L[^;\\s]+;)", Pattern.MULTILINE);

    public final int n;
    public final String[] types;
    public final byte[] flags;
    public final BitSet entry;
    private final int[][] callees;
    private final int[][] callers;
    private final int[][] parents;
    public final long edges;

    private CallSkeleton(int n, String[] types, byte[] flags, BitSet entry, int[][] callees, int[][] callers, int[][] parents, long edges) {
        this.n = n;
        this.types = types;
        this.flags = flags;
        this.entry = entry;
        this.callees = callees;
        this.callers = callers;
        this.parents = parents;
        this.edges = edges;
    }

    public int[] calleesOf(int i) {
        return callees[i];
    }

    public int[] callersOf(int i) {
        return callers[i];
    }

    /** Direct app supertypes (super class + interfaces) of class i. */
    public int[] parentsOf(int i) {
        return parents[i];
    }

    /** Classes with a taint source or a taint sink. */
    public BitSet marked() {
        BitSet b = new BitSet(n);
        for (int i = 0; i < n; i++) if (flags[i] != 0) b.set(i);
        return b;
    }

    /** Everything reachable from {@code from} by following callees (includes {@code from}). */
    public BitSet forward(BitSet from) {
        return walk(from, callees);
    }

    /** Everything that can reach {@code from} by following callers (includes {@code from}). */
    public BitSet backward(BitSet from) {
        return walk(from, callers);
    }

    /** 0.62.0: like {@link #backward(BitSet)}, but a class in {@code hubs} that is found on the way is kept and NOT expanded (the start set always is). */
    public BitSet backward(BitSet from, BitSet hubs) {
        return walk(from, callers, hubs);
    }

    private BitSet walk(BitSet from, int[][] edges) {
        return walk(from, edges, null);
    }

    private BitSet walk(BitSet from, int[][] edges, BitSet hubs) {
        BitSet seen = (BitSet) from.clone();
        ArrayDeque<Integer> q = new ArrayDeque<>();
        for (int i = from.nextSetBit(0); i >= 0; i = from.nextSetBit(i + 1)) q.add(i);
        while (!q.isEmpty()) {
            int x = q.poll();
            for (int y : edges[x]) {
                if (seen.get(y)) continue;
                seen.set(y);
                if (hubs == null || !hubs.get(y)) q.add(y);
            }
        }
        return seen;
    }

    /** @return the skeleton, or {@code null} when {@code src.cancelled()} turned true during the pass. */
    public static CallSkeleton build(ScopePlanner.Source src, Collection<String> entryTypes) {
        return build(src, entryTypes, true);
    }

    /** @param includePrefs false (0.59.2): SharedPreferences getters do not count as sources (weakest source, findings end up LOW anyway) */
    public static CallSkeleton build(ScopePlanner.Source src, Collection<String> entryTypes, boolean includePrefs) {
        int n = src.count();
        String[] types = new String[n];
        Map<String, Integer> idx = new HashMap<>(n * 2 + 1);
        for (int i = 0; i < n; i++) {
            types[i] = src.type(i);
            idx.put(types[i], i);
        }
        Set<String> sinkOwners = TaintIr.sinkOwners();
        byte[] flags = new byte[n];
        int[][] direct = new int[n][];     // classes named by an invoke / const-class
        int[][] parents = new int[n][];    // super + interfaces that are app classes
        for (int i = 0; i < n; i++) {
            if (src.cancelled()) return null;
            String text = src.text(i);
            if (text == null) text = "";
            int f = 0;
            Set<Integer> refs = new HashSet<>();
            Set<Integer> par = new HashSet<>();
            Matcher sm = SUPER.matcher(text);
            if (sm.find()) {
                String s = sm.group(1);
                if (s.endsWith("Provider;")) f |= SRC;
                Integer j = idx.get(s);
                if (j != null && j != i) par.add(j);
            }
            Matcher im = IFACE.matcher(text);
            while (im.find()) {
                Integer j = idx.get(im.group(1));
                if (j != null && j != i) par.add(j);
            }
            Matcher m = INVOKE.matcher(text);
            while (m.find()) {
                String owner = m.group(1), name = m.group(2);
                TaintIr.Tv tv = TaintIr.sourceOf(owner, name);
                if (tv != null && (includePrefs || tv.level >= 2)) f |= SRC;
                if (sinkOwners.contains(owner) && TaintIr.isSink(owner, name)) f |= SINK;
                Integer j = idx.get(owner);
                if (j != null && j != i) refs.add(j);
            }
            Matcher cm = CONST_CLASS.matcher(text);
            while (cm.find()) {
                Integer j = idx.get(cm.group(1));
                if (j != null && j != i) refs.add(j);
            }
            flags[i] = (byte) f;
            direct[i] = toArray(refs);
            parents[i] = toArray(par);
        }
        if (src.cancelled()) return null;

        // children = reverse of parents
        int[] cc = new int[n];
        for (int i = 0; i < n; i++) for (int p : parents[i]) cc[p]++;
        int[][] children = new int[n][];
        for (int i = 0; i < n; i++) children[i] = new int[cc[i]];
        int[] fill = new int[n];
        for (int i = 0; i < n; i++) for (int p : parents[i]) children[p][fill[p]++] = i;

        int[][][] descMemo = new int[n][][];          // memo: [0] = descendants, or a marker for "too many"
        boolean[] tooMany = new boolean[n];
        int[][] callees = new int[n][];
        long edges = 0;
        for (int i = 0; i < n; i++) {
            Set<Integer> out = new HashSet<>();
            for (int j : direct[i]) {
                out.add(j);
                addAncestors(j, parents, out);
                int[] d = descendants(j, children, descMemo, tooMany);
                if (d != null) for (int k : d) out.add(k);
            }
            for (int p : parents[i]) out.add(p);      // a class needs its supertypes to resolve what it inherits
            out.remove(i);
            callees[i] = toArray(out);
            edges += callees[i].length;
        }
        int[] cnt = new int[n];
        for (int i = 0; i < n; i++) for (int j : callees[i]) cnt[j]++;
        int[][] callers = new int[n][];
        for (int i = 0; i < n; i++) callers[i] = new int[cnt[i]];
        java.util.Arrays.fill(fill, 0);
        for (int i = 0; i < n; i++) for (int j : callees[i]) callers[j][fill[j]++] = i;

        BitSet entry = new BitSet(n);
        if (entryTypes != null) for (String t : entryTypes) {
            Integer j = idx.get(t);
            if (j != null) entry.set(j);
        }
        return new CallSkeleton(n, types, flags, entry, callees, callers, parents, edges);
    }

    private static void addAncestors(int j, int[][] parents, Set<Integer> out) {
        ArrayDeque<Integer> q = new ArrayDeque<>();
        q.add(j);
        Set<Integer> seen = new HashSet<>();
        seen.add(j);
        while (!q.isEmpty()) {
            int x = q.poll();
            for (int p : parents[x]) {
                if (!seen.add(p)) continue;
                out.add(p);
                q.add(p);
            }
        }
    }

    /** All app descendants of {@code j}, or null when there are more than {@link #MAX_DESCENDANTS}. Memoised per class. */
    private static int[] descendants(int j, int[][] children, int[][][] memo, boolean[] tooMany) {
        if (tooMany[j]) return null;
        if (memo[j] != null) return memo[j][0];
        if (children[j].length == 0) {
            memo[j] = new int[][]{new int[0]};
            return memo[j][0];
        }
        Set<Integer> seen = new HashSet<>();
        ArrayDeque<Integer> q = new ArrayDeque<>();
        q.add(j);
        while (!q.isEmpty()) {
            int x = q.poll();
            for (int c : children[x]) {
                if (!seen.add(c)) continue;
                if (seen.size() > MAX_DESCENDANTS) {
                    tooMany[j] = true;
                    return null;
                }
                q.add(c);
            }
        }
        memo[j] = new int[][]{toArray(seen)};
        return memo[j][0];
    }

    private static int[] toArray(Set<Integer> s) {
        int[] a = new int[s.size()];
        int k = 0;
        for (int v : s) a[k++] = v;
        java.util.Arrays.sort(a);
        return a;
    }

    /** Short text for the log / path bar. */
    public String stats() {
        int m = 0;
        for (int i = 0; i < n; i++) if (flags[i] != 0) m++;
        return n + " classes, " + edges + " edges, " + m + " marked, " + entry.cardinality() + " entries";
    }

    /** Helper for tests and callers that want the types of a set of indexes. */
    public List<String> typesOf(BitSet b) {
        List<String> out = new ArrayList<>();
        for (int i = b.nextSetBit(0); i >= 0; i = b.nextSetBit(i + 1)) out.add(types[i]);
        return out;
    }
}
