package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.List;

/**
 * 0.57.0 (P1 step 3): picks WHICH classes of a big app the SSA taint parses.
 *
 * Why: the IR keeps every parsed class in memory, so 0.56.0 skipped the whole SSA pass for apps with more than 6000 non-library classes,
 * and those are exactly the real-world apps. Here one cheap pass over the text of every class (the text is read and dropped, nothing but
 * small int arrays is kept) finds the classes that touch a taint source or a taint sink, and only those plus their neighbours are parsed.
 *
 * What is selected, in priority order, until {@code maxClasses} is reached:
 *   A  classes with a source AND a sink (the whole flow can sit inside one class)
 *   B  classes with a source OR a sink
 *   C  entry components (exported activities, services ...), so the entry path can start
 *   D  callees of A and B (helpers that return or forward the value)
 *   E  callers of A and B (the way in from the entries)
 *   F  callers of E (one more step towards the entries)
 *   G  (0.58.0) the entry slice: every class on a path from an entry to a marked class, at ANY depth (see {@link CallSkeleton})
 *   S  (0.58.0) supertypes of everything above (inherited methods, interface defaults)
 *   H  (0.58.0) callees of D (a helper that calls a helper)
 * A source is an Intent getter, a SharedPreferences getter, or a class whose superclass name ends in "Provider;" (ContentProvider
 * parameters are sources). A sink is any API in the sink table of {@link TaintIr}.
 *
 * Honest limit: a flow whose chain leaves this set (more than 2 hops from a marked class) is not seen, and a path from an entry that
 * passes through an unselected class is reported as "not reachable". The Kotlin side says so in the finding when the scope is reduced.
 */
public final class ScopePlanner {

    private ScopePlanner() {
    }

    /** Text access without holding the texts: the caller reads a class on demand and the planner drops it again. */
    public interface Source {
        int count();

        String type(int i);

        String text(int i);

        default boolean cancelled() {
            return false;
        }
    }

    public static final class Plan {
        public final int[] selected;     // ascending indexes into the Source
        public final int total;          // classes offered
        public final int marked;         // classes with a source or a sink (tiers A + B)
        public final int entries;        // entry components found among the classes
        public final int slice;          // 0.58.0: classes on some entry -> marked class path (before the cap)
        public final boolean capped;     // candidates were left out because of maxClasses
        public final boolean cancelled;

        Plan(int[] selected, int total, int marked, int entries, int slice, boolean capped, boolean cancelled) {
            this.selected = selected;
            this.total = total;
            this.marked = marked;
            this.entries = entries;
            this.slice = slice;
            this.capped = capped;
            this.cancelled = cancelled;
        }
    }

    public static Plan plan(Source src, Collection<String> entryTypes, int maxClasses) {
        CallSkeleton sk = CallSkeleton.build(src, entryTypes);
        if (sk == null) return new Plan(new int[0], src.count(), 0, 0, 0, false, true);
        int n = sk.n;
        int[][] callees = new int[n][], callers = new int[n][];
        for (int i = 0; i < n; i++) {
            callees[i] = sk.calleesOf(i);
            callers[i] = sk.callersOf(i);
        }
        BitSet entry = sk.entry;

        List<List<Integer>> tiers = new ArrayList<>();
        List<Integer> a = new ArrayList<>(), b = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            if (sk.flags[i] == (CallSkeleton.SRC | CallSkeleton.SINK)) a.add(i);
            else if (sk.flags[i] != 0) b.add(i);
        }
        int marked = a.size() + b.size();
        List<Integer> c = new ArrayList<>();
        for (int i = entry.nextSetBit(0); i >= 0; i = entry.nextSetBit(i + 1)) c.add(i);
        tiers.add(a);
        tiers.add(b);
        tiers.add(c);
        List<Integer> core = new ArrayList<>(a);
        core.addAll(b);
        List<Integer> d = neighbours(core, callees);
        tiers.add(d);
        List<Integer> e = neighbours(core, callers);
        tiers.add(e);
        tiers.add(neighbours(e, callers));

        // 0.58.0: the entry slice = every class that an entry can reach AND that can reach a marked class. This replaces the old
        // "callers of callers" depth limit for the way in: a flow whose entry is 5 hops away keeps its whole path.
        BitSet markedSet = new BitSet(n);
        for (int i : core) markedSet.set(i);
        List<Integer> slice = new ArrayList<>();
        if (!entry.isEmpty() && !markedSet.isEmpty()) {
            BitSet fwd = sk.forward(entry);
            BitSet bwd = sk.backward(markedSet);
            fwd.and(bwd);
            for (int i = fwd.nextSetBit(0); i >= 0; i = fwd.nextSetBit(i + 1)) slice.add(i);
        }
        tiers.add(slice);
        // supertypes of everything chosen so far: CallGraph walks the super chain to find inherited methods and interface defaults
        BitSet chosen = new BitSet(n);
        for (List<Integer> t : tiers) for (int i : t) chosen.set(i);
        List<Integer> supers = new ArrayList<>();
        java.util.ArrayDeque<Integer> q = new java.util.ArrayDeque<>();
        for (int i = chosen.nextSetBit(0); i >= 0; i = chosen.nextSetBit(i + 1)) q.add(i);
        while (!q.isEmpty()) {
            int x = q.poll();
            for (int p : sk.parentsOf(x)) {
                if (chosen.get(p)) continue;
                chosen.set(p);
                supers.add(p);
                q.add(p);
            }
        }
        tiers.add(supers);
        // one more step for the value that comes back from a helper: callees of the helpers
        tiers.add(neighbours(d, callees));

        BitSet sel = new BitSet(n);
        int count = 0;
        boolean capped = false;
        for (List<Integer> tier : tiers) {
            for (int i : tier) {
                if (sel.get(i)) continue;
                if (count >= maxClasses) {
                    capped = true;
                    continue;
                }
                sel.set(i);
                count++;
            }
        }
        int[] out = new int[count];
        int k = 0;
        for (int i = sel.nextSetBit(0); i >= 0; i = sel.nextSetBit(i + 1)) out[k++] = i;
        return new Plan(out, n, marked, entry.cardinality(), slice.size(), capped, false);
    }

    // ======================================================================================== 0.59.0: groups

    /** Result of {@link #groups}: the whole app as a list of bounded groups of classes. */
    public static final class Groups {
        public final List<int[]> groups;      // ascending indexes into the Source, best group first
        public final int total;               // classes offered
        public final int marked;              // classes with a source or a sink
        public final int entries;
        public final int skippedSinks;        // 0.59.1: sink-only classes with no source class within 2 hops (left out on purpose)
        public final int unreachable;         // 0.59.2: marked classes no entry reaches (left out on purpose)
        public final int cappedGroups;        // groups whose closure was cut at maxPerGroup (a single marked class with a huge neighbourhood)
        public final boolean cancelled;
        /** 0.62.0: classes left out of capped groups (sum over groups), and hub classes (very many callers) not expanded while building closures. */
        public int droppedClasses;
        public int hubs;
        /** 0.63.0: size of the biggest closure before the cap (selected + cut), over all groups: shows how far the cap is from what a group wants. */
        public int maxClosure;
        /** 0.64.0: new classes each tier added in the biggest closure (before the cap), e.g. "callees=12 callers=800 ...". */
        public String maxClosureTiers = "";
        /** 0.65.0: marked classes (source / sink) with very many callers whose callers are not expanded in their own group (only one entry path is kept). */
        public int markedHubs;

        Groups(List<int[]> groups, int total, int marked, int entries, int cappedGroups, int skippedSinks, int unreachable, boolean cancelled) {
            this.groups = groups;
            this.total = total;
            this.marked = marked;
            this.entries = entries;
            this.cappedGroups = cappedGroups;
            this.skippedSinks = skippedSinks;
            this.unreachable = unreachable;
            this.cancelled = cancelled;
        }
    }

    /**
     * 0.59.0 (P1 step 4, part 2): covers the WHOLE app with groups that each fit in memory, instead of one selection cut at a total cap.
     * Every class with a source or a sink lands in exactly one group's "batch"; each group also gets what a flow around that batch
     * needs: callees (2 hops), the entry slice of the batch (classes on a path entry -> batch), callers (2 hops, for code no entry
     * reaches) and supertypes. Groups are built from the best marked classes first (source AND sink in one class), so a caller can
     * analyse them in order and show flows while the rest is still running. A group never exceeds {@code maxPerGroup}.
     * Honest limit: groups do not share summaries, so a flow whose chain leaves its group (more than 2 hops from the batch) is not seen.
     */
    /** 0.62.0: a class with at least this many callers (0.63.0: 60, was 200) (Kotlin / logging / util helpers) is a hub: it joins a closure but its own neighbours do not. */
    static final int HUB_CALLERS = 60;
    /**
     * 0.101.1 (fan-out twin of HUB_CALLERS): an UNMARKED class that calls at least this many classes (a Dagger / Hilt component, a big router) joins a closure as a callee but
     * its own callees are not pulled in at the second hop. Marked classes are never callee hubs. Default 100 because on 5 real apps (Axis Pay, a wallet app, Fossify, Jellyfin, OVAA)
     * the flow set was identical at 100 (analysis CPU -10% to -20%); 200 added one flow on Axis Pay and 50 swapped one, so this is a measured choice, not a law.
     * -Dapkrelab.hubCallees=0 switches it off (the old behaviour) for comparisons.
     */
    static final int HUB_CALLEES = Integer.getInteger("apkrelab.hubCallees", 100);
    /** 0.66.0: number of node-disjoint shortest entry paths kept per marked class (reach). */
    static final int ENTRY_PATHS = 3;

    public static Groups groups(Source src, Collection<String> entryTypes, int maxPerGroup) {
        return groups(src, entryTypes, maxPerGroup, false, false, false);
    }

    /**
     * @param intentOnly    0.59.2: SharedPreferences getters are not sources for the grouping (only Intent getters and Provider classes)
     * @param nearOnly      0.59.1: a sink-only class counts only when a source class is within 2 hops (lossy: off by default since 0.59.3)
     * @param reachableOnly 0.59.2: classes that no entry component can reach (class-level skeleton) are left out; ignored when no entry is known
     */
    public static Groups groups(Source src, Collection<String> entryTypes, int maxPerGroup, boolean intentOnly, boolean reachableOnly,
                                boolean nearOnly) {
        CallSkeleton sk = CallSkeleton.build(src, entryTypes, !intentOnly);
        if (sk == null) return new Groups(new ArrayList<int[]>(), src.count(), 0, 0, 0, 0, 0, true);
        int n = sk.n;
        // 0.59.1: a flow needs a SOURCE. Sink APIs (File, URL ...) are in most classes of a real app, so a sink-only class counts only
        // when a source class is within 2 hops (either direction). Without this a 40k-class app made 467 groups and ran for over an hour.
        int[][] ce = new int[n][], cr = new int[n][];
        for (int i = 0; i < n; i++) {
            ce[i] = sk.calleesOf(i);
            cr[i] = sk.callersOf(i);
        }
        BitSet hub = new BitSet(n);
        for (int i = 0; i < n; i++) if (cr[i].length >= HUB_CALLERS && (sk.flags[i] == 0)) hub.set(i);   // a marked class is never a hub: its flows must be found
        // 0.65.0: a MARKED class with very many callers (a prefs / logging / util wrapper) is expanded in its OWN group only on the callee side.
        // Its callers are not pulled in: a caller that has a sink is itself marked and gets its own group, where this class is a direct callee,
        // so the flow "source in the wrapper -> sink in the caller" is still seen there. JustMarkets 0.64.0: one such class brought 2448 callers.
        BitSet markedHub = new BitSet(n);
        for (int i = 0; i < n; i++) if (cr[i].length >= HUB_CALLERS && sk.flags[i] != 0) markedHub.set(i);
        BitSet calleeHub = new BitSet(n);
        if (HUB_CALLEES > 0) for (int i = 0; i < n; i++) if (ce[i].length >= HUB_CALLEES && sk.flags[i] == 0) calleeHub.set(i);
        BitSet near = new BitSet(n), frontier = new BitSet(n);
        for (int i = 0; i < n; i++) if ((sk.flags[i] & CallSkeleton.SRC) != 0) {
            near.set(i);
            frontier.set(i);
        }
        for (int hop = 0; hop < 2; hop++) {
            BitSet next = new BitSet(n);
            for (int i = frontier.nextSetBit(0); i >= 0; i = frontier.nextSetBit(i + 1)) {
                for (int j : ce[i]) if (!near.get(j)) { near.set(j); next.set(j); }
                for (int j : cr[i]) if (!near.get(j)) { near.set(j); next.set(j); }
            }
            frontier = next;
        }
        BitSet fwdEntry = sk.entry.isEmpty() ? new BitSet(n) : sk.forward(sk.entry);
        boolean restrict = reachableOnly && !sk.entry.isEmpty();
        int unreachable = 0;
        List<Integer> order = new ArrayList<>();
        int skipped = 0;
        for (int i = 0; i < n; i++) if (sk.flags[i] == (CallSkeleton.SRC | CallSkeleton.SINK)) {
            if (restrict && !fwdEntry.get(i)) unreachable++;
            else order.add(i);
        }
        for (int i = 0; i < n; i++) if ((sk.flags[i] & CallSkeleton.SRC) != 0 && sk.flags[i] != (CallSkeleton.SRC | CallSkeleton.SINK)) {
            if (restrict && !fwdEntry.get(i)) unreachable++;
            else order.add(i);
        }
        for (int i = 0; i < n; i++) if (sk.flags[i] == CallSkeleton.SINK) {
            if (nearOnly && !near.get(i)) skipped++;
            else if (restrict && !fwdEntry.get(i)) unreachable++;
            else order.add(i);
        }
        int[][] callees = new int[n][], callers = new int[n][];
        for (int i = 0; i < n; i++) {
            callees[i] = sk.calleesOf(i);
            callers[i] = sk.callersOf(i);
        }
        java.util.Map<Integer, int[]> pathCache = new java.util.HashMap<>();   // 0.66.0: entry paths per marked class, computed once
        List<int[]> out = new ArrayList<>();
        int capped = 0, dropped = 0, maxClosure = 0;
        String maxTiers = "";
        int p = 0, guess = 64;
        while (p < order.size()) {
            if (src.cancelled()) return withStats(new Groups(out, n, order.size(), sk.entry.cardinality(), capped, skipped, unreachable, true), dropped, hub, markedHub, maxClosure, maxTiers);
            int size = Math.min(guess, order.size() - p);
            Closure c = closure(sk, fwdEntry, hub, markedHub, calleeHub, pathCache, callees, callers, order.subList(p, p + size), maxPerGroup);
            while (c.capped && size > 1) {
                size = Math.max(1, size / 2);
                c = closure(sk, fwdEntry, hub, markedHub, calleeHub, pathCache, callees, callers, order.subList(p, p + size), maxPerGroup);
            }
            if (c.capped) { capped++; dropped += c.dropped; }
            if (c.total() > maxClosure) { maxClosure = c.total(); maxTiers = c.tiers; }
            out.add(c.selected);
            p += size;
            guess = c.capped ? size : Math.max(size * 2, 1);
        }
        return withStats(new Groups(out, n, order.size(), sk.entry.cardinality(), capped, skipped, unreachable, false), dropped, hub, markedHub, maxClosure, maxTiers);
    }

    private static Groups withStats(Groups g, int dropped, BitSet hub, BitSet markedHub, int maxClosure, String maxTiers) {
        g.markedHubs = markedHub.cardinality();
        g.maxClosureTiers = maxTiers;
        g.maxClosure = maxClosure;
        g.droppedClasses = dropped;
        g.hubs = hub.cardinality();
        return g;
    }

    private static final class Closure {
        final int[] selected;
        final boolean capped;
        final int dropped;
        final String tiers;
        int total() { return selected.length + dropped; }

        Closure(int[] selected, boolean capped, int dropped, String tiers) {
            this.tiers = tiers;
            this.selected = selected;
            this.capped = capped;
            this.dropped = dropped;
        }
    }

    private static Closure closure(CallSkeleton sk, BitSet fwdEntry, BitSet hub, BitSet markedHub, BitSet calleeHub, java.util.Map<Integer, int[]> pathCache, int[][] callees, int[][] callers, List<Integer> batch, int max) {
        int n = sk.n;
        // 0.65.0: a marked hub reached as a NEIGHBOUR (caller of the batch, ...) joins the closure but is not expanded, like an unmarked hub
        BitSet hubAll = (BitSet) hub.clone();
        hubAll.or(markedHub);
        BitSet batchSet = new BitSet(n);
        for (int i : batch) batchSet.set(i);
        // 0.63.0: tier order changed. The entry slice (every class on a path from an entry to the batch) used to come 3rd and filled the
        // cap on a real app (JustMarkets: 1.6M classes cut), pushing out the callers and supertypes the taint needs. It is now LAST:
        // it mostly adds the entry path (reach), the neighbourhood that the data flow needs comes first.
        List<List<Integer>> tiers = new ArrayList<>();
        tiers.add(new ArrayList<>(batch));
        List<Integer> d1 = neighbours(batch, callees, null);
        tiers.add(d1);
        List<Integer> c1 = neighbours(batch, callers, markedHub);   // 0.65.0: callers of a marked hub are not expanded
        tiers.add(c1);
        tiers.add(neighbours(c1, callers, hubAll));
        BitSet chosen = new BitSet(n);
        for (List<Integer> t : tiers) for (int i : t) chosen.set(i);
        tiers.add(supertypesOf(sk, chosen));
        BitSet hubOut = (BitSet) hubAll.clone();
        hubOut.or(calleeHub);                      // 0.101.1: empty unless the experiment is on
        tiers.add(neighbours(d1, callees, hubOut));
        // 0.66.0: the "slice" is no longer EVERY class on any path entry -> batch (JustMarkets 0.65.0: 6409 of the 7929 classes of the biggest
        // closure, because the class-level graph links most of the app to every entry). It only serves `reach`, not the data flow, so it is now
        // up to ENTRY_PATHS shortest entry chains per marked class (node-disjoint), computed once per class. Data-flow tiers are unchanged.
        List<Integer> slice = new ArrayList<>();
        BitSet bwd = new BitSet(n);
        for (int h : batch) {
            int[] pth = pathCache.get(h);
            if (pth == null) {
                java.util.LinkedHashSet<Integer> acc = new java.util.LinkedHashSet<>();
                BitSet blocked = new BitSet(n);
                for (int k = 0; k < ENTRY_PATHS; k++) {
                    List<Integer> one = entryPath(sk, callers, h, blocked);
                    if (one.isEmpty()) break;
                    for (int x : one) { acc.add(x); blocked.set(x); }
                }
                pth = new int[acc.size()];
                int j = 0;
                for (int x : acc) pth[j++] = x;
                pathCache.put(h, pth);
            }
            for (int x : pth) bwd.set(x);
        }
        for (int i = bwd.nextSetBit(0); i >= 0; i = bwd.nextSetBit(i + 1)) slice.add(i);
        tiers.add(slice);
        BitSet sliceSet = new BitSet(n);
        for (int i : slice) sliceSet.set(i);
        sliceSet.andNot(chosen);
        tiers.add(supertypesOf(sk, sliceSet));
        // 0.64.0: every tier gets a share of the cap first (so one huge tier cannot starve the others), then what is left is filled in tier order.
        // JustMarkets 0.63.0: closures of 7000-8800 classes in every group, so which tier is the big one decides what survives the cap.
        double[] share = {1.0, 0.20, 0.20, 0.20, 0.13, 0.13, 0.13, 0.13};
        String[] names = {"batch", "callees", "callers", "callers2", "supers", "callees2", "slice", "supers2"};
        BitSet sel = new BitSet(n), lost = new BitSet(n), seenAll = new BitSet(n);
        int count = 0;
        int[] added = new int[tiers.size()];
        for (int t = 0; t < tiers.size(); t++) {
            for (int i : tiers.get(t)) if (!seenAll.get(i)) { seenAll.set(i); added[t]++; }
        }
        for (int t = 0; t < tiers.size(); t++) {
            int limit = t == 0 ? Integer.MAX_VALUE : Math.max(1, (int) (max * share[t]));
            int taken = 0;
            for (int i : tiers.get(t)) {
                if (sel.get(i) || taken >= limit || count >= max) continue;
                sel.set(i);
                count++;
                taken++;
            }
        }
        boolean capped = false;
        for (List<Integer> tier : tiers) {
            for (int i : tier) {
                if (sel.get(i)) continue;
                if (count >= max) {
                    capped = true;
                    lost.set(i);
                    continue;
                }
                sel.set(i);
                count++;
            }
        }
        int[] res = new int[count];
        int k = 0;
        for (int i = sel.nextSetBit(0); i >= 0; i = sel.nextSetBit(i + 1)) res[k++] = i;
        StringBuilder tn = new StringBuilder();
        for (int t = 1; t < added.length; t++) tn.append(t > 1 ? " " : "").append(names[t]).append('=').append(added[t]);
        return new Closure(res, capped, lost.cardinality(), tn.toString());
    }

    /** 0.65.0: classes on ONE shortest caller chain from {@code start} up to an entry class (start excluded, entry included); empty when none or start is an entry. */
    static List<Integer> entryPath(CallSkeleton sk, int[][] callers, int start) {
        return entryPath(sk, callers, start, new BitSet());
    }

    /** Same, never passing through a class of {@code blocked} (used to find node-disjoint alternative paths). */
    static List<Integer> entryPath(CallSkeleton sk, int[][] callers, int start, BitSet blocked) {
        List<Integer> path = new ArrayList<>();
        if (sk.entry.isEmpty() || sk.entry.get(start)) return path;
        java.util.HashMap<Integer, Integer> parent = new java.util.HashMap<>();
        java.util.ArrayDeque<Integer> q = new java.util.ArrayDeque<>();
        parent.put(start, -1);
        q.add(start);
        int found = -1;
        while (!q.isEmpty() && found < 0) {
            int x = q.poll();
            for (int c : callers[x]) {
                if (parent.containsKey(c) || blocked.get(c)) continue;
                parent.put(c, x);
                if (sk.entry.get(c)) { found = c; break; }
                q.add(c);
            }
        }
        for (int x = found; x >= 0 && x != start; x = parent.get(x)) path.add(x);
        return path;
    }

    /** Supertypes (transitively) of every class in {@code from}, without the classes already in it. */
    private static List<Integer> supertypesOf(CallSkeleton sk, BitSet from) {
        BitSet chosen = (BitSet) from.clone();
        List<Integer> supers = new ArrayList<>();
        java.util.ArrayDeque<Integer> q = new java.util.ArrayDeque<>();
        for (int i = from.nextSetBit(0); i >= 0; i = from.nextSetBit(i + 1)) q.add(i);
        while (!q.isEmpty()) {
            int x = q.poll();
            for (int par : sk.parentsOf(x)) {
                if (chosen.get(par)) continue;
                chosen.set(par);
                supers.add(par);
                q.add(par);
            }
        }
        return supers;
    }

    private static List<Integer> neighbours(List<Integer> from, int[][] edges) {
        return neighbours(from, edges, null);
    }

    private static List<Integer> neighbours(List<Integer> from, int[][] edges, BitSet hub) {
        BitSet seen = new BitSet();
        for (int i : from) seen.set(i);
        List<Integer> out = new ArrayList<>();
        for (int i : from) {
            if (hub != null && hub.get(i)) continue;     // 0.62.0: a hub joins the closure but its neighbours do not
            for (int j : edges[i]) {
                if (seen.get(j)) continue;
                seen.set(j);
                out.add(j);
            }
        }
        return out;
    }
}
