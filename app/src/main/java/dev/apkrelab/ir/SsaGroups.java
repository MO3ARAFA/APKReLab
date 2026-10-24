package dev.apkrelab.ir;

import java.lang.ref.SoftReference;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 0.60.0: runs the SSA taint over the groups of {@link ScopePlanner#groups} faster, with EXACTLY the same result as the one-thread loop.
 *
 * Nothing about the analysis changes (same groups, same call graph per group, same taint engine, same merge). What changes is the cost:
 *  1. a class is read from disk and parsed once, not once per group that contains it (groups overlap a lot: the entry slice and the
 *     neighbours of every batch). Kept with soft references, so the GC drops them first when memory gets tight;
 *  2. the SSA form of a method is built once ({@link SsaForm#buildCached}), not on every worklist re-run and every group;
 *  3. independent groups run on several threads. Each group still gets its own call graph and its own summaries, the IR is read-only
 *     after parsing, and the results are merged in group order, so the output does not depend on which thread was faster;
 *  4. a group that runs out of memory is not dropped: it is run again alone after the others finished.
 */
public final class SsaGroups {
    private SsaGroups() {
    }

    /** What the scanner provides. Indexes are the scanner's own class indexes. */
    public interface Host {
        /** Smali text of class {@code index}. May be called from several threads. */
        String text(int index) throws Exception;

        String type(int index);

        boolean cancelled();

        /** A group finished (done of total). May be called from several threads. */
        void progress(int done, int total);

        /** A group failed in a way that is not out-of-memory (it is skipped, like before). */
        void groupFailed();

        /** 0.69.1: exported components (class types) protected by a signature-level permission; empty = none known. */
        default Collection<String> guardedEntries() {
            return java.util.Collections.emptyList();
        }

        /** 0.104.0: where finished groups are kept between scans of the same app; null = no cache (the default: nothing changes for a host that does not ask). */
        default GroupCache groupCache() {
            return null;
        }

        /** 0.104.0: names the engine in the cache key (the app's version code). It MUST change whenever a result could change. */
        default String engineId() {
            return "";
        }
    }

    public static final class Picked {
        public final SsaBridge.Item item;
        public final int classIndex;

        Picked(SsaBridge.Item item, int classIndex) {
            this.item = item;
            this.classIndex = classIndex;
        }
    }

    public static final class Result {
        public final List<Picked> picked = new ArrayList<>();
        public int groupsTotal, groupsDone, groupsRetried, threads;
        /** 0.104.0: groups whose result came from the cache (no parsing, no analysis). */
        public int groupsCached;
        /** 0.66.2: time summed over all worker threads: reading + parsing classes, and building the call graph + SSA + taint. */
        public long parseMs, analyseMs;
        public boolean stopped;
        /** 0.66.5: measurement summed over all groups (taint losses, caps hit, slowest methods). Changes no result. */
        public final TaintIr.Stats stats = new TaintIr.Stats();
    }

    /**
     * @param groups    class indexes of each group, in the order they were planned (best first)
     * @param maxPicked the merge keeps at most this many distinct flows (200 in the app)
     * @param threads   worker threads; 1 = same thread as the caller. Clamped to the number of groups
     */
    public static Result run(List<List<Integer>> groups, Collection<String> entries, Collection<TaintIr.Old> old,
                             Host host, int maxPicked, int threads) {
        final int n = groups.size();
        final Result res = new Result();
        res.groupsTotal = n;
        final int nt = Math.max(1, Math.min(threads, n));
        res.threads = nt;
        final ConcurrentHashMap<Integer, SoftReference<ClassIr>> cache = new ConcurrentHashMap<>();
        @SuppressWarnings("unchecked")
        final List<SsaBridge.Item>[] items = new List[n];
        final boolean[] oom = new boolean[n];
        final AtomicInteger next = new AtomicInteger(0);
        final AtomicInteger done = new AtomicInteger(0);
        final Throwable[] fatal = new Throwable[1];
        final AtomicLong parseNs = new AtomicLong(), analyseNs = new AtomicLong();
        final AtomicInteger cached = new AtomicInteger(0);
        final GroupCache gc = host.groupCache();
        final String[] keys = gc == null ? null : groupKeys(groups, entries, old, host);

        if (nt == 1) {
            for (int gi = 0; gi < n; gi++) {
                if (host.cancelled()) break;
                items[gi] = runOne(groups.get(gi), entries, old, host, cache, n == 1, oom, gi, parseNs, analyseNs, res.stats, gc, keys == null ? null : keys[gi], cached);
                if (items[gi] != null) host.progress(done.incrementAndGet(), n);
            }
        } else {
            Thread[] ts = new Thread[nt];
            for (int t = 0; t < nt; t++) {
                ts[t] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        while (true) {
                            if (host.cancelled()) return;
                            int gi = next.getAndIncrement();
                            if (gi >= n) return;
                            try {
                                items[gi] = runOne(groups.get(gi), entries, old, host, cache, false, oom, gi, parseNs, analyseNs, res.stats, gc, keys == null ? null : keys[gi], cached);
                            } catch (Throwable t) {
                                synchronized (fatal) {
                                    if (fatal[0] == null) fatal[0] = t;
                                }
                                return;
                            }
                            if (items[gi] != null) host.progress(done.incrementAndGet(), n);
                        }
                    }
                }, "ssa-group-" + t);
                ts[t].setPriority(Thread.NORM_PRIORITY - 1);
                ts[t].start();
            }
            for (Thread t : ts) {
                try {
                    t.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (fatal[0] != null && !(fatal[0] instanceof OutOfMemoryError)) {
                // not expected (runOne catches everything it can): same as a failed group, the rest still counts
                host.groupFailed();
            }
        }

        // groups that ran out of memory (while others were running, or in a low-memory phone): again, one at a time, with the memory the others gave back
        for (int gi = 0; gi < n; gi++) {
            if (host.cancelled()) break;
            if (items[gi] == null && oom[gi]) {
                cache.clear();
                res.groupsRetried++;
                oom[gi] = false;
                items[gi] = runOne(groups.get(gi), entries, old, host, cache, n == 1, oom, gi, parseNs, analyseNs, res.stats, gc, keys == null ? null : keys[gi], cached);
                if (items[gi] != null) host.progress(done.incrementAndGet(), n);
            }
        }

        // ---- merge in group order: the same loop as the old single-thread code ----
        Set<String> seen = new HashSet<>();
        for (int gi = 0; gi < n; gi++) {
            List<SsaBridge.Item> its = items[gi];
            if (its == null) continue;
            res.groupsDone++;
            for (SsaBridge.Item item : its) {
                Integer ci = classIndexOf(groups.get(gi), host, item.classType);
                if (ci == null) continue;
                if (res.picked.size() < maxPicked && seen.add(item.classType + "|" + item.method + "|" + item.at + "|" + item.title)) {
                    res.picked.add(new Picked(item, ci));
                }
            }
        }
        res.groupsCached = cached.get();
        res.parseMs = parseNs.get() / 1000000L;
        res.analyseMs = analyseNs.get() / 1000000L;
        res.stopped = host.cancelled() && res.groupsDone < n;
        return res;
    }

    private static long fnv(String t) {
        long h = 0xcbf29ce484222325L;
        for (int i = 0, n = t.length(); i < n; i++) {
            h ^= t.charAt(i);
            h *= 0x100000001b3L;
        }
        return h ^ t.length();
    }

    /**
     * 0.104.0: the cache key of every group (null = this group is not cacheable: a class text could not be read). One pass over the unique classes of all groups hashes each text once
     * (64-bit FNV-1a); a group's key is the SHA-1 of: the engine id, the tunable limits that change results, the sorted entry / guarded lists, the earlier findings the flows are
     * de-duplicated against, and every member's type and text hash in group order.
     */
    static String[] groupKeys(List<List<Integer>> groups, Collection<String> entries, Collection<TaintIr.Old> old, Host host) {
        java.util.HashMap<Integer, Long> hash = new java.util.HashMap<>();
        for (List<Integer> g : groups) {
            for (int i : g) {
                if (hash.containsKey(i)) continue;
                if (host.cancelled()) return new String[groups.size()];
                long h;
                try {
                    h = fnv(host.text(i));
                } catch (Throwable t) {
                    h = Long.MIN_VALUE;                  // unreadable: marks the groups that contain it as not cacheable
                }
                hash.put(i, h);
            }
        }
        StringBuilder common = new StringBuilder("sgc1|").append(host.engineId()).append("|hub=").append(ScopePlanner.HUB_CALLEES).append("|depth=").append(TaintIr.MAX_DEPTH)
            .append("|rounds=").append(TaintIr.MAX_ROUNDS).append("|refs=").append(TaintIr.MAX_REFS).append("|requeue=").append(TaintIr.MAX_REQUEUE).append("|approx=").append(TaintIr.MAX_APPROX_TARGETS).append("|E");
        for (String e : new java.util.TreeSet<>(entries)) common.append(e).append(';');
        common.append("|G");
        for (String e : new java.util.TreeSet<>(host.guardedEntries())) common.append(e).append(';');
        java.util.TreeSet<String> olds = new java.util.TreeSet<>();
        if (old != null) for (TaintIr.Old o : old) olds.add(o.method + "\u0001" + o.title);
        common.append("|O");
        for (String o : olds) common.append(o).append(';');
        String[] keys = new String[groups.size()];
        for (int gi = 0; gi < keys.length; gi++) {
            StringBuilder sb = new StringBuilder(common).append("|C");
            boolean ok = true;
            for (int i : groups.get(gi)) {
                Long h = hash.get(i);
                if (h == null || h == Long.MIN_VALUE) { ok = false; break; }
                sb.append(host.type(i)).append(':').append(Long.toHexString(h)).append(';');
            }
            if (!ok) continue;
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
                byte[] d = md.digest(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : d) hex.append(Character.forDigit((b >> 4) & 15, 16)).append(Character.forDigit(b & 15, 16));
                keys[gi] = hex.toString();
            } catch (Throwable t) {
                keys[gi] = null;
            }
        }
        return keys;
    }

    // class type -> scanner index inside one group (the old code kept this map per group)
    private static Integer classIndexOf(List<Integer> group, Host host, String type) {
        for (int i : group) if (type.equals(host.type(i))) return i;
        return null;
    }

    /** One group. Returns null when it did not produce a result (cancelled, out of memory, failed). */
    private static List<SsaBridge.Item> runOne(List<Integer> idxs, Collection<String> entries, Collection<TaintIr.Old> old, Host host,
                                               ConcurrentHashMap<Integer, SoftReference<ClassIr>> cache, boolean single,
                                               boolean[] oom, int gi, AtomicLong parseNs, AtomicLong analyseNs, TaintIr.Stats total,
                                               GroupCache gc, String key, AtomicInteger cached) {
        try {
            if (gc != null && key != null) {
                GroupCache.Entry hit = gc.load(key);
                if (hit != null) {                       // the same classes, entries, earlier findings and engine: the same result
                    total.merge(hit.stats);
                    cached.incrementAndGet();
                    return hit.items;
                }
            }
            long t0 = System.nanoTime();
            List<ClassIr> app = new ArrayList<>(idxs.size());
            for (int i : idxs) {
                if (host.cancelled()) return null;
                try {
                    SoftReference<ClassIr> r = cache.get(i);
                    ClassIr c = r == null ? null : r.get();
                    if (c == null) {
                        c = SmaliParser.parse(host.text(i));
                        cache.put(i, new SoftReference<>(c));
                    }
                    app.add(c);
                } catch (OutOfMemoryError e) {
                    throw e;
                } catch (Throwable e) {
                    // a class that cannot be read or parsed is left out, as before
                }
            }
            if (host.cancelled()) return null;
            long t1 = System.nanoTime();
            parseNs.addAndGet(t1 - t0);
            TaintIr.Stats gs = new TaintIr.Stats();      // 0.66.5: one group's measurement, added to the total only when the group finished
            List<SsaBridge.Item> r = SsaBridge.newFlows(app, entries, old, gs, host.guardedEntries());
            analyseNs.addAndGet(System.nanoTime() - t1);
            total.merge(gs);
            if (gc != null && key != null && !host.cancelled()) gc.store(key, r, gs);     // only a group that finished normally (a failure returns below, never reaches here)
            return r;
        } catch (OutOfMemoryError e) {
            if (single && oom[gi]) throw e;      // a lone group that fails again alone: report it like before
            oom[gi] = true;
            return null;
        } catch (Throwable t) {
            if (single) {
                if (t instanceof RuntimeException) throw (RuntimeException) t;
                if (t instanceof Error) throw (Error) t;
                throw new RuntimeException(t);
            }
            host.groupFailed();
            return new ArrayList<>();      // one bad group must not lose the others
        }
    }
}
