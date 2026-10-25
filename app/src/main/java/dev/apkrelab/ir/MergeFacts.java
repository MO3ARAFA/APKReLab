package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * 1.0.0: the R8 class-merge facts of {@link MergeTags} over the WHOLE app, for a big app analysed in groups.
 *
 * A group holds only the classes on some source-to-sink path: on Axis Pay the group that has the Firebase writer (n62) and the Crashlytics reader (m13) of m42.c does not
 * have dr, the builder that allocates the writer's m42 object with class id 2. Facts computed from the group alone would differ from group to group. This class answers
 * from every class the planner offered, read on demand: the merged classes are known from the planner digests ({@link CallSkeleton#D_MERGED}), and the classes that may
 * construct one or store into its fields are those whose digest names it (an invoke or an iput). Only those classes are parsed, once per merged class (and per holder field), and only for merged
 * classes whose fields a group actually reads with a taint.
 *
 * {@link #hash} covers the texts of the merged classes and of every class that names one: a group's cached result is valid only for the same hash.
 * Thread-safe: groups run in parallel and share one instance (MergeTags' entry points hold its lock).
 */
public final class MergeFacts {
    private static final int LRU = 48;

    private final ScopePlanner.Source src;
    private final Map<String, Integer> index = new HashMap<>();
    private final String[][] refs, writes;                                  // per class: its digest's invoke owners and the other classes whose fields it writes
    private final java.util.Set<String> merged = new java.util.HashSet<>();
    private final Map<String, int[]> namers = new HashMap<>();              // type -> the class itself and every class whose digest names it (memo)
    private final Map<String, String> disc = new HashMap<>();               // merged type -> "name:I" ("" = parsed, none)
    private final Map<String, ClassIr> parsed = new LinkedHashMap<String, ClassIr>(16, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, ClassIr> e) {
            return size() > LRU;
        }
    };
    public final long hash;
    public final int mergedClasses;
    final MergeTags tags;
    int classesParsed;                                                       // measurement only

    private MergeFacts(ScopePlanner.Source src) {
        this.src = src;
        int n = src.count();
        refs = new String[n][];
        writes = new String[n][];
        long[] th = new long[n];
        for (int i = 0; i < n; i++) {
            CallSkeleton.Digest d = src.digest(i);
            refs[i] = d.refs;
            writes[i] = d.fieldOwners;
            th[i] = d.textHash;
            index.put(src.type(i), i);
            if ((d.bits & CallSkeleton.D_MERGED) != 0) merged.add(src.type(i));
        }
        // the cache key: the texts of the merged classes and of every class that names one (a class outside them cannot change a tag)
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < n && !merged.isEmpty(); i++) {
            boolean any = merged.contains(src.type(i));
            for (String t : refs[i]) if (any || merged.contains(t)) { any = true; break; }
            for (String t : writes[i]) if (any || merged.contains(t)) { any = true; break; }
            if (any) h = (h ^ th[i] ^ i) * 0x100000001b3L;
        }
        this.hash = h;
        this.mergedClasses = merged.size();
        this.tags = new MergeTags(new AppProgram());
    }

    /** The class [type] (when it is one of the app's) and every class whose digest names it in an invoke or an instance-field write. */
    private int[] namersOf(String type) {
        int[] r = namers.get(type);
        if (r != null) return r;
        List<Integer> l = new ArrayList<>();
        Integer self = index.get(type);
        if (self != null) l.add(self);
        for (int i = 0; i < refs.length; i++) {
            if (self != null && i == self) continue;
            boolean hit = false;
            for (String t : refs[i]) if (t.equals(type)) { hit = true; break; }
            if (!hit) for (String t : writes[i]) if (t.equals(type)) { hit = true; break; }
            if (hit) l.add(i);
        }
        r = new int[l.size()];
        for (int k = 0; k < r.length; k++) r[k] = l.get(k);
        namers.put(type, r);
        return r;
    }

    /** Facts over the classes of [src] (the planner's source: its digests are read, from a store when the host keeps one). */
    public static MergeFacts of(ScopePlanner.Source src) {
        return new MergeFacts(src);
    }

    /** Measurement: classes parsed so far, tag exclusions made. */
    public String note() {
        synchronized (tags) {
            return mergedClasses + " merged classes, " + classesParsed + " classes read, " + tags.profilesBuilt + " profiles, " + tags.tagsExcluded + " class ids excluded";
        }
    }

    private ClassIr parse(int i) {
        String t = src.type(i);
        ClassIr c = parsed.get(t);
        if (c != null) return c;
        String text = src.text(i);
        classesParsed++;
        if (text == null || text.isEmpty()) return null;
        try {
            c = SmaliParser.parse(text);
        } catch (RuntimeException e) {
            return null;
        }
        parsed.put(t, c);
        return c;
    }

    /** Called with the MergeTags lock held. */
    private final class AppProgram implements MergeTags.Program {
        public String discriminator(String type) {
            if (!merged.contains(type)) return null;
            String d = disc.get(type);
            if (d == null) {
                ClassIr c = parse(index.get(type));
                d = c == null || c.discriminator == null ? "" : c.discriminator;
                disc.put(type, d);
            }
            return d.isEmpty() ? null : d;
        }

        public ClassIr cls(String type) {
            Integer i = index.get(type);
            return i == null ? null : parse(i);
        }

        public MethodIr method(String key) {
            int a = key.indexOf("->");
            ClassIr c = a <= 0 ? null : cls(key.substring(0, a));
            if (c == null) return null;
            for (MethodIr m : c.methods) if (m.key().equals(key)) return m;
            return null;
        }

        public Iterable<ClassIr> namers(String type) {
            int[] rel = namersOf(type);
            return () -> new Iterator<ClassIr>() {
                int ci = 0;
                ClassIr next;

                public boolean hasNext() {
                    while (next == null && ci < rel.length) next = parse(rel[ci++]);
                    return next != null;
                }

                public ClassIr next() {
                    if (!hasNext()) throw new NoSuchElementException();
                    ClassIr c = next;
                    next = null;
                    return c;
                }
            };
        }

        public List<String> callees(MethodIr m, Insn in) {
            return Collections.singletonList(in.ref);
        }

        public List<String> supers(String type) {
            List<String> out = new ArrayList<>();
            for (String t = type; t != null && !t.isEmpty() && out.size() < 16 && !out.contains(t); ) {
                out.add(t);
                ClassIr c = cls(t);
                if (c == null) break;
                out.addAll(c.interfaces);
                t = c.superType;
            }
            return out;
        }
    }
}
