import dev.apkrelab.ir.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 0.103.0: where the allocation of the class-reading passes goes, measured per phase with the exact per-thread allocation counter (no sampling):
 *   read   = file -> String (what the device does with its text index),
 *   parse  = SmaliParser.parse of every class (the result is dropped, as in a group),
 *   skel   = CallSkeleton.build (the planner's pass over every class: 4 regexes per class), texts served from memory so the regex cost is isolated,
 *   hash   = a checksum of every ClassIr (methods, instructions, registers, labels): equal before / after a parser change = identical IR.
 * usage: java -Xmx1000m -cp <ir classes>:<this> ParseBench <dir with .smali> [reps]
 */
public class ParseBench {
    static final com.sun.management.ThreadMXBean TM = (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
    static long alloc() { return TM.getThreadAllocatedBytes(Thread.currentThread().getId()); }

    interface Job { void run() throws Exception; }
    static void measure(String name, Job j) throws Exception {
        System.gc();
        long a0 = alloc(), t0 = System.nanoTime();
        long gc0 = 0, gcn0 = 0;
        for (java.lang.management.GarbageCollectorMXBean g : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) { gc0 += g.getCollectionTime(); gcn0 += g.getCollectionCount(); }
        j.run();
        long gc1 = 0, gcn1 = 0;
        for (java.lang.management.GarbageCollectorMXBean g : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) { gc1 += g.getCollectionTime(); gcn1 += g.getCollectionCount(); }
        System.out.printf("%-6s %7d ms  %9.1f MB allocated  gc %d ms in %d collections%n", name, (System.nanoTime() - t0) / 1000000, (alloc() - a0) / 1048576.0, gc1 - gc0, gcn1 - gcn0);
    }

    static long mix(long h, long v) { return h * 1000003L + v; }
    static long mix(long h, String s) { return mix(h, s == null ? -1 : s.hashCode()); }
    static long mix(long h, int[] a) { if (a == null) return mix(h, -2); h = mix(h, a.length); for (int x : a) h = mix(h, x); return h; }

    /** A checksum of everything the parser produces for one class. */
    static long hash(ClassIr c) {
        long h = 7;
        h = mix(h, c.type); h = mix(h, c.superType); h = mix(h, c.flags);
        for (String s : c.interfaces) h = mix(h, s);
        for (String s : c.fields) h = mix(h, s);
        for (MethodIr m : c.methods) {
            h = mix(h, m.owner); h = mix(h, m.name); h = mix(h, m.desc); h = mix(h, m.flags); h = mix(h, m.isStatic ? 1 : 0); h = mix(h, m.ins); h = mix(h, m.locals);
            h = mix(h, m.startOffset); h = mix(h, m.startLine);
            for (Insn in : m.insns) {
                h = mix(h, in.index); h = mix(h, in.op); h = mix(h, in.kind.ordinal()); h = mix(h, in.offset); h = mix(h, in.line); h = mix(h, in.text());
                h = mix(h, in.ref); h = mix(h, in.defs); h = mix(h, in.uses); h = mix(h, in.hasResult ? 1 : 0);
                if (in.labels != null) for (String l : in.labels) h = mix(h, l);
            }
            for (Map.Entry<String, Integer> e : new TreeMap<>(m.labels).entrySet()) { h = mix(h, e.getKey()); h = mix(h, e.getValue()); }
            for (Map.Entry<String, List<String>> e : new TreeMap<>(m.payloads).entrySet()) { h = mix(h, e.getKey()); for (String t : e.getValue()) h = mix(h, t); }
            for (String[] r : m.rawCatches) for (String t : r) h = mix(h, t);
            for (MethodIr.Catch k : m.catches) { h = mix(h, k.type); h = mix(h, k.start); h = mix(h, k.end); h = mix(h, k.handler); }
        }
        return h;
    }

    public static void main(String[] a) throws Exception {
        List<File> files;
        try (Stream<java.nio.file.Path> s = Files.walk(new File(a[0]).toPath())) { files = s.filter(p -> p.toString().endsWith(".smali")).map(java.nio.file.Path::toFile).sorted().collect(Collectors.toList()); }
        int reps = a.length > 1 ? Integer.parseInt(a[1]) : 3;
        final String[] texts = new String[files.size()]; long chars = 0;
        for (int i = 0; i < texts.length; i++) { texts[i] = new String(Files.readAllBytes(files.get(i).toPath()), StandardCharsets.UTF_8); chars += texts[i].length(); }
        System.out.println(texts.length + " classes, " + chars / 1048576 + " MB of smali text, heap " + Runtime.getRuntime().maxMemory() / 1048576 + " MB");
        // retained size: parse the first 3000 classes, keep them all, collect, read the used heap (what a group of 3000 classes costs while it is analysed)
        { Runtime rt = Runtime.getRuntime(); System.gc(); long base = rt.totalMemory() - rt.freeMemory(); List<ClassIr> keep = new ArrayList<>();
          for (int i = 0; i < Math.min(3000, texts.length); i++) keep.add(SmaliParser.parse(texts[i]));
          System.gc(); System.gc(); System.out.printf("KEPT   %d classes parsed and kept: %.1f MB of heap%n", keep.size(), (rt.totalMemory() - rt.freeMemory() - base) / 1048576.0); keep.clear(); }
        final long[] sum = {0};
        for (int r = 0; r < reps; r++) {
            System.out.println("-- pass " + (r + 1));
            measure("read", () -> { long n = 0; for (File f : files) n += new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).length(); sum[0] = n; });
            measure("parse", () -> { for (String t : texts) { ClassIr c = SmaliParser.parse(t); sum[0] += c.methods.size(); } });
            measure("skel", () -> {
                CallSkeleton sk = CallSkeleton.build(new ScopePlanner.Source() {
                    public int count() { return texts.length; }
                    public String type(int i) { return "L" + files.get(i).getName() + ";"; }
                    public String text(int i) { return texts[i]; }
                }, new ArrayList<>());
                sum[0] += sk.n;
            });
            measure("hash", () -> { long h = 0; for (String t : texts) h = mix(h, hash(SmaliParser.parse(t))); System.out.println("IRHASH " + h); });
        }
    }
}
