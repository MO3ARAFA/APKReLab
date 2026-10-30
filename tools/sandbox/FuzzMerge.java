import dev.apkrelab.ir.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * 1.0.0: robustness of the code 1.0.0 changed (switch keys and class-id fields in SmaliParser, the planner digest, MergeTags / MergeFacts in TaintIr), on mangled input.
 * Takes the R8-merged classes of a decoded app (a synthetic I/S/B field) and the classes that name them, mangles each N ways (lines dropped, duplicated, swapped,
 * truncated; switch payloads and class-id stores corrupted) and runs: parse, digest, one call graph + taint run per batch with app-wide facts over the batch.
 * Counts exceptions (OutOfMemoryError included), calls slower than the limit, and methods the taint run caught throwing. Usage: java FuzzMerge <decoded dir> <classes> <variants> [seed]
 */
public class FuzzMerge {
    public static void main(String[] a) throws Exception {
        Path dec = Paths.get(a[0]);
        int max = Integer.parseInt(a[1]), variants = Integer.parseInt(a[2]);
        Random rnd = new Random(a.length > 3 ? Long.parseLong(a[3]) : 100);
        List<String> texts = new ArrayList<>();
        try (var s = Files.walk(dec)) {
            for (Path p : (Iterable<Path>) s.filter(x -> x.toString().endsWith(".smali"))::iterator) {
                String t = new String(Files.readAllBytes(p));
                boolean merged = t.contains(" synthetic ") && t.matches("(?s).*\\n\\.field [^\\n]*synthetic[^\\n]*:[BSI]\\n.*");
                if (merged || (t.contains("packed-switch") && rnd.nextInt(4) == 0)) texts.add(t);
                if (texts.size() >= max) break;
            }
        }
        System.out.println("classes " + texts.size());
        int calls = 0, exceptions = 0, slow = 0;
        final java.util.concurrent.atomic.AtomicInteger methodFails = new java.util.concurrent.atomic.AtomicInteger();
        List<String> fails = new ArrayList<>();
        ExecutorService ex = Executors.newSingleThreadExecutor(r -> { Thread th = new Thread(r); th.setDaemon(true); return th; });
        for (int v = 0; v < variants; v++) {
            List<String> batch = new ArrayList<>();
            for (String t : texts) batch.add(mangle(t, rnd));
            for (int i = 0; i < batch.size(); i += 50) {
                final List<String> part = batch.subList(i, Math.min(batch.size(), i + 50));
                calls++;
                Future<?> f = ex.submit(() -> {
                    List<ClassIr> cs = new ArrayList<>();
                    for (String t : part) { CallSkeleton.digest(t); cs.add(SmaliParser.parse(t)); }
                    List<String> types = new ArrayList<>();
                    for (ClassIr c : cs) types.add(c.type);
                    MergeFacts mf = MergeFacts.of(new ScopePlanner.Source() {
                        public int count() { return part.size(); }
                        public String type(int k) { return types.get(k); }
                        public String text(int k) { return part.get(k); }
                    });
                    SsaBridge.newFlows(cs, types, null, null, null, mf);
                    // the taint run counts a method that throws instead of failing: count those too
                    CallGraph g = CallGraph.build(cs, types, CallGraph.Mode.RTA, null);
                    TaintIr.Result r = TaintIr.analyze(g, false, null);
                    methodFails.addAndGet(r.failed);
                    if (r.failed > 0 && fails.size() < 10) synchronized (fails) { fails.addAll(r.failures); }
                    return null;
                });
                try {
                    f.get(60, TimeUnit.SECONDS);
                } catch (TimeoutException te) {
                    slow++; f.cancel(true);
                    ex.shutdownNow(); ex = Executors.newSingleThreadExecutor(r -> { Thread th = new Thread(r); th.setDaemon(true); return th; });
                } catch (ExecutionException ee) {
                    exceptions++;
                    if (fails.size() < 10) fails.add(ee.getCause().toString() + " @ " + Arrays.toString(Arrays.copyOf(ee.getCause().getStackTrace(), 3)));
                }
            }
        }
        System.out.println("batches " + calls + " exceptions " + exceptions + " over-60s " + slow + " methods that threw inside the taint run " + methodFails.get());
        for (String s : fails) System.out.println("FAIL " + s);
        System.exit(0);
    }

    static String mangle(String t, Random r) {
        List<String> ls = new ArrayList<>(Arrays.asList(t.split("\n", -1)));
        int ops = 1 + r.nextInt(6);
        for (int k = 0; k < ops && !ls.isEmpty(); k++) {
            int i = r.nextInt(ls.size());
            switch (r.nextInt(8)) {
                case 0: ls.remove(i); break;
                case 1: ls.add(i, ls.get(r.nextInt(ls.size()))); break;
                case 2: { int j = r.nextInt(ls.size()); String x = ls.get(i); ls.set(i, ls.get(j)); ls.set(j, x); break; }
                case 3: ls = new ArrayList<>(ls.subList(0, i)); break;
                case 4: ls.set(i, ls.get(i).replaceAll("0x[0-9a-f]+", r.nextBoolean() ? "0xzz" : "-0x7fffffff")); break;      // switch keys, class ids
                case 5: ls.set(i, ls.get(i).replace("->", r.nextBoolean() ? "-" : "->->")); break;
                case 6: ls.set(i, ls.get(i).replace(":I", ":").replace("synthetic", "synthetic static")); break;
                default: ls.set(i, ls.get(i).replaceAll("[vp]\\d+", "v" + (r.nextInt(70000) - 3))); break;
            }
        }
        return String.join("\n", ls);
    }
}
