package dev.apkrelab.ir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 0.53.1 (P0): stress test of the IR layer on REAL code. Every class goes through SmaliParser, every method with a body through
 * Cfg.build and SsaForm.build, each step wrapped in try/catch so one bad method never stops the run.
 *
 * Reports: totals, failures grouped by (stage, exception, message shape) with a few examples each, SSA invariant violations
 * (these count as failures), "warnings" that are not crashes but point at a parser gap (opcodes the parser files under OTHER,
 * unresolved labels, switches without payload, dropped catch ranges, registers read before any write), time per stage, the
 * slowest methods, and the heap used.
 *
 * In the app: Export report -> "IR stress test" (needs the classes indexed, i.e. after one Deep scan). On a PC:
 * {@code java -cp ... dev.apkrelab.ir.IrStress <dir-with-.smali-files>}.
 */
public final class IrStress {
    private IrStress() {
    }

    public interface TextSource {
        String get(int index) throws Exception;
    }

    public static final class Group {
        public final String key;
        public int count;
        public final List<String> examples = new ArrayList<>();

        Group(String key) {
            this.key = key;
        }
    }

    public static final class Slow {
        public final String method;
        public final long nanos;
        public final int insns, blocks;

        Slow(String method, long nanos, int insns, int blocks) {
            this.method = method;
            this.nanos = nanos;
            this.insns = insns;
            this.blocks = blocks;
        }
    }

    public static final class Report {
        public int classes, classesEmpty, methods, methodsNoBody, methodsBuilt, methodsFailed;
        public long insns, blocks, phis, unreachableBlocks, undefinedReads;
        public int maxInsns, maxBlocks, maxPhis;
        public long parseNs, cfgNs, ssaNs, totalNs;
        public long heapStart, heapPeak, heapEnd;
        public final Map<String, Group> failures = new TreeMap<>();
        public final Map<String, Group> warnings = new TreeMap<>();
        public final Map<String, Integer> otherOps = new TreeMap<>();
        public final List<Slow> slowest = new ArrayList<>();

        void fail(String stage, String cls, String method, Throwable t) {
            String shape = stage + " | " + t.getClass().getSimpleName() + " | " + shape(String.valueOf(t.getMessage()));
            Group g = failures.get(shape);
            if (g == null) failures.put(shape, g = new Group(shape));
            g.count++;
            if (g.examples.size() < 3) {
                StackTraceElement[] st = t.getStackTrace();
                String at = st.length > 0 ? " @ " + st[0].getClassName().replace("dev.apkrelab.ir.", "") + "." + st[0].getMethodName()
                        + ":" + st[0].getLineNumber() : "";
                g.examples.add(cls + "->" + method + at);
            }
        }

        void warn(String kind, String cls, String method, String detail) {
            Group g = warnings.get(kind);
            if (g == null) warnings.put(kind, g = new Group(kind));
            g.count++;
            if (g.examples.size() < 3) g.examples.add(cls + "->" + method + (detail.isEmpty() ? "" : " : " + detail));
        }

        void slow(String method, long ns, int insns, int blocks) {
            slowest.add(new Slow(method, ns, insns, blocks));
            Collections.sort(slowest, (a, b) -> Long.compare(b.nanos, a.nanos));
            while (slowest.size() > 5) slowest.remove(slowest.size() - 1);
        }

        public boolean clean() {
            return failures.isEmpty();
        }

        public String format() {
            StringBuilder sb = new StringBuilder();
            sb.append("IR STRESS TEST (APKReLab IR layer)\n==================================\n");
            sb.append("classes: ").append(classes).append(" (empty/unreadable ").append(classesEmpty).append(")\n");
            sb.append("methods: ").append(methods).append(" | without body ").append(methodsNoBody).append(" | IR built ")
                    .append(methodsBuilt).append(" | FAILED ").append(methodsFailed).append('\n');
            int withBody = methods - methodsNoBody;
            sb.append("success rate: ").append(withBody == 0 ? "n/a" : String.format(java.util.Locale.US, "%.3f%%", 100.0 * methodsBuilt / withBody))
                    .append('\n');
            sb.append("instructions ").append(insns).append(", blocks ").append(blocks).append(" (unreachable ")
                    .append(unreachableBlocks).append("), phi nodes ").append(phis).append('\n');
            sb.append("largest method: ").append(maxInsns).append(" insns / ").append(maxBlocks).append(" blocks / ")
                    .append(maxPhis).append(" phis\n");
            sb.append("time: total ").append(ms(totalNs)).append(" ms (parse ").append(ms(parseNs)).append(", cfg ")
                    .append(ms(cfgNs)).append(", ssa ").append(ms(ssaNs)).append(")\n");
            sb.append("heap used (MB): start ").append(heapStart >> 20).append(", peak sampled ").append(heapPeak >> 20)
                    .append(", end ").append(heapEnd >> 20).append('\n');
            sb.append("\nSLOWEST METHODS\n");
            for (Slow s : slowest) {
                sb.append("  ").append(ms(s.nanos)).append(" ms  ").append(s.insns).append(" insns, ").append(s.blocks)
                        .append(" blocks  ").append(s.method).append('\n');
            }
            sb.append("\nFAILURES (grouped)\n");
            if (failures.isEmpty()) sb.append("  none\n");
            for (Group g : failures.values()) {
                sb.append("  x").append(g.count).append("  ").append(g.key).append('\n');
                for (String e : g.examples) sb.append("      ").append(e).append('\n');
            }
            sb.append("\nWARNINGS (no crash, possible parser gap)\n");
            if (warnings.isEmpty()) sb.append("  none\n");
            for (Group g : warnings.values()) {
                sb.append("  x").append(g.count).append("  ").append(g.key).append('\n');
                for (String e : g.examples) sb.append("      ").append(e).append('\n');
            }
            if (!otherOps.isEmpty()) {
                sb.append("\nOPCODES FILED UNDER OTHER (parser does not model them)\n");
                for (Map.Entry<String, Integer> e : otherOps.entrySet()) {
                    sb.append("  ").append(e.getKey()).append(" x").append(e.getValue()).append('\n');
                }
            }
            return sb.toString();
        }

        private static String ms(long ns) {
            return String.valueOf(ns / 1_000_000L);
        }
    }

    /** Digits and long hex/identifier-ish tails removed so equal bugs fall into one group. */
    static String shape(String msg) {
        String s = msg.replaceAll("[0-9]+", "N");
        return s.length() > 80 ? s.substring(0, 80) : s;
    }

    public static Report run(int classCount, TextSource src) {
        Report r = new Report();
        Runtime rt = Runtime.getRuntime();
        r.heapStart = rt.totalMemory() - rt.freeMemory();
        r.heapPeak = r.heapStart;
        long t0 = System.nanoTime();
        for (int i = 0; i < classCount; i++) {
            String text;
            try {
                text = src.get(i);
            } catch (Throwable t) {
                r.classes++;
                r.classesEmpty++;
                r.fail("source", "#" + i, "-", t);
                continue;
            }
            r.classes++;
            if (text == null || text.isEmpty()) {
                r.classesEmpty++;
                continue;
            }
            oneClass(r, text);
            if (i % 100 == 0) {
                long used = rt.totalMemory() - rt.freeMemory();
                if (used > r.heapPeak) r.heapPeak = used;
            }
        }
        r.totalNs = System.nanoTime() - t0;
        r.heapEnd = rt.totalMemory() - rt.freeMemory();
        if (r.heapEnd > r.heapPeak) r.heapPeak = r.heapEnd;
        return r;
    }

    private static void oneClass(Report r, String text) {
        ClassIr c;
        long a = System.nanoTime();
        try {
            c = SmaliParser.parse(text);
        } catch (Throwable t) {
            r.parseNs += System.nanoTime() - a;
            r.fail("parse-class", firstLine(text), "-", t);
            return;
        }
        r.parseNs += System.nanoTime() - a;
        for (MethodIr m : c.methods) {
            r.methods++;
            if (m.insns.isEmpty()) {
                r.methodsNoBody++;
                continue;
            }
            oneMethod(r, c, m);
        }
    }

    private static void oneMethod(Report r, ClassIr c, MethodIr m) {
        String where = c.type, name = m.sig();
        scanParse(r, where, name, m);
        Cfg g;
        long a = System.nanoTime();
        try {
            g = Cfg.build(m);
        } catch (Throwable t) {
            r.cfgNs += System.nanoTime() - a;
            r.methodsFailed++;
            r.fail("cfg", where, name, t);
            return;
        }
        long b = System.nanoTime();
        r.cfgNs += b - a;
        SsaForm s;
        try {
            s = SsaForm.build(g);
        } catch (Throwable t) {
            r.ssaNs += System.nanoTime() - b;
            r.methodsFailed++;
            r.fail("ssa", where, name, t);
            return;
        }
        long e = System.nanoTime();
        r.ssaNs += e - b;
        r.slow(c.type + "->" + name, e - a, m.insns.size(), g.blocks.size());
        try {
            validate(r, where, name, m, g, s);
        } catch (Throwable t) {
            r.methodsFailed++;
            r.fail("validate", where, name, t);
            return;
        }
        r.methodsBuilt++;
        int n = m.insns.size(), nb = g.blocks.size(), np = s.phiCount();
        r.insns += n;
        r.blocks += nb;
        r.phis += np;
        if (n > r.maxInsns) r.maxInsns = n;
        if (nb > r.maxBlocks) r.maxBlocks = nb;
        if (np > r.maxPhis) r.maxPhis = np;
    }

    /** Parser-level gaps that do not crash: unknown opcodes, labels that do not resolve, switch without payload, lost catches. */
    private static void scanParse(Report r, String cls, String name, MethodIr m) {
        for (Insn in : m.insns) {
            switch (in.kind) {
                case OTHER: {
                    Integer old = r.otherOps.get(in.op);
                    r.otherOps.put(in.op, old == null ? 1 : old + 1);
                    break;
                }
                case GOTO:
                case IF:
                    for (String l : in.labels) if (m.labelIndex(l) < 0) r.warn("unresolved branch label", cls, name, l);
                    break;
                case SWITCH:
                    if (in.labels.length == 0 || !m.payloads.containsKey(in.labels[0])) {
                        r.warn("switch without payload", cls, name, in.text());
                    }
                    break;
                default:
                    break;
            }
        }
        if (m.catches.size() < m.rawCatches.size()) {
            r.warn("catch range dropped", cls, name, (m.rawCatches.size() - m.catches.size()) + " of " + m.rawCatches.size());
        }
    }

    /** SSA must be well formed: phi operands complete, every use and def of reachable code has a value. Violations are failures. */
    private static void validate(Report r, String cls, String name, MethodIr m, Cfg g, SsaForm s) {
        for (Cfg.BasicBlock b : g.blocks) {
            if (!b.reachable) {
                r.unreachableBlocks++;
                continue;
            }
            if (g.idom[b.id] < 0) throw new IllegalStateException("reachable block without idom: " + b);
            for (SsaForm.Phi p : s.phis[b.id]) {
                if (p.operands.length != b.preds.size()) throw new IllegalStateException("phi operand count " + p.reg);
                for (SsaForm.Value v : p.operands) {
                    if (v == null) throw new IllegalStateException("phi operand missing, reg " + p.reg + " in " + b);
                }
                if (p.result == null) throw new IllegalStateException("phi without result in " + b);
            }
            if (b.pseudo) continue;
            for (int i = b.first; i <= b.last; i++) {
                Insn in = m.insns.get(i);
                SsaForm.Value[] us = s.usesOf(in), ds = s.defsOf(in);
                if (us.length != in.uses.length) throw new IllegalStateException("uses length " + in.text());
                if (!(b.defersLast && i == b.last) && ds.length != in.defs.length) {
                    throw new IllegalStateException("defs length " + in.text());
                }
                for (SsaForm.Value v : us) {
                    if (v == null) throw new IllegalStateException("null use in " + in.text());
                    if (v.entry && !v.param) {
                        r.undefinedReads++;
                        r.warn("register read before any write", cls, name, in.text());
                    }
                }
                for (SsaForm.Value v : ds) if (v == null) throw new IllegalStateException("null def in " + in.text());
            }
        }
    }

    private static String firstLine(String t) {
        int e = t.indexOf('\n');
        return e < 0 ? t.substring(0, Math.min(60, t.length())) : t.substring(0, Math.min(e, 60));
    }

    // ---------- PC entry point ----------

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: IrStress <dir with .smali files>");
            System.exit(2);
        }
        final List<File> files = new ArrayList<>();
        collect(new File(args[0]), files);
        Report r = run(files.size(), i -> new String(Files.readAllBytes(files.get(i).toPath()), StandardCharsets.UTF_8));
        System.out.print(r.format());
        System.exit(r.clean() ? 0 : 1);
    }

    private static void collect(File f, List<File> out) {
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids == null) return;
            for (File k : kids) collect(k, out);
        } else if (f.getName().endsWith(".smali")) {
            out.add(f);
        }
    }
}
