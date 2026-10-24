package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

/** 0.66.5: the measurement of {@link TaintIr} ({@link TaintIr.Stats}) on tiny hand-written smali. It must count, and must change no result. */
public class IrStatsTest {

    private static final String OBJ = "Ljava/lang/Object;";
    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";
    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2"};

    private static String mm(int locals, String sig, String... lines) {
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals " + locals + "\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String cls(String type, String sup, String... methods) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        for (String x : methods) sb.append(x).append('\n');
        return sb.toString();
    }

    private static String[] cat(String[] a, String... b) {
        String[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static String act(String... body) {
        return cls("Lt/A;", "Landroid/app/Activity;", mm(4, "onCreate(Landroid/os/Bundle;)V", body));
    }

    private static TaintIr.Result run(String... texts) {
        List<ClassIr> cs = new ArrayList<>();
        for (String t : texts) cs.add(SmaliParser.parse(t));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null);
    }

    @Test
    public void libraryCallThatDropsARealSourceIsCountedAndTheResultIsUnchanged() {
        TaintIr.Result r = run(act(cat(SRC,
                "invoke-static {v2}, Lcom/lib/Foo;->enc(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2",
                "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        assertEquals(0, r.flows.size());                     // same as before 0.66.5: unknown library calls drop the taint
        assertEquals(1, r.stats.library[0]);
        assertEquals(0, r.stats.library[1]);
        assertEquals(Long.valueOf(1L), r.stats.owners.get("com/lib/Foo"));
    }

    @Test
    public void parameterOnlyTaintIsCountedSeparately() {
        TaintIr.Result r = run(
                act("new-instance v3, Lt/B;", "const-string v2, \"x\"", "invoke-virtual {v3, v2}, Lt/B;->show(Ljava/lang/String;)V"),
                cls("Lt/B;", OBJ, mm(3, "show(Ljava/lang/String;)V",
                        "invoke-static {p1}, Lcom/lib/Foo;->enc(Ljava/lang/String;)Ljava/lang/String;")));
        assertEquals(0, r.stats.library[0]);
        assertEquals(1, r.stats.library[1]);
        assertTrue(r.stats.owners.isEmpty());                // 0.66.6: parameter-only drops are not listed by owner
    }

    @Test
    public void calleeWithoutABodyIsCountedAsNotAnalysed() {
        TaintIr.Result r = run(
                act(cat(SRC, "new-instance v3, Lt/B;", "invoke-virtual {v3, v2}, Lt/B;->foo(Ljava/lang/String;)V")),
                cls("Lt/B;", OBJ, ".method public native foo(Ljava/lang/String;)V\n.end method\n"));
        assertEquals(0, r.flows.size());
        assertEquals(1, r.stats.outOfScope[0]);
    }

    @Test
    public void aFullSinkSlotCountsTheDroppedReference() {
        String[] body = new String[TaintIr.MAX_REFS + 2];
        body[0] = "new-instance v0, Landroid/webkit/WebView;";
        for (int i = 1; i < body.length; i++) body[i] = "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";
        TaintIr.Result r = run(
                act(cat(SRC, "new-instance v3, Lt/B;", "invoke-virtual {v3, v2}, Lt/B;->show(Ljava/lang/String;)V")),
                cls("Lt/B;", OBJ, mm(3, "show(Ljava/lang/String;)V", body)));
        assertEquals(1, r.stats.capRefs);                    // MAX_REFS + 1 sink calls, one did not fit
        assertEquals(0, r.stats.capRounds);
        assertEquals(0, r.stats.capRequeue);
    }

    @Test
    public void analysesAndSlowestMethodsAreReported() {
        TaintIr.Result r = run(
                act(cat(SRC, "new-instance v3, Lt/B;", "invoke-virtual {v3, v2}, Lt/B;->show(Ljava/lang/String;)V")),
                cls("Lt/B;", OBJ, mm(3, "show(Ljava/lang/String;)V", "new-instance v0, Landroid/webkit/WebView;",
                        "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")));
        assertEquals(r.analyses, r.stats.analyses);
        assertTrue(r.stats.slowest.size() >= 1 && r.stats.slowest.size() <= TaintIr.Stats.KEEP);
        TaintIr.Stats.Slow s = r.stats.slowest.get(0);
        assertTrue(s.insns > 0);
        assertTrue(s.rounds >= 1);
        assertTrue(s.runs >= 1);
        assertTrue(r.stats.line().contains("slowest methods: "));
    }

    @Test
    public void mergeSumsCountersAndKeepsOneEntryPerMethod() {
        String[] code = cat(SRC, "invoke-static {v2}, Lcom/lib/Foo;->enc(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2");
        TaintIr.Result a = run(act(code)), b = run(act(code));
        TaintIr.Stats total = new TaintIr.Stats();
        total.merge(a.stats);
        total.merge(b.stats);
        assertEquals(2, total.library[0]);
        assertEquals(Long.valueOf(2L), total.owners.get("com/lib/Foo"));
        Set<String> keys = new HashSet<>();
        for (TaintIr.Stats.Slow s : total.slowest) assertTrue(keys.add(s.key));
        assertEquals(a.stats.analyses + b.stats.analyses, total.analyses);
        String line = total.line();
        assertTrue(line.startsWith("taint losses real/param-only: "));
        assertTrue(line.contains("top owners of real drops: com/lib/Foo 2"));
        assertFalse(line.contains("\n"));
    }

    /** 0.103.2: run counts of a method that is NOT always in the top 5 must add up across groups (before: 38 runs in one report, 73 in the next, for the same app). */
    @Test
    public void runCountsAddUpAcrossGroupsEvenForMethodsOutsideTheTopFive() {
        TaintIr.Stats total = new TaintIr.Stats();
        for (int group = 0; group < 3; group++) {
            TaintIr.Stats g = new TaintIr.Stats();
            for (int k = 0; k < 8; k++) g.slowest.add(new TaintIr.Stats.Slow("Lt/M" + k + ";->m()V", 1000L - k * 10, 1, 10 + k, 2));
            total.merge(g);
        }
        assertEquals(8, total.slowest.size());                                       // none was dropped while merging
        for (TaintIr.Stats.Slow x : total.slowest) assertEquals(x.key, 3, x.runs);   // the 8th method (never in the top 5) counted all three groups
        String line = total.line();
        assertTrue(line.contains("M0")); assertTrue(!line.contains("M5"));           // twin: only the top five are printed
    }
}
