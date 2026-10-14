package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

/** 0.57.0 (P1 step 3): tests for {@link ScopePlanner} on tiny hand-written smali. No APK, no device. */
public class IrScopeTest {

    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";
    private static final String[] FLOW = {"new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
            "new-instance v3, Landroid/webkit/WebView;", LOAD};

    private static String cls(String type, String sup, String modifiers, String sig, int locals, String... lines) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        sb.append(".method public ").append(modifiers).append(sig).append("\n    .locals ").append(locals).append('\n');
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String plain(String type) {
        return cls(type, "Ljava/lang/Object;", "", "run()V", 0);
    }

    private static String caller(String type, String callee) {
        return cls(type, "Ljava/lang/Object;", "", "run()V", 0, "invoke-static {}, " + callee + "->go()V");
    }

    private static ScopePlanner.Source src(final List<String> types, final List<String> texts) {
        return new ScopePlanner.Source() {
            public int count() { return types.size(); }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return texts.get(i); }
        };
    }

    private static List<String> names(ScopePlanner.Plan p, List<String> types) {
        List<String> out = new ArrayList<>();
        for (int i : p.selected) out.add(types.get(i));
        return out;
    }

    @Test
    public void onlyClassesWithASourceOrASinkAreSelected() {
        List<String> types = Arrays.asList("Lt/Src;", "Lt/Snk;", "Lt/Other;");
        List<String> texts = Arrays.asList(
                cls("Lt/Src;", "Ljava/lang/Object;", "", "a()V", 3, "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET),
                cls("Lt/Snk;", "Ljava/lang/Object;", "", "b()V", 4, "new-instance v3, Landroid/webkit/WebView;", LOAD),
                plain("Lt/Other;"));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.<String>emptyList(), 10);
        // Other has no edge to or from the marked classes, so it stays out
        assertEquals(Arrays.asList("Lt/Src;", "Lt/Snk;"), names(p, types));
        assertEquals(2, p.marked);
        assertFalse(p.capped);
    }

    @Test
    public void anEntryComponentIsAlwaysKept() {
        List<String> types = Arrays.asList("Lt/A;", "Lt/Other;");
        List<String> texts = Arrays.asList(plain("Lt/A;"), plain("Lt/Other;"));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.singletonList("Lt/A;"), 10);
        assertEquals(Collections.singletonList("Lt/A;"), names(p, types));
        assertEquals(1, p.entries);
    }

    @Test
    public void aHelperCalledByAMarkedClassAndTheCallerOfAMarkedClassAreKept() {
        List<String> types = Arrays.asList("Lt/Marked;", "Lt/Helper;", "Lt/Caller;", "Lt/CallerOfCaller;", "Lt/Far;", "Lt/Unrelated;");
        List<String> texts = Arrays.asList(
                cls("Lt/Marked;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW[0], FLOW[1], FLOW[2], FLOW[3], "invoke-static {}, Lt/Helper;->go()V"),
                plain("Lt/Helper;"),
                caller("Lt/Caller;", "Lt/Marked;"),
                caller("Lt/CallerOfCaller;", "Lt/Caller;"),
                caller("Lt/Far;", "Lt/CallerOfCaller;"),
                plain("Lt/Unrelated;"));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.<String>emptyList(), 10);
        List<String> got = names(p, types);
        assertTrue(got.contains("Lt/Marked;"));
        assertTrue(got.contains("Lt/Helper;"));          // callee, depth 1
        assertTrue(got.contains("Lt/Caller;"));          // caller, depth 1
        assertTrue(got.contains("Lt/CallerOfCaller;"));  // caller of caller, depth 2
        assertFalse(got.contains("Lt/Far;"));            // 3 hops away
        assertFalse(got.contains("Lt/Unrelated;"));
    }

    @Test
    public void aProviderSubclassCountsAsASource() {
        List<String> types = Arrays.asList("Lt/P;", "Lt/Other;");
        List<String> texts = Arrays.asList(
                cls("Lt/P;", "Landroid/content/ContentProvider;", "", "query()V", 0), plain("Lt/Other;"));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.<String>emptyList(), 10);
        assertEquals(Collections.singletonList("Lt/P;"), names(p, types));
    }

    @Test
    public void whenTheCapIsReachedClassesWithBothASourceAndASinkWinAndTheCapIsReported() {
        List<String> types = new ArrayList<>();
        List<String> texts = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            types.add("Lt/S" + i + ";");
            texts.add(cls("Lt/S" + i + ";", "Ljava/lang/Object;", "", "a()V", 3, FLOW[0], FLOW[1], FLOW[2]));   // source only
        }
        types.add("Lt/Both;");
        texts.add(cls("Lt/Both;", "Ljava/lang/Object;", "", "a()V", 4, FLOW));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.<String>emptyList(), 3);
        List<String> got = names(p, types);
        assertEquals(3, got.size());
        assertTrue(got.contains("Lt/Both;"));
        assertTrue(p.capped);
    }

    @Test
    public void cancelStopsThePassAndReturnsAnEmptyPlan() {
        final List<String> types = Arrays.asList("Lt/A;", "Lt/B;");
        final List<String> texts = Arrays.asList(plain("Lt/A;"), plain("Lt/B;"));
        ScopePlanner.Source s = new ScopePlanner.Source() {
            public int count() { return 2; }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return texts.get(i); }
            public boolean cancelled() { return true; }
        };
        ScopePlanner.Plan p = ScopePlanner.plan(s, Collections.<String>emptyList(), 10);
        assertTrue(p.cancelled);
        assertEquals(0, p.selected.length);
    }

    @Test
    public void aBigAppIsReducedAndTheFlowIsStillFoundWithItsEntryPath() {
        List<String> types = new ArrayList<>();
        List<String> texts = new ArrayList<>();
        types.add("Lt/A;");
        texts.add(cls("Lt/A;", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/B;->go()V"));
        types.add("Lt/B;");
        texts.add(cls("Lt/B;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        for (int i = 0; i < 300; i++) {
            types.add("Lt/Fill" + i + ";");
            texts.add(plain("Lt/Fill" + i + ";"));
        }
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.singletonList("Lt/A;"), 20);
        assertEquals(2, p.selected.length);          // 300 fillers stay out
        List<ClassIr> cs = new ArrayList<>();
        for (int i : p.selected) cs.add(SmaliParser.parse(texts.get(i)));
        List<SsaBridge.Item> items = SsaBridge.newFlows(cs, Collections.singletonList("Lt/A;"), new ArrayList<TaintIr.Old>());
        assertEquals(1, items.size());
        assertEquals("Lt/B;", items.get(0).classType);
        assertTrue(items.get(0).reachable);
    }
}
