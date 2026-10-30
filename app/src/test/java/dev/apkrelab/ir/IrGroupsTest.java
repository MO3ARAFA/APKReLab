package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

/** 0.59.0 (P1 step 4, part 2): {@link ScopePlanner#groups} covers the whole app with bounded groups. Tiny hand-written smali. */
public class IrGroupsTest {

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
        return cls(type, "Ljava/lang/Object;", "static ", "go()V", 0);
    }

    private static String calls(String type, String callee) {
        return cls(type, "Ljava/lang/Object;", "static ", "go()V", 0, "invoke-static {}, " + callee + "->go()V");
    }

    private static ScopePlanner.Source src(final List<String> types, final List<String> texts) {
        return new ScopePlanner.Source() {
            public int count() { return types.size(); }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return texts.get(i); }
        };
    }

    /** k independent flows: entry Ek (Activity) -> Hk -> Sk (source + sink). Plus fillers. */
    private static void build(int k, int fillers, List<String> types, List<String> texts, List<String> entries) {
        for (int i = 0; i < k; i++) {
            types.add("Lt/E" + i + ";");
            texts.add(cls("Lt/E" + i + ";", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/H" + i + ";->go()V"));
            entries.add("Lt/E" + i + ";");
            types.add("Lt/H" + i + ";");
            texts.add(calls("Lt/H" + i + ";", "Lt/S" + i + ";"));
            types.add("Lt/S" + i + ";");
            texts.add(cls("Lt/S" + i + ";", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        }
        for (int i = 0; i < fillers; i++) {
            types.add("Lt/Fill" + i + ";");
            texts.add(plain("Lt/Fill" + i + ";"));
        }
    }

    @Test
    public void everyMarkedClassIsInSomeGroupAndNoGroupIsBiggerThanTheLimit() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(12, 200, types, texts, entries);
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), entries, 9);
        assertFalse(g.cancelled);
        assertEquals(12, g.marked);
        assertTrue(g.groups.size() > 1);
        assertEquals(0, g.cappedGroups);
        Set<String> seen = new HashSet<>();
        for (int[] grp : g.groups) {
            assertTrue(grp.length <= 9);
            for (int i : grp) seen.add(types.get(i));
        }
        for (int i = 0; i < 12; i++) assertTrue("S" + i + " covered", seen.contains("Lt/S" + i + ";"));
        for (int i = 0; i < 200; i++) assertFalse(seen.contains("Lt/Fill" + i + ";"));
    }

    @Test
    public void allFlowsOfABigAppAreFoundGroupByGroupWhereOneCappedSelectionLosesSome() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(10, 300, types, texts, entries);        // 30 classes belong to flows, 10 flows
        // one selection capped at 9 classes cannot hold them all
        ScopePlanner.Plan one = ScopePlanner.plan(src(types, texts), entries, 9);
        assertTrue(one.capped);
        List<Integer> oneSel = new ArrayList<>();
        for (int i : one.selected) oneSel.add(i);
        int oneFlows = flowsIn(oneSel, types, texts, entries);
        assertTrue(oneFlows < 10);
        // the same limit per GROUP finds all of them
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), entries, 9);
        Set<String> sinks = new HashSet<>();
        for (int[] grp : g.groups) {
            List<Integer> l = new ArrayList<>();
            for (int i : grp) l.add(i);
            List<ClassIr> cs = new ArrayList<>();
            for (int i : l) cs.add(SmaliParser.parse(texts.get(i)));
            for (SsaBridge.Item it : SsaBridge.newFlows(cs, entries, new ArrayList<TaintIr.Old>())) {
                assertTrue("entry path inside the group", it.reachable);
                sinks.add(it.classType);
            }
        }
        assertEquals(10, sinks.size());
    }

    private static int flowsIn(List<Integer> sel, List<String> types, List<String> texts, List<String> entries) {
        List<ClassIr> cs = new ArrayList<>();
        for (int i : sel) cs.add(SmaliParser.parse(texts.get(i)));
        return SsaBridge.newFlows(cs, entries, new ArrayList<TaintIr.Old>()).size();
    }

    @Test
    public void theBestMarkedClassesComeFirst() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/OnlySrc;");
        texts.add(cls("Lt/OnlySrc;", "Ljava/lang/Object;", "static ", "go()V", 3, FLOW[0], FLOW[1], FLOW[2]));
        types.add("Lt/Both;");
        texts.add(cls("Lt/Both;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 1);
        assertEquals(2, g.groups.size());
        assertEquals(1, g.groups.get(0)[0]);   // Both first
        assertEquals(0, g.groups.get(1)[0]);
    }

    @Test
    public void aHugeNeighbourhoodCapsTheGroupButKeepsTheMarkedClass() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/S;");
        StringBuilder calls = new StringBuilder();
        List<String> lines = new ArrayList<>(java.util.Arrays.asList(FLOW));
        for (int i = 0; i < 30; i++) lines.add("invoke-static {}, Lt/C" + i + ";->go()V");
        texts.add(cls("Lt/S;", "Ljava/lang/Object;", "static ", "go()V", 4, lines.toArray(new String[0])));
        for (int i = 0; i < 30; i++) {
            types.add("Lt/C" + i + ";");
            texts.add(plain("Lt/C" + i + ";"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 5);
        assertEquals(1, g.groups.size());
        assertEquals(5, g.groups.get(0).length);
        assertEquals(1, g.cappedGroups);
        assertEquals(0, g.groups.get(0)[0]);
    }

    @Test
    public void noMarkedClassMeansNoGroup() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            types.add("Lt/P" + i + ";");
            texts.add(plain("Lt/P" + i + ";"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 10);
        assertEquals(0, g.groups.size());
        assertEquals(0, g.marked);
    }

    @Test
    public void cancelStopsTheGrouping() {
        final List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        build(2, 0, types, texts, new ArrayList<String>());
        ScopePlanner.Source s = new ScopePlanner.Source() {
            public int count() { return types.size(); }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return texts.get(i); }
            public boolean cancelled() { return true; }
        };
        ScopePlanner.Groups g = ScopePlanner.groups(s, Collections.<String>emptyList(), 10);
        assertTrue(g.cancelled);
        assertEquals(0, g.groups.size());
    }

    @Test
    public void aSinkOnlyClassFarFromAnySourceIsLeftOutAndANearOneIsKept() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/Src;");
        texts.add(cls("Lt/Src;", "Ljava/lang/Object;", "static ", "go()V", 3, FLOW[0], FLOW[1], FLOW[2], "invoke-static {}, Lt/NearSink;->go()V"));
        types.add("Lt/NearSink;");
        texts.add(cls("Lt/NearSink;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW[4], FLOW[5]));
        types.add("Lt/FarSink;");
        texts.add(cls("Lt/FarSink;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW[4], FLOW[5]));
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 10, false, false, true);
        assertEquals(2, g.marked);
        assertEquals(1, g.skippedSinks);
        Set<Integer> seen = new HashSet<>();
        for (int[] grp : g.groups) for (int i : grp) seen.add(i);
        assertTrue(seen.contains(1));
        assertFalse(seen.contains(2));
    }

    private static final String PREFS = "invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";

    @Test
    public void intentOnlyDropsPreferencesSourcesAndReachableOnlyDropsClassesNoEntryReaches() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/E;");
        texts.add(cls("Lt/E;", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/Live;->go()V"));
        types.add("Lt/Live;");
        texts.add(cls("Lt/Live;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        types.add("Lt/Prefs;");
        texts.add(cls("Lt/Prefs;", "Ljava/lang/Object;", "static ", "go()V", 6, "new-instance v3, Landroid/webkit/WebView;", PREFS, "move-result-object v2", LOAD));
        types.add("Lt/Dead;");
        texts.add(cls("Lt/Dead;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        List<String> entries = Collections.singletonList("Lt/E;");
        ScopePlanner.Groups all = ScopePlanner.groups(src(types, texts), entries, 10, false, false, true);
        assertEquals(3, all.marked);                       // Live, Prefs, Dead
        ScopePlanner.Groups intent = ScopePlanner.groups(src(types, texts), entries, 10, true, false, true);
        assertEquals(2, intent.marked);                    // Prefs is gone (a WebView sink alone, no counted source within 2 hops)
        ScopePlanner.Groups both = ScopePlanner.groups(src(types, texts), entries, 10, true, true, true);
        assertEquals(1, both.marked);                      // only Live: Dead is not reached by any entry
        assertEquals(1, both.unreachable);
        assertEquals(1, both.groups.size());
    }

    @Test
    public void byDefaultNothingIsLeftOut() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/Src;");
        texts.add(cls("Lt/Src;", "Ljava/lang/Object;", "static ", "go()V", 3, FLOW[0], FLOW[1], FLOW[2]));
        types.add("Lt/FarSink;");
        texts.add(cls("Lt/FarSink;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW[4], FLOW[5]));
        types.add("Lt/Prefs;");
        texts.add(cls("Lt/Prefs;", "Ljava/lang/Object;", "static ", "go()V", 6, "new-instance v3, Landroid/webkit/WebView;", PREFS, "move-result-object v2", LOAD));
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.singletonList("Lt/Other;"), 10);
        assertEquals(3, g.marked);
        assertEquals(0, g.skippedSinks);
        assertEquals(0, g.unreachable);
        Set<Integer> seen = new HashSet<>();
        for (int[] grp : g.groups) for (int i : grp) seen.add(i);
        assertEquals(3, seen.size());
    }

    /** 0.62.0: a helper called by hundreds of classes (hub) joins the closure but does not pull in its own neighbourhood. */
    @Test
    public void aHubJoinsTheGroupButItsNeighboursDoNot() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/S;");
        texts.add(cls("Lt/S;", "Ljava/lang/Object;", "static ", "go()V", 4,
                FLOW[0], FLOW[1], FLOW[2], FLOW[3], FLOW[4], FLOW[5], "invoke-static {}, Lt/Hub;->go()V"));
        types.add("Lt/Hub;");
        String[] hubCalls = new String[40];
        for (int i = 0; i < 40; i++) hubCalls[i] = "invoke-static {}, Lt/Z" + i + ";->go()V";
        texts.add(cls("Lt/Hub;", "Ljava/lang/Object;", "static ", "go()V", 0, hubCalls));
        for (int i = 0; i < 40; i++) {
            types.add("Lt/Z" + i + ";");
            texts.add(plain("Lt/Z" + i + ";"));
        }
        for (int i = 0; i < 250; i++) {
            types.add("Lt/P" + i + ";");
            texts.add(calls("Lt/P" + i + ";", "Lt/Hub;"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 100);
        assertEquals(1, g.hubs);
        assertEquals(1, g.groups.size());
        assertEquals(0, g.cappedGroups);
        Set<String> in = new HashSet<>();
        for (int i : g.groups.get(0)) in.add(types.get(i));
        assertTrue(in.contains("Lt/S;"));
        assertTrue(in.contains("Lt/Hub;"));
        assertFalse(in.contains("Lt/Z0;"));
        assertFalse(in.contains("Lt/P0;"));
    }

    /** 0.65.0: a MARKED class with very many callers (prefs / util wrapper) does not pull its callers into its own group. */
    @Test
    public void aMarkedHubDoesNotPullItsCallersIntoItsOwnGroup() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/M;");
        texts.add(cls("Lt/M;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        for (int i = 0; i < 80; i++) {
            types.add("Lt/P" + i + ";");
            texts.add(calls("Lt/P" + i + ";", "Lt/M;"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 100);
        assertEquals(1, g.markedHubs);
        assertEquals(1, g.groups.size());
        assertEquals(0, g.cappedGroups);
        Set<String> in = new HashSet<>();
        for (int i : g.groups.get(0)) in.add(types.get(i));
        assertTrue(in.contains("Lt/M;"));
        assertFalse(in.contains("Lt/P0;"));
    }

    /** 0.65.0: a caller that has a sink is marked itself, so its own group still holds the hub as a callee (the flow hub -> caller is kept). */
    @Test
    public void aSinkCallerOfAMarkedHubStillSeesTheHubInItsOwnGroup() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/M;");
        texts.add(cls("Lt/M;", "Ljava/lang/Object;", "static ", "go()V", 4, GET, "move-result-object v2"));
        types.add("Lt/C;");
        texts.add(cls("Lt/C;", "Ljava/lang/Object;", "static ", "go()V", 4, "invoke-static {}, Lt/M;->go()V", "new-instance v3, Landroid/webkit/WebView;", LOAD));
        for (int i = 0; i < 80; i++) {
            types.add("Lt/P" + i + ";");
            texts.add(calls("Lt/P" + i + ";", "Lt/M;"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 100);
        assertEquals(1, g.markedHubs);
        boolean found = false;
        for (int[] grp : g.groups) {
            Set<String> in = new HashSet<>();
            for (int i : grp) in.add(types.get(i));
            if (in.contains("Lt/C;")) {
                found = true;
                assertTrue(in.contains("Lt/M;"));
                assertFalse(in.contains("Lt/P0;"));
            }
        }
        assertTrue(found);
    }

    /** 0.65.0: a marked hub keeps one shortest entry path, so reach is still meaningful. */
    @Test
    public void aMarkedHubKeepsOneEntryPath() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        types.add("Lt/M;");
        texts.add(cls("Lt/M;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        types.add("Lt/E;");
        texts.add(cls("Lt/E;", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/L;->go()V"));
        entries.add("Lt/E;");
        types.add("Lt/L;");
        texts.add(calls("Lt/L;", "Lt/M;"));
        for (int i = 0; i < 80; i++) {
            types.add("Lt/P" + i + ";");
            texts.add(calls("Lt/P" + i + ";", "Lt/M;"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), entries, 100);
        assertEquals(1, g.markedHubs);
        Set<String> in = new HashSet<>();
        for (int[] grp : g.groups) for (int i : grp) in.add(types.get(i));
        assertTrue(in.contains("Lt/M;"));
        assertTrue(in.contains("Lt/L;"));
        assertTrue(in.contains("Lt/E;"));
        assertFalse(in.contains("Lt/P0;"));
    }

    /** 0.66.0: the entry slice is a few shortest entry paths, not every class on any path from any entry (50 entries share one chain). */
    @Test
    public void theEntrySliceIsAFewPathsNotEveryEntry() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        types.add("Lt/M;");
        texts.add(cls("Lt/M;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        types.add("Lt/L3;");
        texts.add(calls("Lt/L3;", "Lt/M;"));
        types.add("Lt/L2;");
        texts.add(calls("Lt/L2;", "Lt/L3;"));
        types.add("Lt/L1;");
        texts.add(calls("Lt/L1;", "Lt/L2;"));
        for (int i = 0; i < 50; i++) {
            types.add("Lt/E" + i + ";");
            texts.add(cls("Lt/E" + i + ";", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/L1;->go()V"));
            entries.add("Lt/E" + i + ";");
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), entries, 100);
        assertEquals(0, g.cappedGroups);
        Set<String> in = new HashSet<>();
        for (int[] grp : g.groups) for (int i : grp) in.add(types.get(i));
        int e = 0;
        for (String t : in) if (t.startsWith("Lt/E")) e++;
        assertTrue(e >= 1);
        assertTrue(e <= ScopePlanner.ENTRY_PATHS);
        assertTrue(in.contains("Lt/L1;"));
        assertTrue(in.contains("Lt/L2;"));
    }

    /** 0.63.0: with a tight cap the direct callers come before the long entry slice (the slice only adds the entry path). */
    @Test
    public void directCallersComeBeforeTheEntrySliceWhenTheCapIsTight() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        types.add("Lt/S;");
        texts.add(cls("Lt/S;", "Ljava/lang/Object;", "static ", "go()V", 4, FLOW));
        for (int i = 0; i < 3; i++) {            // 3 direct callers; only C0 is reachable from the entry
            types.add("Lt/C" + i + ";");
            texts.add(calls("Lt/C" + i + ";", "Lt/S;"));
        }
        types.add("Lt/E;");
        texts.add(cls("Lt/E;", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/L0;->go()V"));
        entries.add("Lt/E;");
        for (int i = 0; i < 12; i++) {
            types.add("Lt/L" + i + ";");
            texts.add(calls("Lt/L" + i + ";", i == 11 ? "Lt/C0;" : "Lt/L" + (i + 1) + ";"));
        }
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), entries, 6);
        assertEquals(1, g.groups.size());
        Set<String> in = new HashSet<>();
        for (int i : g.groups.get(0)) in.add(types.get(i));
        assertTrue(in.contains("Lt/S;"));
        for (int i = 0; i < 3; i++) assertTrue("C" + i, in.contains("Lt/C" + i + ";"));
        assertTrue(g.cappedGroups > 0);
        assertTrue(g.maxClosure > 6);
        assertTrue(g.maxClosureTiers.contains("slice="));
        assertFalse(in.contains("Lt/L5;"));
    }

    // ---- 0.101.1: callee hubs (fan-out). Assumes the default threshold of 100 (-Dapkrelab.hubCallees unset).
    private static Set<String> groupOf(List<String> types, List<String> texts) {
        ScopePlanner.Groups g = ScopePlanner.groups(src(types, texts), Collections.<String>emptyList(), 1000);
        Set<String> in = new HashSet<>();
        for (int[] grp : g.groups) { boolean hasS = false; for (int i : grp) if (types.get(i).equals("Lt/S;")) hasS = true; if (hasS) for (int i : grp) in.add(types.get(i)); }
        return in;
    }

    private static void fanOut(List<String> types, List<String> texts, String owner, int n, boolean marked) {
        String[] lines = new String[n];
        for (int i = 0; i < n; i++) lines[i] = "invoke-static {}, Lt/L" + i + ";->go()V";
        types.add(owner);
        texts.add(marked ? cls(owner, "Ljava/lang/Object;", "static ", "go()V", 4, concat(FLOW, lines)) : cls(owner, "Ljava/lang/Object;", "static ", "go()V", 0, lines));
        for (int i = 0; i < n; i++) { types.add("Lt/L" + i + ";"); texts.add(plain("Lt/L" + i + ";")); }
    }

    private static String[] concat(String[] a, String[] b) {
        String[] r = new String[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    @Test
    public void aHelperThatCallsHundredsOfClassesDoesNotPullThemIntoTheGroup() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/S;");
        texts.add(cls("Lt/S;", "Ljava/lang/Object;", "static ", "go()V", 4, concat(FLOW, new String[]{"invoke-static {}, Lt/H;->go()V"})));
        fanOut(types, texts, "Lt/H;", 120, false);
        Set<String> in = groupOf(types, texts);
        assertTrue(in.contains("Lt/S;") && in.contains("Lt/H;"));      // the helper itself is a callee: it is in
        assertFalse(in.contains("Lt/L0;"));                             // its 120 callees are not
    }

    @Test
    public void aHelperBelowTheThresholdStillExpandsAndAMarkedClassNeverCounts() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/S;");
        texts.add(cls("Lt/S;", "Ljava/lang/Object;", "static ", "go()V", 4, concat(FLOW, new String[]{"invoke-static {}, Lt/H;->go()V"})));
        fanOut(types, texts, "Lt/H;", 40, false);                       // 40 callees: below the threshold
        assertTrue(groupOf(types, texts).contains("Lt/L0;"));
        List<String> t2 = new ArrayList<>(), x2 = new ArrayList<>();
        t2.add("Lt/S;");
        x2.add(cls("Lt/S;", "Ljava/lang/Object;", "static ", "go()V", 4, concat(FLOW, new String[]{"invoke-static {}, Lt/H;->go()V"})));
        fanOut(t2, x2, "Lt/H;", 150, true);                             // a MARKED class with 150 callees: its flows must be found, so it is not a hub
        assertTrue(groupOf(t2, x2).contains("Lt/L0;"));
    }
}
