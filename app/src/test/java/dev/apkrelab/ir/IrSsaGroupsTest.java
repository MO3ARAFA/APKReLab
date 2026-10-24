package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

/** 0.60.0: {@link SsaGroups} must give exactly what the one-thread loop gave, whatever the thread count. Tiny hand-written smali. */
public class IrSsaGroupsTest {

    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

    private static String cls(String type, String sup, String mods, String sig, int locals, String... lines) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        sb.append(".method public ").append(mods).append(sig).append("\n    .locals ").append(locals).append('\n');
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    /** k flows Ek -> Hk -> Sk (source and sink in Sk), all groups share the hub class Hub. */
    private static void build(int k, List<String> types, List<String> texts, List<String> entries) {
        types.add("Lt/Hub;");
        texts.add(cls("Lt/Hub;", "Ljava/lang/Object;", "static ", "go()V", 0));
        for (int i = 0; i < k; i++) {
            types.add("Lt/E" + i + ";");
            texts.add(cls("Lt/E" + i + ";", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0,
                    "invoke-static {}, Lt/Hub;->go()V", "invoke-static {}, Lt/S" + i + ";->go()V"));
            entries.add("Lt/E" + i + ";");
            types.add("Lt/S" + i + ";");
            texts.add(cls("Lt/S" + i + ";", "Ljava/lang/Object;", "static ", "go()V", 4,
                    "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
                    "new-instance v3, Landroid/webkit/WebView;", LOAD));
        }
    }

    private static List<List<Integer>> groupsOf(int k, int per) {
        // each group: the hub (index 0) + `per` flows (3 classes each: E, S are at 1 + 2*i, 2 + 2*i)
        List<List<Integer>> out = new ArrayList<>();
        for (int s = 0; s < k; s += per) {
            List<Integer> g = new ArrayList<>();
            g.add(0);
            for (int i = s; i < Math.min(k, s + per); i++) {
                g.add(1 + 2 * i);
                g.add(2 + 2 * i);
            }
            out.add(g);
        }
        return out;
    }

    private static SsaGroups.Host host(final List<String> types, final List<String> texts, final AtomicInteger reads,
                                       final AtomicBoolean cancel, final AtomicInteger failed) {
        return new SsaGroups.Host() {
            public String text(int i) { reads.incrementAndGet(); return texts.get(i); }
            public String type(int i) { return types.get(i); }
            public boolean cancelled() { return cancel.get(); }
            public void progress(int done, int total) { }
            public void groupFailed() { failed.incrementAndGet(); }
        };
    }

    private static List<String> keys(SsaGroups.Result r) {
        List<String> out = new ArrayList<>();
        for (SsaGroups.Picked p : r.picked) out.add(p.item.classType + "|" + p.item.method + "|" + p.item.at + "|" + p.item.title + "|" + p.classIndex);
        return out;
    }

    @Test
    public void threadsGiveTheSameFlowsAsOneThread() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(12, types, texts, entries);
        List<List<Integer>> groups = groupsOf(12, 3);
        Collection<TaintIr.Old> none = new ArrayList<>();
        SsaGroups.Result one = SsaGroups.run(groups, new HashSet<>(entries), none,
                host(types, texts, new AtomicInteger(), new AtomicBoolean(), new AtomicInteger()), 200, 1);
        SsaGroups.Result four = SsaGroups.run(groups, new HashSet<>(entries), none,
                host(types, texts, new AtomicInteger(), new AtomicBoolean(), new AtomicInteger()), 200, 4);
        assertEquals(12, one.picked.size());
        assertEquals(keys(one), keys(four));
        assertEquals(groups.size(), four.groupsDone);
    }

    @Test
    public void aClassSharedByManyGroupsIsReadOnce() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(8, types, texts, entries);
        List<List<Integer>> groups = groupsOf(8, 2);       // 4 groups, all with the hub
        AtomicInteger reads = new AtomicInteger();
        SsaGroups.run(groups, new HashSet<>(entries), new ArrayList<TaintIr.Old>(), host(types, texts, reads, new AtomicBoolean(), new AtomicInteger()), 200, 1);
        assertEquals(types.size(), reads.get());
    }

    @Test
    public void theMergeKeepsAtMostMaxPicked() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(12, types, texts, entries);
        SsaGroups.Result r = SsaGroups.run(groupsOf(12, 3), new HashSet<>(entries), new ArrayList<TaintIr.Old>(),
                host(types, texts, new AtomicInteger(), new AtomicBoolean(), new AtomicInteger()), 5, 2);
        assertEquals(5, r.picked.size());
    }

    @Test
    public void stopBeforeStartKeepsNothingAndMarksStopped() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(6, types, texts, entries);
        AtomicBoolean cancel = new AtomicBoolean(true);
        SsaGroups.Result r = SsaGroups.run(groupsOf(6, 2), new HashSet<>(entries), new ArrayList<TaintIr.Old>(),
                host(types, texts, new AtomicInteger(), cancel, new AtomicInteger()), 200, 2);
        assertTrue(r.stopped);
        assertEquals(0, r.picked.size());
    }

    @Test
    public void anUnreadableClassIsLeftOutAndTheRestStillWorks() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(4, types, texts, entries);
        texts.set(2, "this is not smali at all {{{");       // S0
        SsaGroups.Result r = SsaGroups.run(groupsOf(4, 2), new HashSet<>(entries), new ArrayList<TaintIr.Old>(),
                host(types, texts, new AtomicInteger(), new AtomicBoolean(), new AtomicInteger()), 200, 2);
        assertEquals(2, r.groupsDone);
        assertTrue(r.picked.size() >= 3);
    }
}
