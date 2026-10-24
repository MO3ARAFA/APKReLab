package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

/**
 * 0.104.0: the per-group disk cache. The rule it must keep: a cached scan gives EXACTLY what a scan without a cache gives, and anything that could change a result (a class text, the entry
 * list, the earlier findings, the engine id) makes the affected groups run again. Same synthetic app as IrSsaGroupsTest: k flows Ek -> Hub / Sk, groups of 3 flows sharing the hub.
 */
public class IrGroupCacheTest {
    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

    private static String cls(String type, String sup, String mods, String sig, int locals, String... lines) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        sb.append(".method public ").append(mods).append(sig).append("\n    .locals ").append(locals).append('\n');
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static void build(int k, List<String> types, List<String> texts, List<String> entries) {
        types.add("Lt/Hub;");
        texts.add(cls("Lt/Hub;", "Ljava/lang/Object;", "static ", "go()V", 0));
        for (int i = 0; i < k; i++) {
            types.add("Lt/E" + i + ";");
            texts.add(cls("Lt/E" + i + ";", "Landroid/app/Activity;", "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/Hub;->go()V", "invoke-static {}, Lt/S" + i + ";->go()V"));
            entries.add("Lt/E" + i + ";");
            types.add("Lt/S" + i + ";");
            texts.add(cls("Lt/S" + i + ";", "Ljava/lang/Object;", "static ", "go()V", 4, "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
                    "new-instance v3, Landroid/webkit/WebView;", LOAD));
        }
    }

    private static List<List<Integer>> groupsOf(int k, int per) {
        List<List<Integer>> out = new ArrayList<>();
        for (int s = 0; s < k; s += per) {
            List<Integer> g = new ArrayList<>();
            g.add(0);
            for (int i = s; i < Math.min(k, s + per); i++) { g.add(1 + 2 * i); g.add(2 + 2 * i); }
            out.add(g);
        }
        return out;
    }

    private static final class H implements SsaGroups.Host {
        final List<String> types, texts; final GroupCache cache; final String engine; final AtomicInteger reads = new AtomicInteger(); final Set<Integer> unreadable = new HashSet<>();
        H(List<String> types, List<String> texts, GroupCache cache, String engine) { this.types = types; this.texts = texts; this.cache = cache; this.engine = engine; }
        public String text(int i) throws Exception { reads.incrementAndGet(); if (unreadable.contains(i)) throw new java.io.IOException("unreadable"); return texts.get(i); }
        public String type(int i) { return types.get(i); }
        public boolean cancelled() { return false; }
        public void progress(int d, int t) { }
        public void groupFailed() { }
        public GroupCache groupCache() { return cache; }
        public String engineId() { return engine; }
    }

    private static List<String> keys(SsaGroups.Result r) {
        List<String> out = new ArrayList<>();
        for (SsaGroups.Picked p : r.picked) out.add(p.item.classType + "|" + p.item.method + "|" + p.item.at + "|" + p.item.title + "|" + p.item.detail + "|" + p.item.path + "|" + p.classIndex);
        return out;
    }

    private static GroupCache.Disk disk() throws Exception {
        File d = Files.createTempDirectory("grpcache").toFile(); d.deleteOnExit();
        return new GroupCache.Disk(d, 100);
    }

    private static SsaGroups.Result run(H h, List<List<Integer>> groups, List<String> entries, int threads) {
        return SsaGroups.run(groups, new HashSet<>(entries), new ArrayList<TaintIr.Old>(), h, 200, threads);
    }

    @Test
    public void aWarmScanGivesExactlyWhatAScanWithoutACacheGivesAndReusesEveryGroup() throws Exception {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(12, types, texts, entries);
        List<List<Integer>> groups = groupsOf(12, 3);
        GroupCache.Disk c = disk();
        SsaGroups.Result plain = run(new H(types, texts, null, "v1"), groups, entries, 1);
        SsaGroups.Result cold = run(new H(types, texts, c, "v1"), groups, entries, 1);
        H warmHost = new H(types, texts, c, "v1");
        SsaGroups.Result warm = run(warmHost, groups, entries, 2);                      // two threads: the cache must not depend on them either
        assertEquals(12, plain.picked.size());
        assertEquals(keys(plain), keys(cold)); assertEquals(keys(plain), keys(warm));
        assertEquals(0, cold.groupsCached); assertEquals(groups.size(), warm.groupsCached); assertEquals(groups.size(), warm.groupsDone);
        assertEquals(plain.stats.analyses, cold.stats.analyses); assertEquals(cold.stats.analyses, warm.stats.analyses);   // the measurement is cached too
        assertEquals(types.size(), warmHost.reads.get());                                // a warm scan reads each class once (to hash it), parses and analyses nothing
        assertEquals(0, warm.parseMs + warm.analyseMs);
    }

    @Test
    public void editingOneClassRunsOnlyTheGroupsThatContainItAndStillMatchesAFreshScan() throws Exception {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(12, types, texts, entries);
        List<List<Integer>> groups = groupsOf(12, 3);                                     // 4 groups; flow 4 lives in group 1
        GroupCache.Disk c = disk();
        run(new H(types, texts, c, "v1"), groups, entries, 1);
        List<String> edited = new ArrayList<>(texts);
        edited.set(2 + 2 * 4, edited.get(2 + 2 * 4).replace(GET, "nop"));                 // S4 no longer reads the Intent: its flow is gone
        SsaGroups.Result fresh = run(new H(types, edited, null, "v1"), groups, entries, 1);
        SsaGroups.Result cached = run(new H(types, edited, c, "v1"), groups, entries, 1);
        assertEquals(11, fresh.picked.size()); assertEquals(keys(fresh), keys(cached));
        assertEquals(groups.size() - 1, cached.groupsCached);                             // only group 1 was analysed again
        assertEquals(groups.size(), run(new H(types, edited, c, "v1"), groups, entries, 1).groupsCached);   // and now the edited app is warm too
    }

    @Test
    public void anythingThatCouldChangeAResultInvalidatesTheKeys() throws Exception {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(6, types, texts, entries);
        List<List<Integer>> groups = groupsOf(6, 3);
        GroupCache.Disk c = disk();
        run(new H(types, texts, c, "v1"), groups, entries, 1);
        assertEquals(0, run(new H(types, texts, c, "v2"), groups, entries, 1).groupsCached);          // another engine id (a new app version)
        List<String> fewer = new ArrayList<>(entries); fewer.remove(0);
        SsaGroups.Result noEntry = run(new H(types, texts, c, "v1"), groups, fewer, 1);
        assertEquals(0, noEntry.groupsCached);                                                         // another entry list: reachability differs
        assertEquals(keys(run(new H(types, texts, null, "v1"), groups, fewer, 1)), keys(noEntry));
        List<TaintIr.Old> old = new ArrayList<>(); old.add(new TaintIr.Old("Lt/S0;->go()V", "Untrusted input is loaded into a WebView"));
        assertEquals(0, SsaGroups.run(groups, new HashSet<>(entries), old, new H(types, texts, c, "v1"), 200, 1).groupsCached);   // other earlier findings
        assertEquals(groups.size(), run(new H(types, texts, c, "v1"), groups, entries, 1).groupsCached);     // twin: the original inputs still hit
    }

    @Test
    public void aGroupWithAnUnreadableClassIsNeverCachedAndAHalfWrittenFileIsAMiss() throws Exception {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>(), entries = new ArrayList<>();
        build(6, types, texts, entries);
        List<List<Integer>> groups = groupsOf(6, 3);
        GroupCache.Disk c = disk();
        H bad = new H(types, texts, c, "v1"); bad.unreadable.add(2 + 2 * 4);                          // a class of group 1 cannot be read
        run(bad, groups, entries, 1);
        H again = new H(types, texts, c, "v1"); again.unreadable.add(2 + 2 * 4);
        assertEquals(1, run(again, groups, entries, 1).groupsCached);                                  // group 0 yes, group 1 never
        // truncate every stored file: all misses, same result
        GroupCache.Disk c2 = disk();
        run(new H(types, texts, c2, "v1"), groups, entries, 1);
        File dir = (File) getField(c2, "dir");
        for (File f : dir.listFiles()) { byte[] b = Files.readAllBytes(f.toPath()); Files.write(f.toPath(), java.util.Arrays.copyOf(b, b.length / 2)); }
        SsaGroups.Result r = run(new H(types, texts, c2, "v1"), groups, entries, 1);
        assertEquals(0, r.groupsCached); assertEquals(keys(run(new H(types, texts, null, "v1"), groups, entries, 1)), keys(r));
    }

    private static Object getField(Object o, String name) throws Exception {
        java.lang.reflect.Field f = o.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(o);
    }

    @Test
    public void everyFieldOfAnItemAndOfTheMeasurementSurvivesTheDisk() throws Exception {
        GroupCache.Disk c = disk();
        List<SsaBridge.Item> items = new ArrayList<>();
        items.add(new SsaBridge.Item("Lt/S;", "Lt/S;->go()V", 77, "Untrusted input is loaded into a WebView", "CWE-79", "HIGH", "MEDIUM", "fix text é中", "Data from Intent.getStringExtra() reaches loadUrl",
                true, "Lt/E;->onCreate()V", "E.onCreate -> S.go", 3, "Lt/E;->onCreate()V", "Intent.getStringExtra -> S.go -> loadUrl"));
        items.add(new SsaBridge.Item("Lt/T;", "m", 0, "x", "", "LOW", "", "", "", false, "", "", 1, "", ""));
        TaintIr.Stats st = new TaintIr.Stats();
        st.analyses = 41; st.outOfScope[0] = 1; st.outOfScope[1] = 2; st.unresolved[0] = 3; st.unresolved[1] = 4; st.library[0] = 5; st.library[1] = 6;
        st.capRefs = 7; st.capRounds = 8; st.capRequeue = 9; st.capApprox = 10; st.owners.put("fo6", 210L); st.owners.put("np2", 131L);
        st.slowest.add(new TaintIr.Stats.Slow("Lt/S;->go()V", 123456789L, 4, 55, 2));
        c.store("abc", items, st);
        GroupCache.Entry e = c.load("abc");
        assertNotNull(e); assertEquals(2, e.items.size());
        SsaBridge.Item a = e.items.get(0), b = items.get(0);
        assertEquals(b.classType, a.classType); assertEquals(b.method, a.method); assertEquals(b.at, a.at); assertEquals(b.title, a.title); assertEquals(b.cwe, a.cwe); assertEquals(b.sev, a.sev);
        assertEquals(b.confidence, a.confidence); assertEquals(b.fix, a.fix); assertEquals(b.detail, a.detail); assertEquals(b.reachable, a.reachable); assertEquals(b.entry, a.entry);
        assertEquals(b.path, a.path); assertEquals(b.count, a.count); assertEquals(b.sourceMethod, a.sourceMethod); assertEquals(b.dataPath, a.dataPath);
        assertFalse(e.items.get(1).reachable);
        assertEquals(41, e.stats.analyses); assertEquals(2, e.stats.outOfScope[1]); assertEquals(4, e.stats.unresolved[1]); assertEquals(6, e.stats.library[1]);
        assertEquals(10, e.stats.capApprox); assertEquals(Long.valueOf(210L), e.stats.owners.get("fo6")); assertEquals(1, e.stats.slowest.size()); assertEquals(4, e.stats.slowest.get(0).runs);
        assertNull(c.load("missing"));
    }

    @Test
    public void theOldestFilesGoWhenThereAreTooMany() throws Exception {
        File d = Files.createTempDirectory("grpcache2").toFile(); d.deleteOnExit();
        GroupCache.Disk c = new GroupCache.Disk(d, 3);
        TaintIr.Stats st = new TaintIr.Stats();
        for (int i = 0; i < 6; i++) { c.store("k" + i, new ArrayList<SsaBridge.Item>(), st); new File(d, "k" + i + ".grp").setLastModified(1000L * (i + 1)); }
        c.store("k6", new ArrayList<SsaBridge.Item>(), st);
        assertEquals(3, d.listFiles((x, n) -> n.endsWith(".grp")).length);
        assertNotNull(c.load("k6")); assertNull(c.load("k0"));
    }
}
