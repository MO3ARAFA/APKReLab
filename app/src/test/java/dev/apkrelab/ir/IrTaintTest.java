package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.55.0 (P1): tests for {@link TaintIr} on tiny hand-written smali. No APK, no device. */
public class IrTaintTest {

    private static final String OBJ = "Ljava/lang/Object;";
    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";
    private static final String ON_CREATE = "Lt/A;->onCreate(Landroid/os/Bundle;)V";

    private static String mm(int locals, String sig, String... lines) {
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals " + locals + "\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String mr(int locals, String sig, String... lines) { // method that returns an object (last line is the return)
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals " + locals + "\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append(".end method\n").toString();
    }

    private static String cls(String type, String sup, String... methods) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        for (String x : methods) sb.append(x).append('\n');
        return sb.toString();
    }

    private static String act(String... methods) {
        return cls("Lt/A;", "Landroid/app/Activity;", methods);
    }

    private static String onCreate(String... body) {
        return mm(4, "onCreate(Landroid/os/Bundle;)V", body);
    }

    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2"};

    private static String[] cat(String[] a, String... b) {
        String[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static TaintIr.Result run(boolean reachableOnly, String... texts) {
        List<ClassIr> cs = new ArrayList<>();
        for (String t : texts) cs.add(SmaliParser.parse(t));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, reachableOnly, null);
    }

    private static TaintIr.Result run(String... texts) {
        return run(true, texts);
    }

    @Test
    public void intentExtraStraightToWebView() {
        TaintIr.Result r = run(act(onCreate(cat(SRC, "new-instance v3, Landroid/webkit/WebView;", LOAD))));
        assertEquals(1, r.flows.size());
        TaintIr.Flow f = r.flows.get(0);
        assertEquals("Intent.getStringExtra()", f.source);
        assertEquals(Arrays.asList(ON_CREATE), f.chain);
        assertTrue(f.reachable);
        assertEquals(Arrays.asList(ON_CREATE), f.entryPath);
        assertEquals("Untrusted input is loaded into a WebView", f.sink.title);
        assertFalse(f.crossesMethods());
    }

    @Test
    public void constantNeverFlows() {
        TaintIr.Result r = run(act(onCreate("const-string v2, \"https://x\"", "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        assertEquals(0, r.flows.size());
    }

    @Test
    public void sanitizerStopsTheFlow() {
        TaintIr.Result r = run(act(onCreate(cat(SRC,
                "invoke-static {v2}, Ljava/net/URLEncoder;->encode(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2",
                "new-instance v3, Landroid/webkit/WebView;", LOAD))));
        assertEquals(0, r.flows.size());
    }

    @Test
    public void stringBuilderCarriesTheTaint() {
        TaintIr.Result r = run(act(onCreate(cat(SRC,
                "new-instance v0, Ljava/lang/StringBuilder;", "invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V",
                "invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
                "invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;", "move-result-object v2",
                "new-instance v3, Landroid/webkit/WebView;", LOAD))));
        assertEquals(1, r.flows.size());
    }

    @Test
    public void builderAliasedThroughMoveIsStillTainted() {
        // v1 = sb; v3 = v1 (alias); append on the alias; toString on the original
        TaintIr.Result r = run(act(mm(6, "onCreate(Landroid/os/Bundle;)V",
                "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
                "new-instance v4, Ljava/lang/StringBuilder;", "invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V",
                "move-object v5, v4",
                "invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
                "invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;", "move-result-object v2",
                "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        assertEquals(1, r.flows.size());
    }

    @Test
    public void phiJoinsOneTaintedBranch() {
        TaintIr.Result r = run(act(mm(4, "onCreate(Landroid/os/Bundle;)V",
                "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"",
                "if-eqz p1, :c", GET, "move-result-object v2", "goto :j",
                ":c", "const-string v2, \"safe\"", ":j",
                "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        assertEquals(1, r.flows.size());
    }

    @Test
    public void sourceIntoCalleeParameterReachesSinkInCallee() {
        TaintIr.Result r = run(
                act(onCreate(cat(SRC, "new-instance v3, Lt/B;", "invoke-virtual {v3, v2}, Lt/B;->show(Ljava/lang/String;)V"))),
                cls("Lt/B;", OBJ, mm(3, "show(Ljava/lang/String;)V", "new-instance v0, Landroid/webkit/WebView;",
                        "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")));
        assertEquals(1, r.flows.size());
        TaintIr.Flow f = r.flows.get(0);
        assertEquals(Arrays.asList(ON_CREATE, "Lt/B;->show(Ljava/lang/String;)V"), f.chain);
        assertEquals("Lt/B;->show(Ljava/lang/String;)V", f.sink.method);
        assertTrue(f.crossesMethods());
        assertTrue(f.reachable);
    }

    @Test
    public void calleeReturnsTheSourceAndCallerHasTheSink() {
        TaintIr.Result r = run(
                act(onCreate("new-instance v3, Lt/B;", "invoke-virtual {v3}, Lt/B;->get()Ljava/lang/String;", "move-result-object v2",
                        "new-instance v3, Landroid/webkit/WebView;", LOAD)),
                cls("Lt/B;", OBJ, mr(3, "get()Ljava/lang/String;", "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET,
                        "move-result-object v2", "return-object v2")));
        assertEquals(1, r.flows.size());
        assertEquals("B.get()Ljava/lang/String;", r.flows.get(0).via);
        assertEquals(Arrays.asList(ON_CREATE), r.flows.get(0).chain);
    }

    @Test
    public void threeLevelChainAndShortestChainIsKept() {
        TaintIr.Result r = run(
                act(onCreate(cat(SRC, "new-instance v3, Lt/B;", "invoke-virtual {v3, v2}, Lt/B;->a(Ljava/lang/String;)V"))),
                cls("Lt/B;", OBJ,
                        mm(3, "a(Ljava/lang/String;)V", "new-instance v0, Lt/C;", "invoke-virtual {v0, p1}, Lt/C;->b(Ljava/lang/String;)V"),
                        ""),
                cls("Lt/C;", OBJ, mm(3, "b(Ljava/lang/String;)V", "new-instance v0, Landroid/webkit/WebView;",
                        "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")));
        assertEquals(1, r.flows.size());
        assertEquals(3, r.flows.get(0).chain.size());
        assertEquals(Arrays.asList(ON_CREATE), r.flows.get(0).entryPath);
    }

    @Test
    public void unreachableMethodIsSkippedUnlessAskedFor() {
        String dead = cls("Lt/D;", OBJ, mm(4, "dead()V", "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET,
                "move-result-object v2", "new-instance v3, Landroid/webkit/WebView;", LOAD));
        assertEquals(0, run(true, act(onCreate()), dead).flows.size());
        TaintIr.Result all = run(false, act(onCreate()), dead);
        assertEquals(1, all.flows.size());
        assertFalse(all.flows.get(0).reachable);
    }

    @Test
    public void parameterAloneIsNotAFlow() {
        TaintIr.Result r = run(
                act(onCreate("new-instance v3, Lt/B;", "const-string v2, \"fixed\"", "invoke-virtual {v3, v2}, Lt/B;->show(Ljava/lang/String;)V")),
                cls("Lt/B;", OBJ, mm(3, "show(Ljava/lang/String;)V", "new-instance v0, Landroid/webkit/WebView;",
                        "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")));
        assertEquals(0, r.flows.size());
        assertTrue(r.nonEmptySummaries >= 1);
    }

    @Test
    public void fieldCarriesARealSourceBetweenMethods() {
        TaintIr.Result r = run(
                act(onCreate(cat(SRC, "sput-object v2, Lt/A;->saved:Ljava/lang/String;", "new-instance v3, Lt/B;", "invoke-virtual {v3}, Lt/B;->go()V")),
                        ""),
                cls("Lt/B;", OBJ, mm(3, "go()V", "sget-object v2, Lt/A;->saved:Ljava/lang/String;", "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        assertEquals(1, r.flows.size());
        assertTrue(r.flows.get(0).via.startsWith("field "));
    }

    @Test
    public void interfaceCallFollowsTheRtaEdgeToTheImplementation() {
        TaintIr.Result r = run(
                act(onCreate(cat(SRC, "new-instance v3, Lt/Impl;", "invoke-interface {v3, v2}, Lt/I;->show(Ljava/lang/String;)V"))),
                ".class public interface abstract Lt/I;\n.super Ljava/lang/Object;\n\n.method public abstract show(Ljava/lang/String;)V\n.end method\n",
                ".class public Lt/Impl;\n.super Ljava/lang/Object;\n.implements Lt/I;\n\n" + mm(3, "show(Ljava/lang/String;)V",
                        "new-instance v0, Landroid/webkit/WebView;", "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"));
        assertEquals(1, r.flows.size());
        assertEquals("Lt/Impl;->show(Ljava/lang/String;)V", r.flows.get(0).sink.method);
    }

    @Test
    public void wideParameterDoesNotShiftTheArguments() {
        // static go(J, String): the long takes v0/v1 in the invoke, the string is the third register
        TaintIr.Result r = run(
                act(onCreate("new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
                        "const-wide v0, 0x5L", "invoke-static {v0, v1, v2}, Lt/B;->go(JLjava/lang/String;)V")),
                cls("Lt/B;", OBJ, ".method public static go(JLjava/lang/String;)V\n    .locals 2\n    new-instance v0, Landroid/webkit/WebView;\n" +
                        "    invoke-virtual {v0, p2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n"));
        assertEquals(1, r.flows.size());
    }

    @Test
    public void wideParameterBeforeCleanArgumentGivesNoFlow() {
        // the tainted string is argument 1 of go, but the sink uses the long's slot only: must not be confused
        TaintIr.Result r = run(
                act(onCreate("new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
                        "const-wide v0, 0x5L", "invoke-static {v0, v1, v2}, Lt/B;->go(JLjava/lang/String;)V")),
                cls("Lt/B;", OBJ, ".method public static go(JLjava/lang/String;)V\n    .locals 2\n    new-instance v0, Landroid/webkit/WebView;\n" +
                        "    const-string v1, \"x\"\n    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n"));
        assertEquals(0, r.flows.size());
    }

    @Test
    public void recursionTerminates() {
        TaintIr.Result r = run(
                act(onCreate(cat(SRC, "new-instance v3, Lt/B;", "invoke-virtual {v3, v2}, Lt/B;->loop(Ljava/lang/String;)V"))),
                cls("Lt/B;", OBJ, mm(3, "loop(Ljava/lang/String;)V", "invoke-virtual {p0, p1}, Lt/B;->loop(Ljava/lang/String;)V",
                        "new-instance v0, Landroid/webkit/WebView;", "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")));
        assertEquals(1, r.flows.size());
        assertEquals(0, r.failed);
    }

    @Test
    public void sharedPreferencesIsAWeakerSource() {
        TaintIr.Result r = run(act(mm(5, "onCreate(Landroid/os/Bundle;)V",
                "const-string v1, \"k\"", "const-string v4, \"d\"",
                "invoke-interface {v0, v1, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                "move-result-object v2", "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        assertEquals(1, r.flows.size());
        assertEquals(1, r.flows.get(0).level);
    }

    @Test
    public void compareAgainstOldFindingsAndReportText() {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(act(onCreate(cat(SRC, "new-instance v3, Landroid/webkit/WebView;", LOAD)))));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        List<TaintIr.Old> old = new ArrayList<>();
        old.add(new TaintIr.Old(ON_CREATE, "Untrusted input is loaded into a WebView"));
        old.add(new TaintIr.Old("Lt/Z;->gone()V", "Untrusted input reaches an SQL statement"));
        TaintIr.Result r = TaintIr.analyze(g, true, old);
        assertTrue(r.compareText.contains("both: 1, only old: 1, only new: 0"));
        assertTrue(r.format().contains("ONLY OLD"));
        assertTrue(r.format().contains("chain:"));
    }


    @Test
    public void flowInAClassWhoseOldCardWasMergedIsNotCountedAsNew() {
        // the scanner merges same-title findings of one class into one card kept at the first method: update() below is part of delete()'s card
        String p = cls("Lt/P;", "Landroid/content/ContentProvider;",
                mr(4, "delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
                        "new-instance v0, Landroid/database/sqlite/SQLiteDatabase;", "const-string v1, \"t\"",
                        "invoke-virtual {v0, v1, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I",
                        "move-result v2", "return v2"),
                mr(4, "update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
                        "new-instance v0, Landroid/database/sqlite/SQLiteDatabase;", "const-string v1, \"t\"",
                        "invoke-virtual {v0, v1, p2, p3, p4}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
                        "move-result v2", "return v2"));
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(act(onCreate())));
        cs.add(SmaliParser.parse(p));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;", "Lt/P;"), CallGraph.Mode.RTA, null);
        List<TaintIr.Old> old = new ArrayList<>();
        old.add(new TaintIr.Old("Lt/P;->delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I", "Untrusted input reaches an SQL statement"));
        TaintIr.Result r = TaintIr.analyze(g, true, old);
        assertTrue(r.compareText, r.compareText.contains("both: 1, only old: 0, only new: 0, same class and title as an old card"));
        assertTrue(r.compareText.contains("MERGED"));
        assertFalse(r.compareText.contains("ONLY NEW"));
    }

    @Test
    public void contentProviderParametersAreSources() {
        String prov = cls("Lt/P;", "Landroid/content/ContentProvider;", mr(4,
                "delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
                "new-instance v0, Landroid/database/sqlite/SQLiteDatabase;", "const-string v1, \"t\"",
                "invoke-virtual {v0, v1, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I",
                "move-result v2", "return v2"));
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(act(onCreate())));
        cs.add(SmaliParser.parse(prov));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;", "Lt/P;"), CallGraph.Mode.RTA, null);
        TaintIr.Result r = TaintIr.analyze(g, true, null);
        assertEquals(1, r.flows.size());
        assertEquals(1, r.flows.get(0).level);
        assertEquals("Untrusted input reaches an SQL statement", r.flows.get(0).sink.title);
    }

    @Test
    public void sameMethodOnANonProviderClassIsNotASource() {
        String plain = cls("Lt/P;", OBJ, mr(4, "delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
                "new-instance v0, Landroid/database/sqlite/SQLiteDatabase;", "const-string v1, \"t\"",
                "invoke-virtual {v0, v1, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I",
                "move-result v2", "return v2"));
        assertEquals(0, run(false, act(onCreate()), plain).flows.size());
    }

    @Test
    public void flowInAClassNoEntryReachesIsStillReportedAndMarkedNotReachable() {
        // the real InjuredAndroid FlagTwelveProtectedActivity case: the old engine reports it, so the new one must too
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(act(onCreate())));
        cs.add(SmaliParser.parse(cls("Lt/Hidden;", "Landroidx/appcompat/app/c;", mm(4, "onCreate(Landroid/os/Bundle;)V",
                "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
                "new-instance v3, Landroid/webkit/WebView;", LOAD))));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        assertEquals(0, TaintIr.analyze(g, true, null).flows.size());
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        assertEquals(1, r.flows.size());
        assertFalse(r.flows.get(0).reachable);
        assertTrue(r.format().contains("not reachable in the call graph"));
        assertTrue(r.format().contains("every app method"));
    }

    // ---------- fuzz: random call graphs with recursion, fields, builders and diamonds must terminate without failures ----------

    private static List<String> fuzzClasses(long seed) {
        java.util.Random rnd = new java.util.Random(seed);
        int nc = 12, nm = 5;
        List<String> out = new ArrayList<>();
        out.add(act(mm(6, "onCreate(Landroid/os/Bundle;)V", "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET,
                "move-result-object v2", "invoke-static {v2}, Lt/F0;->m0(Ljava/lang/String;)Ljava/lang/String;")));
        int label = 0;
        for (int c = 0; c < nc; c++) {
            StringBuilder cls = new StringBuilder(".class public Lt/F" + c + ";\n.super Ljava/lang/Object;\n\n");
            for (int k = 0; k < nm; k++) {
                StringBuilder b = new StringBuilder(".method public static m" + k + "(Ljava/lang/String;)Ljava/lang/String;\n    .locals 6\n");
                int n = 6 + rnd.nextInt(14);
                for (int i = 0; i < n; i++) {
                    int x = rnd.nextInt(4), y = rnd.nextInt(4);
                    switch (rnd.nextInt(8)) {
                        case 0:
                            b.append("    invoke-static {v").append(y).append("}, Lt/F").append(rnd.nextInt(nc)).append(";->m").append(rnd.nextInt(nm))
                                    .append("(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v").append(x).append('\n');
                            break;
                        case 1:
                            b.append("    new-instance v4, Landroid/content/Intent;\n    const-string v5, \"u\"\n    invoke-virtual {v4, v5}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v")
                                    .append(x).append('\n');
                            break;
                        case 2:
                            b.append("    new-instance v4, Landroid/webkit/WebView;\n    invoke-virtual {v4, v").append(x).append("}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n");
                            break;
                        case 3:
                            b.append("    move-object v").append(x).append(", v").append(y).append('\n');
                            break;
                        case 4: {
                            int l = label++;
                            b.append("    if-eqz v").append(y).append(", :c").append(l).append("\n    move-object v").append(x).append(", p0\n    goto :j").append(l)
                                    .append("\n    :c").append(l).append("\n    const-string v").append(x).append(", \"s\"\n    :j").append(l).append('\n');
                            break;
                        }
                        case 5:
                            b.append("    sput-object v").append(x).append(", Lt/F").append(rnd.nextInt(nc)).append(";->f:Ljava/lang/String;\n");
                            break;
                        case 6:
                            b.append("    sget-object v").append(x).append(", Lt/F").append(rnd.nextInt(nc)).append(";->f:Ljava/lang/String;\n");
                            break;
                        default:
                            b.append("    new-instance v4, Ljava/lang/StringBuilder;\n    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V\n    invoke-virtual {v4, v")
                                    .append(y).append("}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n    move-result-object v")
                                    .append(x).append('\n');
                            break;
                    }
                }
                b.append("    return-object v").append(rnd.nextInt(4)).append("\n.end method\n");
                cls.append(b).append('\n');
            }
            out.add(cls.toString());
        }
        return out;
    }

    @Test
    public void fuzzTerminatesWithoutFailuresAndIsDeterministic() {
        for (long seed = 1; seed <= 40; seed++) {
            List<String> txt = fuzzClasses(seed);
            TaintIr.Result a = run(txt.toArray(new String[0]));
            TaintIr.Result b = run(txt.toArray(new String[0]));
            assertEquals("seed " + seed + " failures " + a.failures, 0, a.failed);
            assertEquals("seed " + seed, a.flows.size(), b.flows.size());
            assertEquals("seed " + seed, a.format().replaceAll("time \\d+ ms", ""), b.format().replaceAll("time \\d+ ms", ""));
        }
    }
}
