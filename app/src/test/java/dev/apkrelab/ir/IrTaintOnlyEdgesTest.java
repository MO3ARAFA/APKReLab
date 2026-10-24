package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.66.7: methods that no entry reaches get call edges for the TAINT engine only (static / direct / super exact, virtual /
 * interface by CHA). Before this, a source -> sink chain that passed through such code lost its taint at the first call out
 * of it. Reachability and every other graph query must stay as they were. Tiny hand-written smali.
 */
public class IrTaintOnlyEdgesTest {

    private static final String OBJ = "Ljava/lang/Object;";
    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2"};

    private static String[] cat(String[] a, String... b) {
        String[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static String m(int locals, String flagsAndSig, String... lines) {
        StringBuilder sb = new StringBuilder(".method " + flagsAndSig + "\n    .locals " + locals + "\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String cls(String flags, String type, String sup, String[] ifaces, String... methods) {
        StringBuilder sb = new StringBuilder(".class " + flags + " " + type + "\n.super " + sup + "\n");
        for (String i : ifaces) sb.append(".implements ").append(i).append('\n');
        sb.append('\n');
        for (String x : methods) sb.append(x).append('\n');
        return sb.toString();
    }

    private static String cls(String type, String sup, String... methods) {
        return cls("public", type, sup, new String[0], methods);
    }

    /** The entry component. It calls nothing of the rest, so everything else is "not reachable". */
    private static String entry() {
        return cls("Lt/A;", "Landroid/app/Activity;", m(2, "public onCreate(Landroid/os/Bundle;)V"));
    }

    private static CallGraph graph(String... texts) {
        List<ClassIr> cs = new ArrayList<>();
        for (String t : texts) cs.add(SmaliParser.parse(t));
        return CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
    }

    private static final String SINK_STATIC = m(2, "public static sinkIt(Ljava/lang/String;)V",
            "new-instance v0, Landroid/webkit/WebView;", "invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");

    @Test
    public void staticCallOutOfUnreachableCodeKeepsTheTaint() {
        CallGraph g = graph(entry(),
                cls("Lt/B;", OBJ, m(4, "public static go()V", cat(SRC, "invoke-static {v2}, Lt/C;->sinkIt(Ljava/lang/String;)V"))),
                cls("Lt/C;", OBJ, SINK_STATIC));
        assertFalse(g.isReachable("Lt/B;->go()V"));
        assertFalse(g.isReachable("Lt/C;->sinkIt(Ljava/lang/String;)V"));
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        assertEquals(1, r.flows.size());
        TaintIr.Flow f = r.flows.get(0);
        assertEquals("Intent.getStringExtra()", f.source);
        assertEquals(Arrays.asList("Lt/B;->go()V", "Lt/C;->sinkIt(Ljava/lang/String;)V"), f.chain);
        assertFalse(f.reachable);                            // still honest: no entry gets there
        assertEquals(0, r.stats.unresolved[0]);
    }

    @Test
    public void theSameChainFromAReachableMethodWasAlreadyFound() {
        CallGraph g = graph(
                cls("Lt/A;", "Landroid/app/Activity;", m(4, "public onCreate(Landroid/os/Bundle;)V",
                        cat(SRC, "invoke-static {v2}, Lt/C;->sinkIt(Ljava/lang/String;)V"))),
                cls("Lt/C;", OBJ, SINK_STATIC));
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        assertEquals(1, r.flows.size());
        assertTrue(r.flows.get(0).reachable);
        assertEquals(0, g.taintOnlyEdges);                   // nothing to add: every caller is reachable
    }

    @Test
    public void interfaceCallOutOfUnreachableCodeUsesEveryConcreteImplementation() {
        CallGraph g = graph(entry(),
                cls("public interface abstract", "Lt/I;", OBJ, new String[0], ".method public abstract put(Ljava/lang/String;)V\n.end method\n"),
                cls("public", "Lt/Safe;", OBJ, new String[]{"Lt/I;"}, m(1, "public put(Ljava/lang/String;)V")),
                cls("public", "Lt/Web;", OBJ, new String[]{"Lt/I;"}, m(2, "public put(Ljava/lang/String;)V",
                        "new-instance v0, Landroid/webkit/WebView;", "invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")),
                cls("Lt/B;", OBJ, m(5, "public static go(Lt/I;)V", cat(SRC, "invoke-interface {p0, v2}, Lt/I;->put(Ljava/lang/String;)V"))));
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        assertEquals(1, r.flows.size());
        assertEquals(Arrays.asList("Lt/B;->go(Lt/I;)V", "Lt/Web;->put(Ljava/lang/String;)V"), r.flows.get(0).chain);
        assertEquals(2, g.taintEdgesFrom("Lt/B;->go(Lt/I;)V").size() - countExternal(g, "Lt/B;->go(Lt/I;)V"));
    }

    private static int countExternal(CallGraph g, String key) {
        int n = 0;
        for (CallGraph.Edge e : g.taintEdgesFrom(key)) if (e.external) n++;
        return n;
    }

    @Test
    public void reachabilityAndTheNormalQueriesDoNotChange() {
        CallGraph g = graph(entry(),
                cls("Lt/B;", OBJ, m(4, "public static go()V", "invoke-static {}, Lt/C;->run()V")),
                cls("Lt/C;", OBJ, m(1, "public static run()V")));
        assertFalse(g.isReachable("Lt/B;->go()V"));
        assertFalse(g.isReachable("Lt/C;->run()V"));
        assertTrue(g.edgesFrom("Lt/B;->go()V").isEmpty());   // the graph's own edge list stays empty
        assertTrue(g.edgesTo("Lt/C;->run()V").isEmpty());
        assertTrue(g.callersOf("Lt/C;->run()V").isEmpty());
        assertEquals(1, g.taintEdgesFrom("Lt/B;->go()V").size());
        assertTrue(g.taintCallersOf("Lt/C;->run()V").contains("Lt/B;->go()V"));
        assertEquals(1, g.taintOnlyEdges);
        assertEquals(2, g.methods.size() - 1 /* onCreate */);
        assertEquals(1, g.reachable.size());                 // only onCreate
    }

    @Test
    public void aSinkCallIsNotCountedAsADroppedLibraryCall() {
        CallGraph g = graph(cls("Lt/A;", "Landroid/app/Activity;", m(4, "public onCreate(Landroid/os/Bundle;)V",
                cat(SRC, "new-instance v3, Landroid/webkit/WebView;",
                        "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V"))));
        TaintIr.Result r = TaintIr.analyze(g, true, null);
        assertEquals(1, r.flows.size());                     // the flow is reported ...
        assertEquals(0, r.stats.library[0]);                 // ... so it is not also a "drop"
        assertTrue(r.stats.owners.isEmpty());
    }

    @Test
    public void aLibraryCallThatIsNotASinkIsStillCounted() {
        CallGraph g = graph(cls("Lt/A;", "Landroid/app/Activity;", m(4, "public onCreate(Landroid/os/Bundle;)V",
                cat(SRC, "invoke-static {v2}, Lcom/lib/Foo;->enc(Ljava/lang/String;)Ljava/lang/String;"))));
        TaintIr.Result r = TaintIr.analyze(g, true, null);
        assertEquals(1, r.stats.library[0]);
        assertEquals(Long.valueOf(1L), r.stats.owners.get("com/lib/Foo"));
    }
}
