package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.67.1: android.util.Log is not counted as a lost taint (counter only); Iterable.iterator() passes the collection's taint on. */
public class IrLogIterableTest {

    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"",
            "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2"};

    private static TaintIr.Result run(String... body) {
        StringBuilder sb = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        for (String l : SRC) sb.append("    ").append(l).append('\n');
        for (String l : body) sb.append("    ").append(l).append('\n');
        sb.append("    return-void\n.end method\n");
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(sb.toString()));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null);
    }

    @Test
    public void logIsNotCountedAsALoss() {
        TaintIr.Result r = run("const-string v3, \"tag\"",
                "invoke-static {v3, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I");
        assertEquals(0, r.stats.library[0]);
        assertTrue(r.stats.owners.isEmpty());
    }

    @Test
    public void anotherAndroidCallIsStillCounted() {
        TaintIr.Result r = run("invoke-static {v2}, Landroid/os/Foo;->bar(Ljava/lang/String;)V");
        assertEquals(1, r.stats.library[0]);
    }

    @Test
    public void iteratorOfATaintedIterableCarriesTheTaintToASink() {
        TaintIr.Result r = run(
                "invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;", "move-result-object v3",
                "invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;", "move-result-object v4",
                "invoke-virtual {v5, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(1, r.flows.size());
        assertEquals("Intent.getStringExtra()", r.flows.get(0).source);
        assertEquals(0, r.stats.library[0]);
    }
}
