package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.68.3 (from the NewPipe measurement): container classes the code names directly (AbstractCollection, LinkedHashSet ...) are containers,
 * System.arraycopy copies the taint of the source array, and primitive results / UI setters are not counted as lost taint.
 */
public class IrCollectionsArraycopyTest {

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
    public void aLinkedHashSetKeepsTheTaintOfWhatWasAdded() {
        TaintIr.Result r = run(
                "new-instance v3, Ljava/util/LinkedHashSet;",
                "invoke-virtual {v3, v2}, Ljava/util/LinkedHashSet;->add(Ljava/lang/Object;)Z",
                "invoke-virtual {v3}, Ljava/util/LinkedHashSet;->iterator()Ljava/util/Iterator;", "move-result-object v4",
                "invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;", "move-result-object v5",
                "invoke-virtual {v1, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(1, r.flows.size());
        assertEquals("Intent.getStringExtra()", r.flows.get(0).source);
    }

    @Test
    public void iteratorOfATaintedAbstractCollectionCarriesTheTaint() {
        TaintIr.Result r = run(
                "invoke-virtual {v2}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;", "move-result-object v3",
                "invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;", "move-result-object v4",
                "invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(1, r.flows.size());
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void arraycopyMovesTheTaintToTheDestinationArray() {
        TaintIr.Result r = run(
                "const/4 v3, 0x1", "const/4 v6, 0x0",
                "new-array v4, v3, [Ljava/lang/String;", "new-array v5, v3, [Ljava/lang/String;",
                "aput-object v2, v4, v6",
                "invoke-static {v4, v6, v5, v6, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
                "aget-object v0, v5, v6",
                "invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(1, r.flows.size());
        assertEquals("Intent.getStringExtra()", r.flows.get(0).source);
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void anArrayThatWasNotCopiedIntoStaysClean() {
        TaintIr.Result r = run(
                "const/4 v3, 0x1", "const/4 v6, 0x0",
                "new-array v4, v3, [Ljava/lang/String;", "new-array v5, v3, [Ljava/lang/String;",
                "aput-object v2, v4, v6",
                "aget-object v0, v5, v6",
                "invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(0, r.flows.size());
    }

    @Test
    public void aPrimitiveResultAndAUiSetterAreNotCountedAsLosses() {
        TaintIr.Result r = run(
                "invoke-static {v2}, Landroid/os/Foo;->count(Ljava/lang/String;)I",
                "invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V");
        assertEquals(0, r.stats.library[0]);
        assertTrue(r.stats.owners.isEmpty());
    }

    @Test
    public void aStringResultFromAnUnknownLibraryCallIsStillCounted() {
        TaintIr.Result r = run("invoke-static {v2}, Landroid/os/Foo;->bar(Ljava/lang/String;)Ljava/lang/String;");
        assertEquals(1, r.stats.library[0]);
    }

    @Test
    public void aDesugaringCompanionStringHelperHandsTheTaintToItsResult() {
        TaintIr.Result r = run(
                "const-string v3, \"p\"",
                "invoke-static {v3, v2}, Landroidx/x/Owner$-CC;->m(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", "move-result-object v4",
                "invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(1, r.flows.size());
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void aCompanionHelperWithAnObjectParameterIsNotTreatedAsConcatenation() {
        TaintIr.Result r = run(
                "invoke-static {v2, v0}, Landroidx/x/Owner$-CC;->m(Ljava/lang/String;Landroid/content/Intent;)Ljava/lang/String;", "move-result-object v4",
                "invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(0, r.flows.size());
        assertEquals(1, r.stats.library[0]);
    }

    @Test
    public void aStaticStringHelperOutsideACompanionClassStaysUnknown() {
        TaintIr.Result r = run(
                "invoke-static {v2, v2}, Landroidx/x/Owner;->m(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", "move-result-object v4",
                "invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(0, r.flows.size());
    }
}
