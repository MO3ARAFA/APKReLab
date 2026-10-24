package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.68.1: Intrinsics.stringPlus passes the taint on; Number.*Value and Activity launches are not counted as lost taint (counter only). */
public class IrIntrinsicsTest {

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
    public void stringPlusCarriesTheTaintToASink() {
        TaintIr.Result r = run(
                "const-string v3, \"x\"",
                "invoke-static {v2, v3}, Lkotlin/jvm/internal/Intrinsics;->stringPlus(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;",
                "move-result-object v4",
                "invoke-virtual {v5, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V");
        assertEquals(1, r.flows.size());
        assertEquals("Intent.getStringExtra()", r.flows.get(0).source);
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void numberValueIsNotCounted() {
        TaintIr.Result r = run("invoke-virtual {v2}, Ljava/lang/Number;->intValue()I");
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void activityLaunchIsNotCountedButOtherActivityCallsAre() {
        TaintIr.Result r = run("invoke-virtual {v6, v2}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V");
        assertEquals(0, r.stats.library[0]);
        TaintIr.Result r2 = run("invoke-virtual {v6, v2}, Landroid/app/Activity;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;");
        assertEquals(1, r2.stats.library[0]);
    }
}
