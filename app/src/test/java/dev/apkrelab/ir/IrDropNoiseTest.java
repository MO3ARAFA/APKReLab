package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.66.9: Kotlin null checks and java/lang exception constructors are not counted as library drops (counter only). Tiny hand-written smali. */
public class IrDropNoiseTest {

    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2"};

    private static TaintIr.Result run(String... body) {
        StringBuilder sb = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n");
        for (String l : SRC) sb.append("    ").append(l).append('\n');
        for (String l : body) sb.append("    ").append(l).append('\n');
        sb.append("    return-void\n.end method\n");
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(sb.toString()));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null);
    }

    @Test
    public void kotlinNullCheckIsNotCounted() {
        TaintIr.Result r = run("invoke-static {v2, v1}, Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter(Ljava/lang/Object;Ljava/lang/String;)V");
        assertEquals(0, r.stats.library[0]);
        assertTrue(r.stats.owners.isEmpty());
    }

    @Test
    public void intrinsicsThatReturnABooleanIsNotCounted() {
        TaintIr.Result r = run("invoke-static {v2, v1}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z");
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void intrinsicsThatReturnsAStringIsNotADropAnyMore() {
        // 0.68.1: it is modelled (the taint goes to the result), see IrIntrinsicsTest
        TaintIr.Result r = run("invoke-static {v2, v1}, Lkotlin/jvm/internal/Intrinsics;->stringPlus(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;");
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void exceptionConstructorIsNotCounted() {
        TaintIr.Result r = run("new-instance v3, Ljava/lang/IllegalArgumentException;",
                "invoke-direct {v3, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V");
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void anotherLibraryCallIsStillCounted() {
        TaintIr.Result r = run("invoke-static {v2}, Lcom/gms/Foo;->wrap(Ljava/lang/String;)Ljava/lang/String;");
        assertEquals(1, r.stats.library[0]);
        assertEquals(Long.valueOf(1L), r.stats.owners.get("com/gms/Foo"));
    }
}
