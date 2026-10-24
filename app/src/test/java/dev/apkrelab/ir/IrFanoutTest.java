package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.83.0: the RESULT of a call that resolves to 8 or more targets is a weak lead (FairEmail SimpleTask.onExecute). */
public class IrFanoutTest {

    private static List<TaintIr.Flow> run(int subclasses) {
        List<ClassIr> cs = new ArrayList<>();
        StringBuilder main = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n");
        for (int i = 0; i < subclasses; i++)
            main.append("    new-instance v0, Lt/S").append(i).append(";\n    invoke-direct {v0}, Lt/S").append(i).append(";-><init>()V\n");
        main.append("    invoke-virtual {v0}, Lt/Base;->run()Ljava/lang/Object;\n    move-result-object v1\n    check-cast v1, Ljava/lang/String;\n"
                + "    new-instance v2, Ljava/io/FileInputStream;\n    invoke-direct {v2, v1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n");
        cs.add(SmaliParser.parse(main.toString()));
        cs.add(SmaliParser.parse(".class public abstract Lt/Base;\n.super Ljava/lang/Object;\n\n.method public constructor <init>()V\n    .locals 0\n    return-void\n.end method\n\n"
                + ".method public abstract run()Ljava/lang/Object;\n.end method\n"));
        for (int i = 0; i < subclasses; i++) {
            String body = i == 0
                    ? "    new-instance v0, Landroid/content/Intent;\n    invoke-direct {v0}, Landroid/content/Intent;-><init>()V\n    const-string v1, \"k\"\n"
                      + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n    return-object v0\n"
                    : "    const-string v0, \"fixed\"\n    return-object v0\n";
            cs.add(SmaliParser.parse(".class public Lt/S" + i + ";\n.super Lt/Base;\n\n.method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Lt/Base;-><init>()V\n    return-void\n.end method\n\n"
                    + ".method public run()Ljava/lang/Object;\n    .locals 2\n" + body + ".end method\n"));
        }
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows;
    }

    @Test public void aResultFromManyTargetsIsWeak() {
        List<TaintIr.Flow> f = run(TaintIr.FANOUT_WEAK);
        assertTrue(!f.isEmpty());
        assertTrue(f.get(0).weak);
    }

    @Test public void aResultFromFewTargetsStaysStrong() {
        List<TaintIr.Flow> f = run(3);
        assertTrue(!f.isEmpty());
        assertFalse(f.get(0).weak);
    }

    @Test public void erasedHopsAreCountedFromTheSignatureOnly() {
        List<String> chain = Arrays.asList(
                "Lb8;->a(IILandroid/content/Intent;)Z",              // typed: no
                "Lmy3;->e(Ljava/lang/Object;)V",                    // erased
                "Ljb;->I(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",   // erased
                "Lfz6;->v(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", // erased
                "Lbi;->d(Ljava/lang/Object;Lnj1;)Ljava/lang/Object;", // one typed param: no
                "Lcom/x/S;->b(Ljava/lang/String;Lkb3;)V");           // typed: no
        assertEquals(3, TaintIr.erasedHops(chain));
        assertEquals(0, TaintIr.erasedHops(Arrays.asList("Lt/A;->run()V", "Lt/A;->f([Ljava/lang/Object;)V")));
    }
}

