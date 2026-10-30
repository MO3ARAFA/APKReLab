package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.79.0: one root cause = one card (Markor), and an onActivityResult helper is an activity result (Markor extractResultFromActivityResult). */
public class IrRootGroupingTest {

    private static final String HELPERS =
            ".method public readIt(Ljava/lang/String;)V\n    .locals 1\n    new-instance v0, Ljava/io/FileInputStream;\n"
          + "    invoke-direct {v0, p1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n\n"
          + ".method public writeIt(Ljava/lang/String;)V\n    .locals 1\n    new-instance v0, Ljava/io/FileOutputStream;\n"
          + "    invoke-direct {v0, p1}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";

    private static List<SsaBridge.Item> items(String body) {
        String t = ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
                + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n" + body
                + "    return-void\n.end method\n\n" + HELPERS;
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        return SsaBridge.newFlows(cs, Arrays.asList("Lt/D;"), new ArrayList<TaintIr.Old>());
    }

    @Test public void oneSourceReachingTwoFileSinksIsOneCard() {
        List<SsaBridge.Item> it = items("    const-string v1, \"path\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {p0, v2}, Lt/D;->readIt(Ljava/lang/String;)V\n    invoke-virtual {p0, v2}, Lt/D;->writeIt(Ljava/lang/String;)V\n");
        assertEquals(1, it.size());
        assertTrue(it.get(0).detail.contains("one root cause"));
    }

    @Test public void twoDifferentSourcesStayTwoCards() {
        List<SsaBridge.Item> it = items("    const-string v1, \"path\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {p0, v2}, Lt/D;->readIt(Ljava/lang/String;)V\n"
                + "    invoke-virtual {v0}, Landroid/content/Intent;->getDataString()Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {p0, v2}, Lt/D;->writeIt(Ljava/lang/String;)V\n");
        assertEquals(2, it.size());
    }

    @Test public void anActivityResultHelperReadsAnAnswerNotAnAttackerInput() {
        String t = ".class public Lt/U;\n.super Ljava/lang/Object;\n\n"
                + ".method public extractResultFromActivityResult(Landroid/app/Activity;IILandroid/content/Intent;)V\n    .locals 2\n"
                + "    invoke-virtual {p4}, Landroid/content/Intent;->getDataString()Ljava/lang/String;\n    move-result-object v0\n"
                + "    new-instance v1, Ljava/io/FileOutputStream;\n    invoke-direct {v1, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n"
                + "    return-void\n.end method\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/U;"), CallGraph.Mode.RTA, null);
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        assertEquals(1, r.flows.size());
        assertTrue(r.flows.get(0).source.endsWith(TaintIr.ACTIVITY_RESULT_SUFFIX));
    }

    @Test public void aRenamedActivityResultHelperIsRecognisedByItsShape() {
        String t = ".class public Lt/U;\n.super Ljava/lang/Object;\n\n"
                + ".method public a(IILandroid/content/Intent;)Z\n    .locals 3\n"
                + "    invoke-virtual {p3}, Landroid/content/Intent;->getDataString()Ljava/lang/String;\n    move-result-object v0\n"
                + "    new-instance v1, Ljava/io/FileOutputStream;\n    invoke-direct {v1, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n"
                + "    const/4 v2, 0x1\n    return v2\n.end method\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/U;"), CallGraph.Mode.RTA, null);
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        assertEquals(1, r.flows.size());
        assertTrue(r.flows.get(0).source.endsWith(TaintIr.ACTIVITY_RESULT_SUFFIX));
    }
}

