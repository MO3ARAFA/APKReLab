package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.82.0: an SSA card carries the method where the untrusted value is first held and the source -> sink path (shown to the AI triage). */
public class IrItemPathTest {

    private static List<SsaBridge.Item> items(String t) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        return SsaBridge.newFlows(cs, Arrays.asList("Lt/D;"), new ArrayList<TaintIr.Old>());
    }

    @Test public void sourceReadInOneMethodAndUsedInAnotherNamesBothAndThePath() {
        String t = ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
                + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"p\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {p0, v2}, Lt/D;->readIt(Ljava/lang/String;)V\n    return-void\n.end method\n\n"
                + ".method public readIt(Ljava/lang/String;)V\n    .locals 1\n    new-instance v0, Ljava/io/FileInputStream;\n"
                + "    invoke-direct {v0, p1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";
        List<SsaBridge.Item> it = items(t);
        assertEquals(1, it.size());
        assertEquals("Lt/D;->onCreate(Landroid/os/Bundle;)V", it.get(0).sourceMethod);
        assertTrue(it.get(0).dataPath.contains("onCreate") && it.get(0).dataPath.contains("readIt"));
        assertTrue(it.get(0).dataPath.indexOf("onCreate") < it.get(0).dataPath.indexOf("readIt"));
    }

    @Test public void sourceAndSinkInTheSameMethodHaveNoSeparatePath() {
        String t = ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n"
                + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"p\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    new-instance v3, Ljava/io/FileInputStream;\n    invoke-direct {v3, v2}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n"
                + "    return-void\n.end method\n";
        List<SsaBridge.Item> it = items(t);
        assertEquals(1, it.size());
        assertEquals("", it.get(0).sourceMethod);
        assertEquals("", it.get(0).dataPath);
    }
}
