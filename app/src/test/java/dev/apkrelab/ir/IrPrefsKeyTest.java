package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.78.0: a SharedPreferences link that rests on a non-literal key is a weak lead (Markor preferences wrapper). */
public class IrPrefsKeyTest {

    private static List<TaintIr.Flow> run(String readKey) {
        String t = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n"
                + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n"
                + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                + "    const-string v1, \"path\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {p0}, Lt/A;->ed()Landroid/content/SharedPreferences$Editor;\n    move-result-object v3\n"
                + "    const-string v1, \"last_file\"\n"
                + "    invoke-interface {v3, v1, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;\n"
                + "    return-void\n.end method\n\n"
                + ".method public read(Ljava/lang/String;)V\n    .locals 4\n"
                + "    invoke-virtual {p0}, Lt/A;->sp()Landroid/content/SharedPreferences;\n    move-result-object v0\n"
                + readKey
                + "    const/4 v2, 0x0\n"
                + "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v3\n"
                + "    new-instance v2, Ljava/io/FileInputStream;\n    invoke-direct {v2, v3}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n"
                + "    return-void\n.end method\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows;
    }

    @Test public void sameLiteralKeyIsAStrongFlow() {
        List<TaintIr.Flow> f = run("    const-string v1, \"last_file\"\n");
        assertTrue(!f.isEmpty());
        assertTrue(!f.get(0).weak);
    }

    @Test public void aNonLiteralReadKeyIsAWeakLead() {
        // the Intent link is weak, so the read's own (strong, level-1, LOW-confidence) SharedPreferences source is what is reported
        List<TaintIr.Flow> f = run("    move-object v1, p1\n");
        assertEquals(1, f.size());
        assertTrue(f.get(0).source.startsWith("SharedPreferences."));
    }

    @Test public void anotherLiteralKeyGivesOnlyThePreferencesLead() {
        List<TaintIr.Flow> f = run("    const-string v1, \"theme\"\n");
        assertEquals(1, f.size());
        assertEquals("SharedPreferences.getString()", f.get(0).source);
    }
}
