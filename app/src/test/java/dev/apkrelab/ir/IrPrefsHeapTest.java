package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.67.0 heap model, step 1: a real source stored with SharedPreferences.Editor.putString is read back by getString with the same key.
 * Tiny hand-written smali: onCreate writes, onResume reads and sends to WebView.loadUrl.
 */
public class IrPrefsHeapTest {

    private static final String PUT = "invoke-interface {v3, v1, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;";
    private static final String GET = "invoke-interface {v3, v1, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
    private static final String GET_ALL = "invoke-interface {v3}, Landroid/content/SharedPreferences;->getAll()Ljava/util/Map;";
    private static final String LOAD = "invoke-virtual {v5, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

    private static String writer(String keyLine, String... extra) {
        StringBuilder sb = new StringBuilder(".method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n");
        String[] pre = {"new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"",
                "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2",
                "const-string v6, \"x\""};
        for (String l : pre) sb.append("    ").append(l).append('\n');
        sb.append("    ").append(keyLine).append('\n');
        for (String l : extra) sb.append("    ").append(l).append('\n');
        sb.append("    ").append(PUT).append("\n    return-void\n.end method\n\n");
        return sb.toString();
    }

    private static String reader(String keyLine, String getLine) {
        StringBuilder sb = new StringBuilder(".method public onResume()V\n    .locals 6\n");
        sb.append("    ").append(keyLine).append('\n');
        sb.append("    ").append(getLine).append("\n    move-result-object v2\n    ").append(LOAD).append("\n    return-void\n.end method\n");
        return sb.toString();
    }

    private static TaintIr.Result run(String writerMethod, String readerMethod) {
        String smali = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n" + writerMethod + readerMethod;
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(smali));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null);
    }

    @Test
    public void sameKeyCarriesTheIntentSourceThroughPreferences() {
        TaintIr.Result r = run(writer("const-string v1, \"k\""), reader("const-string v1, \"k\"", GET));
        assertEquals(1, r.flows.size());
        TaintIr.Flow f = r.flows.get(0);
        assertEquals("Intent.getStringExtra()", f.source);
        assertEquals(2, f.level);
        assertTrue(f.via, f.via.contains("prefs:\"k\""));
    }

    @Test
    public void anotherKeyStaysAPlainPreferencesSource() {
        TaintIr.Result r = run(writer("const-string v1, \"k\""), reader("const-string v1, \"other\"", GET));
        assertEquals(1, r.flows.size());
        assertEquals("SharedPreferences.getString()", r.flows.get(0).source);
        assertEquals(1, r.flows.get(0).level);
    }

    @Test
    public void aWriteWithAKeyThatIsNotALiteralIsSeenByEveryRead() {
        // v1 comes from a method call, not a const-string
        TaintIr.Result r = run(writer("invoke-static {}, Lt/K;->key()Ljava/lang/String;", "move-result-object v1"),
                reader("const-string v1, \"other\"", GET));
        assertEquals(1, r.flows.size());
        // 0.78.0: the link through a non-literal key is a WEAK lead, so the strong SharedPreferences source of the read wins the join
        assertTrue(r.flows.get(0).source.startsWith("SharedPreferences."));
    }

    @Test
    public void aReadWithAKeyThatIsNotALiteralSeesEveryWrite() {
        TaintIr.Result r = run(writer("const-string v1, \"k\""),
                reader("invoke-static {}, Lt/K;->key()Ljava/lang/String;\n    move-result-object v1", GET));
        assertEquals(1, r.flows.size());
        // 0.78.0: the link through a non-literal key is a WEAK lead, so the strong SharedPreferences source of the read wins the join
        assertTrue(r.flows.get(0).source.startsWith("SharedPreferences."));
    }

    @Test
    public void getAllSeesEveryWrite() {
        TaintIr.Result r = run(writer("const-string v1, \"k\""), reader("const-string v1, \"k\"", GET_ALL));
        assertEquals(1, r.flows.size());
        assertEquals("Intent.getStringExtra()", r.flows.get(0).source);
    }

    @Test
    public void aPutWithARealSourceIsNotCountedAsALoss() {
        TaintIr.Result r = run(writer("const-string v1, \"k\""), reader("const-string v1, \"k\"", GET));
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void aPutWithAnUntaintedValueChangesNothing() {
        // writer stores a constant, not the Intent extra
        String w = ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n    const-string v1, \"k\"\n    const-string v2, \"fixed\"\n    " + PUT
                + "\n    return-void\n.end method\n\n";
        TaintIr.Result r = run(w, reader("const-string v1, \"k\"", GET));
        assertEquals(1, r.flows.size());
        assertEquals("SharedPreferences.getString()", r.flows.get(0).source);
    }
}
