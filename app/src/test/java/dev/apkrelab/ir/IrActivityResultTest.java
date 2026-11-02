package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.70.0: the Intent handed to onActivityResult is the ANSWER of an activity the app started, not an input from another app, so data read
 * from that parameter is a weak lead (LOW), never a strong source. Only the method's own Intent parameter counts: a locally built Intent
 * or getIntent() inside onActivityResult, and the Intent of any other method, keep their normal strength. Real-app trigger: Nextcloud
 * SettingsActivity.onActivityResult(storage path from the folder picker) -> prefs -> 11 HIGH file-path flows.
 */
public class IrActivityResultTest {

    private static final String READ_LOCAL =
            "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
            + "    invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n";

    /** Activity whose onActivityResult(int, int, Intent) body is {@code body}; p3 (the result Intent) is v10 with .locals 7. */
    private static String withResult(String type, String body) {
        return ".class public " + type + "\n.super Landroid/app/Activity;\n\n.method public onActivityResult(IILandroid/content/Intent;)V\n    .locals 7\n"
                + body + "    return-void\n.end method\n";
    }

    private static final String READ_PARAM =
            "    const-string v1, \"u\"\n"
            + "    invoke-virtual {v10, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
            + "    invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n";

    private static TaintIr.Flow flow(String... smali) {
        List<ClassIr> cs = new ArrayList<>();
        for (String s : smali) cs.add(SmaliParser.parse(s));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);    // Lt/A; is exported
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        return r.flows.isEmpty() ? null : r.flows.get(0);
    }

    @Test
    public void theResultIntentParameterIsAWeakSourceEvenInAnExportedActivity() {
        TaintIr.Flow f = flow(withResult("Lt/A;", READ_PARAM));
        assertNotNull(f);
        assertEquals(2, f.level);                    // still reported, never removed
        assertTrue(f.weak);
        assertTrue(f.internal);
        assertTrue(f.source.endsWith(TaintIr.ACTIVITY_RESULT_SUFFIX));
    }

    @Test
    public void aMovedCopyOfTheResultIntentIsStillTheResultIntent() {
        String body = "    move-object v0, v10\n    const-string v1, \"u\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
                + "    invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n";
        TaintIr.Flow f = flow(withResult("Lt/A;", body));
        assertNotNull(f);
        assertTrue(f.weak);
    }

    @Test
    public void aLocallyBuiltIntentInsideOnActivityResultKeepsItsStrength() {
        TaintIr.Flow f = flow(withResult("Lt/A;", READ_LOCAL));
        assertNotNull(f);
        assertFalse(f.weak);
        assertFalse(f.internal);
        assertFalse(f.source.endsWith(TaintIr.ACTIVITY_RESULT_SUFFIX));
    }

    @Test
    public void theIntentParameterOfAnotherMethodIsNotAffected() {
        // onNewIntent(Intent) of an exported activity: the Intent really comes from the caller
        String smali = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onNewIntent(Landroid/content/Intent;)V\n    .locals 7\n"
                + "    const-string v1, \"u\"\n"
                + "    invoke-virtual {v8, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
                + "    invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n";
        TaintIr.Flow f = flow(smali);
        assertNotNull(f);
        assertFalse(f.weak);
    }

    @Test
    public void aRealSourceReachingTheSameSinkStaysStrong() {
        // two loadUrl calls in one method: one fed by the result Intent, one by a real source. The engine keeps both flows and the report
        // shows the strong one, so adding the weak rule can never hide a real path.
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(withResult("Lt/A;", READ_PARAM + READ_LOCAL)));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        boolean strong = false, weak = false;
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) {
            if (f.weak) weak = true; else strong = true;
        }
        assertTrue(strong);
        assertTrue(weak);
        List<SsaBridge.Item> items = SsaBridge.newFlows(g, null);
        assertEquals(1, items.size());
        assertEquals("HIGH", items.get(0).confidence);
        assertFalse(items.get(0).detail.contains("not an input that another app sends"));
    }

    @Test
    public void theReportedItemIsLowWithItsOwnSentence() {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(withResult("Lt/A;", READ_PARAM)));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        List<SsaBridge.Item> items = SsaBridge.newFlows(g, null);
        assertEquals(1, items.size());
        SsaBridge.Item it = items.get(0);
        assertEquals("LOW", it.confidence);
        assertTrue(it.detail.contains("onActivityResult"));
        assertTrue(it.detail.contains("not an input that another app sends"));
        assertFalse(it.detail.contains("An Intent is controlled by the caller"));
        assertFalse(it.detail.contains("does not export"));
    }

    // 3.0.0 (blind round 3 false positive: simplenotes c5.S(Intent, int) = a renamed, R8-merged ActivityResultContract.parseResult)
    /** Exported Lt/A; whose onCreate calls Lt/C;->[name](desc) and loads the result into a WebView; parse reads getStringExtra from its own Intent parameter. */
    private static String contract(String desc, String args) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n"
            + "    new-instance v0, Lt/C;\n    invoke-direct {v0}, Lt/C;-><init>()V\n    new-instance v1, Landroid/content/Intent;\n    invoke-direct {v1}, Landroid/content/Intent;-><init>()V\n    const/4 v2, 0x1\n"
            + "    invoke-virtual {v0" + args + "}, Lt/C;->parse" + desc + "\n    move-result-object v4\n    check-cast v4, Ljava/lang/String;\n"
            + "    new-instance v5, Landroid/webkit/WebView;\n    invoke-virtual {v5, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n";
    }
    private static String parser(String desc, String intentReg) {
        return ".class public Lt/C;\n.super Ljava/lang/Object;\n.method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public parse" + desc + "\n    .locals 2\n    const-string v0, \"u\"\n    invoke-virtual {" + intentReg + ", v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
            + "    move-result-object v1\n    return-object v1\n.end method\n";
    }

    @Test
    public void aRenamedParseResultIsAnActivityAnswer() {
        TaintIr.Flow f = flow(contract("(Landroid/content/Intent;I)Ljava/lang/Object;", ", v1, v2"), parser("(Landroid/content/Intent;I)Ljava/lang/Object;", "p1"));
        assertNotNull(f);
        assertTrue(f.weak);
        TaintIr.Flow g = flow(contract("(ILandroid/content/Intent;)Ljava/lang/Object;", ", v2, v1"), parser("(ILandroid/content/Intent;)Ljava/lang/Object;", "p2"));
        assertNotNull(g);
        assertTrue(g.weak);
    }

    @Test
    public void anotherIntentHelperShapeStaysStrong() {                                    // twin: (Intent) -> Object is not the contract shape
        TaintIr.Flow f = flow(contract("(Landroid/content/Intent;)Ljava/lang/Object;", ", v1"), parser("(Landroid/content/Intent;)Ljava/lang/Object;", "p1"));
        assertNotNull(f);
        assertFalse(f.weak);
    }

    @Test
    public void theMutationMakesTheContractStrong() {
        boolean was = TaintIr.RESULT_CONTRACT_SHAPE;
        TaintIr.RESULT_CONTRACT_SHAPE = false;
        try {
            TaintIr.Flow f = flow(contract("(Landroid/content/Intent;I)Ljava/lang/Object;", ", v1, v2"), parser("(Landroid/content/Intent;I)Ljava/lang/Object;", "p1"));
            assertNotNull(f);
            assertFalse(f.weak);
        } finally { TaintIr.RESULT_CONTRACT_SHAPE = was; }
    }
}
