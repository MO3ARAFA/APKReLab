package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

/**
 * 0.69.1: an exported component protected by a SIGNATURE-level permission is not an attacker seed. An Intent read in it is shown as LOW
 * (never removed), UNLESS an unprotected exported component forwards an Intent to it: that forwarder runs with the app's own identity
 * and passes the permission check (confused deputy), so the flow stays strong. Every positive has twins.
 */
public class IrGuardedSourceTest {

    private static final String ACT = "Landroid/app/Activity;";

    private static final String READ_AND_SINK =
            "    .locals 7\n"
            + "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
            + "    invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n";

    private static String activity(String type) {
        return ".class public " + type + "\n.super " + ACT + "\n\n.method public onCreate(Landroid/os/Bundle;)V\n" + READ_AND_SINK;
    }

    /** An activity that reads Intent data and launches {@code to} with an explicit Intent. */
    private static String launcher(String self, String to) {
        StringBuilder sb = new StringBuilder(".class public " + self + "\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        sb.append("    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n");
        sb.append("    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n");
        sb.append("    const-class v5, " + to + "\n    new-instance v6, Landroid/content/Intent;\n");
        sb.append("    invoke-direct {v6, v7, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n");
        sb.append("    const-string v1, \"u\"\n    invoke-virtual {v6, v1, v4}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n");   // 2.0.1: the value is really handed on
        sb.append("    invoke-virtual {v7, v6}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V\n    return-void\n.end method\n");
        return sb.toString();
    }

    /** An activity that takes an Intent out of its extras and launches it (intent redirection). */
    private static String redirector(String self) {
        return ".class public " + self + "\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n"
                + "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"x\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n    move-result-object v4\n"
                + "    invoke-virtual {v7, v4}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V\n    return-void\n.end method\n";
    }

    private static CallGraph graph(List<String> exported, List<String> guarded, String... smali) {
        List<ClassIr> cs = new ArrayList<>();
        for (String s : smali) cs.add(SmaliParser.parse(s));
        CallGraph g = CallGraph.build(cs, exported, CallGraph.Mode.RTA, null);
        if (guarded != null) g.setGuardedComponents(guarded);
        return g;
    }

    private static TaintIr.Flow flowIn(CallGraph g, String classType) {
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        TaintIr.Flow hit = null;
        for (TaintIr.Flow f : r.flows) if (TaintIr.classOf(f.sink.method).equals(classType)) hit = f;
        return hit;
    }

    @Test
    public void anIntentReadInASignatureGuardedExportedActivityIsInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), Arrays.asList("Lt/A;"), activity("Lt/A;"));
        TaintIr.Flow f = flowIn(g, "Lt/A;");
        assertTrue(f.internal);
        assertTrue(f.weak);
        assertEquals(2, f.level);          // still a real source: shown, never removed
        assertTrue(g.isGuardedComponent("Lt/A;"));
    }

    @Test
    public void theSameActivityWithoutAGuardStaysStrong() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), null, activity("Lt/A;"));
        TaintIr.Flow f = flowIn(g, "Lt/A;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    @Test
    public void anEmptyGuardListChangesNothing() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), Collections.<String>emptyList(), activity("Lt/A;"));
        assertFalse(flowIn(g, "Lt/A;").internal);
    }

    @Test
    public void anotherExportedActivityStaysStrongWhenOnlyOneIsGuarded() {
        CallGraph g = graph(Arrays.asList("Lt/A;", "Lt/B;"), Arrays.asList("Lt/A;"), activity("Lt/A;"), activity("Lt/B;"));
        assertTrue(flowIn(g, "Lt/A;").internal);
        assertFalse(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void anUnguardedExportedForwarderMakesTheGuardedActivityStrongAgain() {
        // confused deputy: Lt/A; (open) starts Lt/B; (signature-guarded) with its own identity
        CallGraph g = graph(Arrays.asList("Lt/A;", "Lt/B;"), Arrays.asList("Lt/B;"), launcher("Lt/A;", "Lt/B;"), activity("Lt/B;"));
        TaintIr.Flow f = flowIn(g, "Lt/B;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    @Test
    public void anUnguardedExportedRedirectorMakesTheGuardedActivityStrongAgain() {
        CallGraph g = graph(Arrays.asList("Lt/R;", "Lt/B;"), Arrays.asList("Lt/B;"), redirector("Lt/R;"), activity("Lt/B;"));
        assertFalse(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void aGuardedForwarderDoesNotMakeItsTargetStrong() {
        // Lt/A; is signature-guarded: only same-key apps can drive it, so what it forwards to Lt/C; is not attacker data
        CallGraph g = graph(Arrays.asList("Lt/A;"), Arrays.asList("Lt/A;"), launcher("Lt/A;", "Lt/C;"), activity("Lt/C;"));
        assertTrue(flowIn(g, "Lt/C;").internal);
    }

    @Test
    public void aGuardedRedirectorDoesNotSwitchTheWholeAppBackToStrong() {
        CallGraph g = graph(Arrays.asList("Lt/R;"), Arrays.asList("Lt/R;"), redirector("Lt/R;"), activity("Lt/B;"));
        assertTrue(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void aGuardedForwarderStillCountsWhenAnUnguardedOneAlsoReachesTheTarget() {
        CallGraph g = graph(Arrays.asList("Lt/A;", "Lt/D;"), Arrays.asList("Lt/A;"),
                launcher("Lt/A;", "Lt/C;"), launcher("Lt/D;", "Lt/C;"), activity("Lt/C;"));
        assertFalse(flowIn(g, "Lt/C;").internal);
    }

    @Test
    public void aNestedClassOfAGuardedActivityIsGuardedToo() {
        String task = ".class public Lt/A$Task;\n.super Ljava/lang/Object;\n\n.method public static read()V\n" + READ_AND_SINK;
        CallGraph g = graph(Arrays.asList("Lt/A;"), Arrays.asList("Lt/A;"), activity("Lt/A;"), task);
        assertTrue(g.isGuardedComponent("Lt/A$Task;"));
        assertFalse(g.isGuardedComponent("Lt/B;"));
    }

    @Test
    public void aGuardedFlowIsShownAsLowWithItsOwnSentenceAndTheOpenOneKeepsItsConfidence() {
        CallGraph g = graph(Arrays.asList("Lt/A;", "Lt/B;"), Arrays.asList("Lt/A;"), activity("Lt/A;"), activity("Lt/B;"));
        SsaBridge.Item guarded = null, open = null;
        for (SsaBridge.Item it : SsaBridge.newFlows(g, null)) {
            if (it.classType.equals("Lt/A;")) guarded = it;
            if (it.classType.equals("Lt/B;")) open = it;
        }
        assertEquals("LOW", guarded.confidence);
        assertTrue(guarded.detail.contains("signature-level permission"));
        assertFalse(guarded.detail.contains("does not export"));
        assertEquals("HIGH", open.confidence);
        assertFalse(open.detail.contains("signature-level permission"));
    }

    @Test
    public void anUnexportedActivityKeepsTheOldSentence() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), Arrays.asList("Lt/A;"), activity("Lt/A;"), activity("Lt/B;"));
        for (SsaBridge.Item it : SsaBridge.newFlows(g, null))
            if (it.classType.equals("Lt/B;")) {
                assertTrue(it.detail.contains("does not export"));
                assertFalse(it.detail.contains("signature-level permission"));
            }
    }
}
