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
 * 0.68.6 (sandbox study of 15 real apps): an Intent read in an activity / service / receiver that the manifest does NOT export was built by
 * the app itself (or is a system broadcast), so it is not attacker data. The flow stays in the list, shown as LOW with its own sentence.
 * Every positive has twins: an exported component, an abstract base of an exported component, a helper class, no component list at all.
 */
public class IrInternalSourceTest {

    private static final String READ_AND_SINK =
            "    .locals 7\n"
            + "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
            + "    invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n";

    private static String activity(String type, String sup) {
        return ".class public " + type + "\n.super " + sup + "\n\n.method public onCreate(Landroid/os/Bundle;)V\n" + READ_AND_SINK;
    }

    private static String receiver(String type) {
        return ".class public " + type + "\n.super Landroid/content/BroadcastReceiver;\n\n.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V\n" + READ_AND_SINK;
    }

    private static String plain(String type) {
        return ".class public " + type + "\n.super Ljava/lang/Object;\n\n.method public static read()V\n" + READ_AND_SINK;
    }

    private static CallGraph graph(List<String> components, String... smali) {
        List<ClassIr> cs = new ArrayList<>();
        for (String s : smali) cs.add(SmaliParser.parse(s));
        return CallGraph.build(cs, components, CallGraph.Mode.RTA, null);
    }

    private static TaintIr.Flow flowIn(CallGraph g, String classType) {
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        TaintIr.Flow hit = null;
        for (TaintIr.Flow f : r.flows) if (TaintIr.classOf(f.sink.method).equals(classType)) hit = f;
        return hit;
    }

    private static final String ACT = "Landroid/app/Activity;";

    @Test
    public void anIntentReadInAnUnexportedActivityIsInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), activity("Lt/A;", ACT), activity("Lt/B;", ACT));
        TaintIr.Flow f = flowIn(g, "Lt/B;");
        assertTrue(f.internal);
        assertTrue(f.weak);
        assertEquals(2, f.level);
    }

    @Test
    public void theSameReadInAnExportedActivityStaysStrong() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), activity("Lt/A;", ACT), activity("Lt/B;", ACT));
        TaintIr.Flow f = flowIn(g, "Lt/A;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    @Test
    public void anAbstractBaseOfAnExportedActivityStaysStrong() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), activity("Lt/Base;", ACT), activity("Lt/A;", "Lt/Base;"));
        TaintIr.Flow f = flowIn(g, "Lt/Base;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    @Test
    public void aDynamicReceiverAndAHelperClassAreNeverCalledInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), activity("Lt/A;", ACT), receiver("Lt/M$R;"), plain("Lt/Helper;"));
        TaintIr.Flow r = flowIn(g, "Lt/M$R;");
        assertFalse(r.internal);
        assertFalse(r.weak);
        TaintIr.Flow h = flowIn(g, "Lt/Helper;");
        assertFalse(h.internal);
        assertFalse(h.weak);
    }

    /** An exported activity that (reads Intent data or not) launches Lt/B; with an explicit Intent. */
    private static String launcher(boolean readsIntent) {
        return launcher("Lt/A;", "Lt/B;", readsIntent);
    }

    private static String launcher(String self, String to, boolean readsIntent) { return launcher(self, to, readsIntent, true); }

    private static String launcher(String self, String to, boolean readsIntent, boolean forwards) {
        StringBuilder sb = new StringBuilder(".class public " + self + "\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        if (readsIntent) {
            sb.append("    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n");
            sb.append("    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n");
        }
        sb.append("    const-class v5, " + to + "\n    new-instance v6, Landroid/content/Intent;\n");
        sb.append("    invoke-direct {v6, v7, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n");
        if (readsIntent && forwards) sb.append("    const-string v1, \"u\"\n    invoke-virtual {v6, v1, v4}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n");   // 2.0.1: really handed on
        sb.append("    invoke-virtual {v7, v6}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V\n    return-void\n.end method\n");
        return sb.toString();
    }

    @Test
    public void anActivityThatAnExportedActivityForwardsDataToStaysStrong() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), launcher(true), activity("Lt/B;", ACT));
        TaintIr.Flow f = flowIn(g, "Lt/B;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    // 2.0.1 (WE Wallet SignUpWebViewActivity): an exported launcher that READS an Intent value but never hands it on does not make the target attacker-fed
    @Test
    public void anActivityLaunchedByAReaderThatForwardsNothingIsInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), launcher("Lt/A;", "Lt/B;", true, false), activity("Lt/B;", ACT));
        assertTrue(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void mutantClassLevelForwardingMakesItStrongAgain() {
        boolean was = TaintIr.PRIVATE_STRICT;
        TaintIr.PRIVATE_STRICT = false;
        try {
            CallGraph g = graph(Arrays.asList("Lt/A;"), launcher("Lt/A;", "Lt/B;", true, false), activity("Lt/B;", ACT));
            assertFalse(flowIn(g, "Lt/B;").internal);
        } finally { TaintIr.PRIVATE_STRICT = was; }
    }

    /** An exported activity that hands its whole incoming Intent on: how = "putExtras" | "copy" | "startActivity". */
    private static String wholesale(String how) {
        StringBuilder sb = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        sb.append("    invoke-virtual {v7}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v4\n");
        sb.append("    const-class v5, Lt/B;\n    new-instance v6, Landroid/content/Intent;\n");
        if (how.equals("copy")) {
            sb.append("    invoke-direct {v6, v4}, Landroid/content/Intent;-><init>(Landroid/content/Intent;)V\n");
            sb.append("    invoke-virtual {v6, v7, v5}, Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;\n");
        } else if (how.equals("putExtras")) {
            sb.append("    invoke-direct {v6, v7, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n");
            sb.append("    invoke-virtual {v6, v4}, Landroid/content/Intent;->putExtras(Landroid/content/Intent;)Landroid/content/Intent;\n");
        } else {
            sb.append("    invoke-virtual {v4, v7, v5}, Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;\n");
            sb.append("    move-object v6, v4\n");
        }
        sb.append("    invoke-virtual {v7, v6}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V\n    return-void\n.end method\n");
        return sb.toString();
    }

    @Test
    public void handingTheWholeIncomingIntentOnKeepsTheTargetStrong() {
        for (String how : new String[]{"putExtras", "copy", "startActivity"}) {
            CallGraph g = graph(Arrays.asList("Lt/A;"), wholesale(how), activity("Lt/B;", ACT));
            TaintIr.Flow f = flowIn(g, "Lt/B;");
            assertFalse(how, f.internal);
            assertFalse(how, f.weak);
        }
    }

    /** OVAA DeeplinkActivity: onCreate hands the deep link Uri to a private method that puts one of its query parameters into the Intent for Lt/B; (a parameter, not yet a source). */
    private static String deepLink() {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;\n    move-result-object v0\n"
            + "    invoke-direct {p0, v0}, Lt/A;->process(Landroid/net/Uri;)V\n    return-void\n.end method\n"
            + ".method private process(Landroid/net/Uri;)V\n    .locals 5\n"
            + "    const-string v2, \"u\"\n"
            + "    invoke-virtual {p1, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1\n"
            + "    const-class v3, Lt/B;\n    new-instance v4, Landroid/content/Intent;\n"
            + "    invoke-direct {v4, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
            + "    invoke-virtual {v4, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n"
            + "    invoke-virtual {p0, v4}, Lt/A;->startActivity(Landroid/content/Intent;)V\n    return-void\n.end method\n";
    }

    @Test
    public void aParameterPutIntoTheIntentOfAPrivateActivityKeepsItStrong() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), deepLink(), activity("Lt/B;", ACT));
        TaintIr.Flow f = flowIn(g, "Lt/B;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    // 2.0.2: the proof is recorded at WRITE time for every engine's cards (TaintIr.forwardedComponents)
    @Test
    public void aProvenForwardIsRecordedAndAnUnprovenOneIsNot() {
        TaintIr.clearForwarded();
        CallGraph g = graph(Arrays.asList("Lt/A;"), deepLink(), activity("Lt/B;", ACT));
        TaintIr.analyze(g, false, null);
        assertTrue(TaintIr.forwardedComponents().toString(), TaintIr.forwardedComponents().contains("Lt/B;"));
        TaintIr.clearForwarded();
        TaintIr.analyze(graph(Arrays.asList("Lt/A;"), launcher("Lt/A;", "Lt/B;", true, false), activity("Lt/B;", ACT)), false, null);
        assertFalse(TaintIr.forwardedComponents().toString(), TaintIr.forwardedComponents().contains("Lt/B;"));
        TaintIr.analyze(graph(Arrays.asList("Lt/A;"), redirector(true), activity("Lt/B;", ACT)), false, null);
        assertTrue(TaintIr.openRedirectorSeen());
        TaintIr.clearForwarded();
        assertFalse(TaintIr.openRedirectorSeen());
    }

    @Test
    public void mutantNoParameterPutsLeavesItInternal() {
        boolean was = TaintIr.ICC_PARAM_PUTS;
        TaintIr.ICC_PARAM_PUTS = false;
        try {
            CallGraph g = graph(Arrays.asList("Lt/A;"), deepLink(), activity("Lt/B;", ACT));
            assertTrue(flowIn(g, "Lt/B;").internal);
        } finally { TaintIr.ICC_PARAM_PUTS = was; }
    }

    @Test
    public void mutantNoWholeValueHandOverLeavesTheTargetInternal() {
        boolean was = TaintIr.ICC_WHOLE;
        TaintIr.ICC_WHOLE = false;
        try {
            for (String how : new String[]{"putExtras", "copy", "startActivity"}) {
                CallGraph g = graph(Arrays.asList("Lt/A;"), wholesale(how), activity("Lt/B;", ACT));
                assertTrue(how, flowIn(g, "Lt/B;").internal);
            }
        } finally { TaintIr.ICC_WHOLE = was; }
    }

    @Test
    public void anActivityThatIsLaunchedByAnActivityThatReadsNoIntentDataIsInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), launcher(false), activity("Lt/B;", ACT));
        assertTrue(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void theForwardingContinuesThroughAChainOfActivities() {
        String c = activity("Lt/C;", ACT);
        String b = launcherOf("Lt/B;", "Lt/C;");
        CallGraph g = graph(Arrays.asList("Lt/A;"), launcher(true), b, c);
        assertFalse(flowIn(g, "Lt/C;").internal);
    }

    /** An activity that reads Intent data (so it can forward it) and launches {@code to}. */
    private static String launcherOf(String type, String to) {
        return launcher(type, to, true);
    }

    /** An exported activity that takes an Intent from its extras and launches it (the InsecureShop pattern), optionally. */
    private static String redirector(boolean launch) {
        StringBuilder sb = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        sb.append("    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"x\"\n");
        sb.append("    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n    move-result-object v4\n");
        if (launch) sb.append("    invoke-virtual {v7, v4}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V\n");
        sb.append("    return-void\n.end method\n");
        return sb.toString();
    }

    @Test
    public void whenAnExportedActivityLaunchesTheIntentItReceivedNothingIsCalledInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), redirector(true), activity("Lt/B;", ACT));
        TaintIr.Flow f = flowIn(g, "Lt/B;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    @Test
    public void anExportedActivityThatOnlyReadsTheParcelableLeavesTheOthersInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), redirector(false), activity("Lt/B;", ACT));
        assertTrue(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void withoutAComponentListNothingIsInternal() {
        CallGraph g = graph(Collections.<String>emptyList(), activity("Lt/B;", ACT));
        TaintIr.Flow f = flowIn(g, "Lt/B;");
        assertFalse(f.internal);
        assertFalse(f.weak);
    }

    @Test
    public void aBaseClassWeCannotReadIsNotCalledInternal() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), activity("Lt/A;", ACT), activity("Lt/B;", "Lq/z;"));
        assertFalse(flowIn(g, "Lt/B;").internal);
    }

    @Test
    public void anInternalFlowIsShownAsLowWithItsOwnSentenceAndTheExportedOneKeepsItsConfidence() {
        CallGraph g = graph(Arrays.asList("Lt/A;"), activity("Lt/A;", ACT), activity("Lt/B;", ACT));
        List<SsaBridge.Item> items = SsaBridge.newFlows(g, null);
        SsaBridge.Item internal = null, exported = null;
        for (SsaBridge.Item it : items) {
            if (it.classType.equals("Lt/B;")) internal = it;
            if (it.classType.equals("Lt/A;")) exported = it;
        }
        assertEquals("LOW", internal.confidence);
        assertTrue(internal.detail.contains("does not export"));
        assertEquals("HIGH", exported.confidence);
        assertFalse(exported.detail.contains("does not export"));
    }

    @Test
    public void aStrongSourceBeatsAnInternalOneInAJoin() {
        TaintIr.Tv in = TaintIr.Tv.internalSource(2, "I", null);
        TaintIr.Tv strong = TaintIr.Tv.real(1, "S", null);
        assertTrue(in.weak);
        assertTrue(in.internal);
        TaintIr.Tv j = in.join(strong);
        assertFalse(j.weak);
        assertFalse(j.internal);
        assertEquals("S", j.src);
        assertTrue(strong.join(in).src.equals("S"));
    }
}
