package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.68.0: a call site that RTA could not link (the receiver is made by reflection / DI, so no new-instance is seen) is linked by CHA with
 * the kinds "virtual~" / "interface~"; the taint engine now follows those edges too (at most MAX_APPROX_TARGETS per site).
 */
public class IrApproxEdgesTest {

    private static final String IFACE = ".class public interface abstract Lt/I;\n.super Ljava/lang/Object;\n\n"
            + ".method public abstract run(Ljava/lang/String;)V\n.end method\n";

    private static String impl(int n) {
        return ".class public Lt/B" + n + ";\n.super Ljava/lang/Object;\n.implements Lt/I;\n\n"
                + ".method public run(Ljava/lang/String;)V\n    .locals 2\n"
                + "    invoke-virtual {v0, p1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n    return-void\n.end method\n";
    }

    private static final String ACTIVITY = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n"
            + "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
            + "    move-result-object v2\n"
            + "    invoke-interface {v3, v2}, Lt/I;->run(Ljava/lang/String;)V\n    return-void\n.end method\n";

    private static TaintIr.Result run(int impls) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(ACTIVITY));
        cs.add(SmaliParser.parse(IFACE));
        for (int i = 0; i < impls; i++) cs.add(SmaliParser.parse(impl(i)));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null);
    }

    @Test
    public void aSiteLinkedOnlyByTheChaFallbackStillCarriesTheTaint() {
        TaintIr.Result r = run(1);
        assertEquals(1, r.flows.size());
        assertEquals("Intent.getStringExtra()", r.flows.get(0).source);
        assertEquals(0, r.stats.unresolved[0]);
    }

    @Test
    public void aSiteWithManyFallbackTargetsIsCapped() {
        TaintIr.Result r = run(TaintIr.MAX_APPROX_TARGETS + 6);
        assertEquals(TaintIr.MAX_APPROX_TARGETS, r.flows.size());
    }

    @Test
    public void aCappedFallbackSiteIsCountedAndAnUncappedOneIsNot() {
        TaintIr.Result capped = run(TaintIr.MAX_APPROX_TARGETS + 6);
        assertEquals(1, capped.stats.capApprox);
        assertTrue(capped.stats.line().contains("~ sites 1"));
        TaintIr.Result small = run(3);
        assertEquals(0, small.stats.capApprox);
        assertTrue(small.stats.line().contains("~ sites 0"));
    }

    @Test
    public void theCappedSiteCounterIsSummedWhenStatsAreMerged() {
        TaintIr.Stats total = new TaintIr.Stats();
        total.merge(run(TaintIr.MAX_APPROX_TARGETS + 1).stats);
        total.merge(run(TaintIr.MAX_APPROX_TARGETS + 2).stats);
        assertEquals(2, total.capApprox);
    }

    @Test
    public void aSiteWithNoImplementationIsStillAnUnresolvedDrop() {
        TaintIr.Result r = run(0);
        assertEquals(0, r.flows.size());
    }
}
