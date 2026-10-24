package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.68.5 (sandbox measurement on Bitwarden): R8 merges several classes into one class with ONE shared Object field, so a tainted write
 * taints every read. A taint read from an Object-typed field of a default-package (obfuscated) class is marked weak and shown as LOW.
 * A strong path always wins over a weak one. Every positive has clean twins (String field, packaged class, plain flow).
 */
public class IrWeakTaintTest {

    private static final String SINK = "invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

    private static CallGraph graph(String owner, String type, boolean viaGetter) {
        String ownerCls = owner.substring(0, owner.length() - 1);
        StringBuilder a = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        a.append("    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"u\"\n");
        a.append("    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n");
        a.append("    new-instance v3, ").append(owner).append("\n");
        a.append("    invoke-direct {v3}, ").append(owner).append("-><init>()V\n");
        a.append("    iput-object v2, v3, ").append(owner).append("->Q:").append(type).append("\n");
        if (viaGetter) {
            a.append("    invoke-virtual {v3}, ").append(owner).append("->get()").append(type).append("\n    move-result-object v4\n");
        } else {
            a.append("    iget-object v4, v3, ").append(owner).append("->Q:").append(type).append("\n");
        }
        a.append("    ").append(SINK).append("\n    return-void\n.end method\n");
        StringBuilder b = new StringBuilder(".class public ").append(owner).append("\n.super Ljava/lang/Object;\n\n");
        b.append(".field public Q:").append(type).append("\n\n");
        b.append(".method public constructor <init>()V\n    .locals 0\n    return-void\n.end method\n\n");
        b.append(".method public get()").append(type).append("\n    .locals 1\n    iget-object v0, p0, ").append(owner).append("->Q:").append(type).append("\n    return-object v0\n.end method\n");
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(a.toString()));
        cs.add(SmaliParser.parse(b.toString()));
        return CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
    }

    private static TaintIr.Flow only(CallGraph g) {
        TaintIr.Result r = TaintIr.analyze(g, true, null);
        assertEquals(1, r.flows.size());
        return r.flows.get(0);
    }

    @Test
    public void anObjectFieldOfAnObfuscatedClassMakesTheFlowWeak() {
        TaintIr.Flow f = only(graph("Laq3;", "Ljava/lang/Object;", false));
        assertTrue(f.weak);
        assertEquals(2, f.level);
    }

    @Test
    public void aStringFieldOfTheSameObfuscatedClassStaysStrong() {
        assertFalse(only(graph("Laq3;", "Ljava/lang/String;", false)).weak);
    }

    @Test
    // 0.80.0: the readable package is "com/example" now; "t/B" (all segments <= 3 chars) is what R8 repackaging produces and is weak
    public void anObjectFieldOfAPackagedClassStaysStrong() {
        assertFalse(only(graph("Lcom/example/B;", "Ljava/lang/Object;", false)).weak);
    }

    @Test
    public void theWeakMarkTravelsThroughAReturnValue() {
        TaintIr.Flow f = only(graph("Laq3;", "Ljava/lang/Object;", true));
        assertTrue(f.weak);
    }

    @Test
    public void aReturnValueFromAStringFieldStaysStrong() {
        assertFalse(only(graph("Laq3;", "Ljava/lang/String;", true)).weak);
    }

    @Test
    public void aWeakFlowIsShownAsLowAndItsTwinsKeepTheirConfidence() {
        List<SsaBridge.Item> weak = SsaBridge.newFlows(graph("Laq3;", "Ljava/lang/Object;", false), null);
        assertEquals(1, weak.size());
        assertEquals("LOW", weak.get(0).confidence);
        assertTrue(weak.get(0).detail.contains("false positive"));
        List<SsaBridge.Item> strong = SsaBridge.newFlows(graph("Lcom/example/B;", "Ljava/lang/Object;", false), null);
        assertEquals(1, strong.size());
        assertEquals("HIGH", strong.get(0).confidence);
        assertFalse(strong.get(0).detail.contains("false positive"));
    }

    @Test
    public void aStrongTaintBeatsAWeakOneInAJoinAndTheOtherWayRound() {
        TaintIr.Tv strong1 = TaintIr.Tv.real(1, "S", null);
        TaintIr.Tv weak2 = TaintIr.Tv.real(2, "W", null, true);
        assertFalse(strong1.join(weak2).weak);
        assertFalse(weak2.join(strong1).weak);
        assertEquals("S", weak2.join(strong1).src);
        assertTrue(weak2.join(TaintIr.Tv.real(1, "W1", null, true)).weak);
        assertEquals(2, weak2.join(TaintIr.Tv.real(1, "W1", null, true)).level);
        TaintIr.Tv strong2 = TaintIr.Tv.real(2, "S2", null);
        assertTrue(strong2.covers(weak2));
        assertFalse(weak2.covers(strong2));
    }
}
