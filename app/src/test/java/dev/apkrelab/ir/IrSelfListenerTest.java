package dev.apkrelab.ir;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.Test;

/**
 * 3.0.0 (real-CVE benchmark C01, Nextcloud Talk ConversationsListController: implements FlexibleAdapter$OnItemClickListener, calls adapter.addListener(this)):
 * a class that hands itself to code outside the app while it implements an outside interface gets approximate edges to its public on... methods.
 */
public class IrSelfListenerTest {
    // Lt/A; (an exported Activity) creates Lt/C; and calls c.attach(); attach() passes "this" to the outside library Lx/Lib;
    static final String ACT = ".class public Lt/A;\n.super Landroid/app/Activity;\n" + IrBridgeSupport.CTOR
        + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 2\n    new-instance v0, Lt/C;\n    invoke-direct {v0}, Lt/C;-><init>()V\n"
        + "    invoke-virtual {v0}, Lt/C;->attach()V\n    return-void\n.end method\n";
    static String ctl(boolean implementsOutside, boolean passesSelf) {
        return ".class public Lt/C;\n.super Ljava/lang/Object;\n" + (implementsOutside ? ".implements Lx/Lib$OnItemClickListener;\n" : "") + IrBridgeSupport.CTOR
            + ".method public attach()V\n    .locals 2\n    new-instance v0, Lx/Lib;\n    invoke-direct {v0}, Lx/Lib;-><init>()V\n"
            + (passesSelf ? "    invoke-virtual {v0, p0}, Lx/Lib;->addListener(Ljava/lang/Object;)Lx/Lib;\n" : "    invoke-virtual {v0}, Lx/Lib;->clear()V\n")
            + "    return-void\n.end method\n"
            + ".method public onItemClick(Landroid/view/View;I)Z\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"
            + ".method private onHelper()V\n    .locals 0\n    return-void\n.end method\n";
    }
    static CallGraph graph(String c) {
        return CallGraph.build(new ArrayList<>(Arrays.asList(SmaliParser.parse(ACT), SmaliParser.parse(c))), Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
    }
    static final String CLICK = "Lt/C;->onItemClick(Landroid/view/View;I)Z";

    @Test public void aSelfRegisteredListenerMethodIsReachedApproximately() {
        CallGraph g = graph(ctl(true, true));
        assertTrue(g.isReachable(CLICK));
        assertFalse(g.isReachable("Lt/C;->onHelper()V"));                      // private: not an interface method
        boolean approx = false;
        for (CallGraph.Edge e : g.edgesFrom("Lt/C;->attach()V")) if (e.callee.equals(CLICK)) { approx = "callback~".equals(e.kind) && g.isHubEdge(e); }
        assertTrue(approx);
    }

    @Test public void notPassingItselfOrNoOutsideInterfaceGivesNoEdge() {              // twins
        assertFalse(graph(ctl(true, false)).isReachable(CLICK));
        assertFalse(graph(ctl(false, true)).isReachable(CLICK));
    }

    @Test public void theMutationLosesTheEdge() {
        boolean was = CallGraph.SELF_LISTENER_EDGES;
        CallGraph.SELF_LISTENER_EDGES = false;
        try { assertFalse(graph(ctl(true, true)).isReachable(CLICK)); } finally { CallGraph.SELF_LISTENER_EDGES = was; }
    }
}
