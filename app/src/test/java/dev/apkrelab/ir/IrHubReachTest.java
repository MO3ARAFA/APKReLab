package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.1 (Axis Pay device report: MainActivity.onActivityResult -> im2.success -> f51.run -> unrelated SDK classes): an exported activity calls Runnable.run()
 * on a Runnable it does not know; the call site resolves to every Runnable class of the app. A flow whose ONLY path from the entry goes through that call is
 * reported with an approximate reach; a flow that also has a direct path keeps the direct one.
 */
public class IrHubReachTest {

    /** N Runnable classes, the last of which reads an Intent-free SharedPreferences-less source: a constant-free File sink fed by its own getIntent(). */
    static String runnable(int i, boolean sink) {
        return ".class public Lt/R" + i + ";\n.super Ljava/lang/Object;\n.implements Ljava/lang/Runnable;\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public run()V\n    .locals 3\n"
            + (sink ? "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"p\"\n"
                      + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
                      + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n" : "")
            + "    return-void\n.end method\n";
    }

    /** The exported activity: creates every Runnable (so RTA instantiates them), then calls run() on a field of the interface type. */
    static String activity(int n, boolean directCall) {
        StringBuilder sb = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n.field public r:Ljava/lang/Runnable;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n");
        for (int i = 0; i < n; i++) sb.append("    new-instance v0, Lt/R" + i + ";\n    invoke-direct {v0}, Lt/R" + i + ";-><init>()V\n");
        sb.append("    iget-object v1, p0, Lt/A;->r:Ljava/lang/Runnable;\n    invoke-interface {v1}, Ljava/lang/Runnable;->run()V\n");
        if (directCall) sb.append("    new-instance v2, Lt/R0;\n    invoke-direct {v2}, Lt/R0;-><init>()V\n    invoke-virtual {v2}, Lt/R0;->run()V\n");
        sb.append("    return-void\n.end method\n");
        return sb.toString();
    }

    static TaintIr.Flow flow(int n, boolean directCall) {
        List<ClassIr> all = new ArrayList<>();
        all.add(SmaliParser.parse(activity(n, directCall)));
        for (int i = 0; i < n; i++) all.add(SmaliParser.parse(runnable(i, i == 0)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/R0;")) return f;
        return null;
    }

    @Test public void aFlowReachedOnlyThroughAManyTargetFrameworkCallIsApproximate() {
        TaintIr.Flow f = flow(CallGraph.HUB_FANOUT + 2, false);
        assertTrue(f != null && f.reachable);
        assertTrue(f.viaHub);
    }

    // twins
    @Test public void aFewTargetsAreAnOrdinaryPath() {
        TaintIr.Flow f = flow(3, false);
        assertTrue(f != null && f.reachable);
        assertFalse(f.viaHub);
    }

    @Test public void aDirectCallBesideTheHubKeepsTheExactPath() {
        TaintIr.Flow f = flow(CallGraph.HUB_FANOUT + 2, true);
        assertTrue(f != null && f.reachable);
        assertFalse(f.viaHub);
        assertEquals(2, f.entryPath.size());                      // Lt/A;->onCreate -> Lt/R0;->run, not through the interface call
    }

    /** 2.0.2 (Axis Pay 3.1.0: im2 is an R8-renamed callback interface of the APP): the same graph with an app interface Lt/Cb; instead of Runnable. */
    static boolean viaHubWithAppInterface(int n) {
        List<ClassIr> all = new ArrayList<>();
        StringBuilder a = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n.field public r:Lt/Cb;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n");
        for (int i = 0; i < n; i++) a.append("    new-instance v0, Lt/R" + i + ";\n    invoke-direct {v0}, Lt/R" + i + ";-><init>()V\n");
        a.append("    iget-object v1, p0, Lt/A;->r:Lt/Cb;\n    invoke-interface {v1}, Lt/Cb;->go()V\n    return-void\n.end method\n");
        all.add(SmaliParser.parse(a.toString()));
        all.add(SmaliParser.parse(".class public interface abstract Lt/Cb;\n.super Ljava/lang/Object;\n.method public abstract go()V\n.end method\n"));
        for (int i = 0; i < n; i++) {
            all.add(SmaliParser.parse(".class public Lt/R" + i + ";\n.super Ljava/lang/Object;\n.implements Lt/Cb;\n"
                + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
                + ".method public go()V\n    .locals 3\n"
                + (i == 0 ? "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"p\"\n"
                          + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
                          + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n" : "")
                + "    return-void\n.end method\n"));
        }
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/R0;")) { assertTrue(f.reachable); return f.viaHub; }
        throw new AssertionError("no flow");
    }

    @Test public void anAppInterfaceWithManyImplementersIsAHubToo() { assertTrue(viaHubWithAppInterface(CallGraph.HUB_FANOUT + 2)); }

    // twin: the same shape with a few implementers is an ordinary path
    @Test public void anAppInterfaceWithFewImplementersIsNot() { assertFalse(viaHubWithAppInterface(3)); }

    @Test public void mutantNoHubAwarenessReportsAnExactPath() {
        boolean was = CallGraph.HUB_AWARE;
        CallGraph.HUB_AWARE = false;
        try { assertFalse(flow(CallGraph.HUB_FANOUT + 2, false).viaHub); } finally { CallGraph.HUB_AWARE = was; }
    }

    @Test public void theCardSaysTheReachIsApproximate() {
        List<ClassIr> all = new ArrayList<>();
        int n = CallGraph.HUB_FANOUT + 2;
        all.add(SmaliParser.parse(activity(n, false)));
        for (int i = 0; i < n; i++) all.add(SmaliParser.parse(runnable(i, i == 0)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        SsaBridge.Item hit = null;
        for (SsaBridge.Item it : SsaBridge.newFlows(g, null)) if (it.classType.equals("Lt/R0;")) hit = it;
        assertTrue(hit != null && hit.viaHub && hit.reachable);
        assertTrue(hit.detail, hit.detail.contains("treat the reach as approximate"));
    }
}
