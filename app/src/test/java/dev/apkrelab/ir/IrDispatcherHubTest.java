package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.1.0 (Axis Pay 3.1.0: im2.success -> f51.run -> ...): an R8-merged class whose run() switches over a tag field and calls a different class in each case. No call site has
 * many targets; the method is the hub. A path that leaves it is approximate.
 */
public class IrDispatcherHubTest {
    static String target(int i, boolean sink) {
        return ".class public Lt/R" + i + ";\n.super Ljava/lang/Object;\n"
            + ".method public static go()V\n    .locals 3\n"
            + (sink ? "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"p\"\n"
                      + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
                      + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n" : "")
            + "    return-void\n.end method\n";
    }

    /** D.run(): optionally a packed-switch, then one static call to each of n classes. */
    static String dispatcher(int n, boolean withSwitch) {
        StringBuilder sb = new StringBuilder(".class public Lt/D;\n.super Ljava/lang/Object;\n.field public a:I\n.method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public run()V\n    .locals 2\n    iget v0, p0, Lt/D;->a:I\n");
        if (withSwitch) sb.append("    packed-switch v0, :pswitch_data\n");
        for (int i = 0; i < n; i++) sb.append("    :pswitch_" + i + "\n    invoke-static {}, Lt/R" + i + ";->go()V\n");
        sb.append("    return-void\n");
        if (withSwitch) { sb.append("    :pswitch_data\n    .packed-switch 0x0\n"); for (int i = 0; i < n; i++) sb.append("        :pswitch_" + i + "\n"); sb.append("    .end packed-switch\n"); }
        return sb.append(".end method\n").toString();
    }

    static final String HOST = ".class public Lt/A;\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 2\n"
        + "    new-instance v0, Lt/D;\n    invoke-direct {v0}, Lt/D;-><init>()V\n    invoke-virtual {v0}, Lt/D;->run()V\n    return-void\n.end method\n";

    static Boolean viaHub(int n, boolean withSwitch) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(HOST), SmaliParser.parse(dispatcher(n, withSwitch))));
        for (int i = 0; i < n; i++) all.add(SmaliParser.parse(target(i, i == 0)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/R0;")) { assertTrue(f.reachable); return f.viaHub; }
        throw new AssertionError("no flow");
    }

    @Test public void aSwitchMethodThatCallsManyClassesIsAHub() { assertTrue(viaHub(CallGraph.HUB_FANOUT + 1, true)); }

    // twins
    @Test public void withoutASwitchItIsOrdinaryCode() { assertFalse(viaHub(CallGraph.HUB_FANOUT + 1, false)); }
    @Test public void aSwitchOverFewClassesIsOrdinaryCode() { assertFalse(viaHub(3, true)); }

    @Test public void mutantNoDispatcherHubs() {
        boolean was = CallGraph.DISPATCHER_HUBS;
        CallGraph.DISPATCHER_HUBS = false;
        try { assertFalse(viaHub(CallGraph.HUB_FANOUT + 1, true)); } finally { CallGraph.DISPATCHER_HUBS = was; }
    }
}
