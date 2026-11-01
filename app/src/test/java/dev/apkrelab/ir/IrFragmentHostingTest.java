package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 2.0.2 (Omni-Notes DetailFragment): the callbacks of a Fragment that a reached method instantiates are reached; a Fragment nobody creates stays unreached. */
public class IrFragmentHostingTest {
    static final String HOST = ".class public Lt/A;\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 2\n"
        + "    new-instance v0, Lt/F;\n    invoke-direct {v0}, Lt/F;-><init>()V\n    return-void\n.end method\n";
    static final String FRAG = ".class public Lt/F;\n.super Landroidx/fragment/app/Fragment;\n"
        + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Landroidx/fragment/app/Fragment;-><init>()V\n    return-void\n.end method\n"
        + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
        + "    invoke-virtual {p0}, Lt/F;->getActivity()Landroid/app/Activity;\n    move-result-object v0\n"
        + "    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
        + "    const-string v1, \"p\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
        + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";

    static CallGraph graph(String host) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(host), SmaliParser.parse(FRAG)));
        return CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
    }

    @Test public void aFragmentCreatedByAReachedMethodIsReached() {
        CallGraph g = graph(HOST);
        assertTrue(g.isReachable("Lt/F;->onCreate(Landroid/os/Bundle;)V"));
        assertTrue(g.pathTo("Lt/F;->onCreate(Landroid/os/Bundle;)V").size() == 2);
    }

    // twin: nobody instantiates it
    @Test public void aFragmentNobodyCreatesStaysUnreached() {
        assertFalse(graph(HOST.replace("    new-instance v0, Lt/F;\n    invoke-direct {v0}, Lt/F;-><init>()V\n", "")).isReachable("Lt/F;->onCreate(Landroid/os/Bundle;)V"));
    }

    @Test public void mutantNoFragmentHosting() {
        boolean was = CallGraph.FRAGMENT_HOSTING;
        CallGraph.FRAGMENT_HOSTING = false;
        try { assertFalse(graph(HOST).isReachable("Lt/F;->onCreate(Landroid/os/Bundle;)V")); } finally { CallGraph.FRAGMENT_HOSTING = was; }
    }
}
