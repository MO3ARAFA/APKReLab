package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.0 step 2 (real-CVE benchmark C05, CVE-2023-24804, ownCloud UriUploader -> CopyAndUploadContentUrisTask): an exported activity passes Intent data
 * in the params of AsyncTask.execute(params...); the task's doInBackground(Object[]) reads params[0] and builds a File from it.
 */
public class IrAsyncTaskArgsTest {

    static String a(boolean tainted) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n"
            + (tainted
                ? "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                  + "    const-string v1, \"p\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
                : "    const-string v0, \"fixed.txt\"\n")
            + "    filled-new-array {v0}, [Ljava/lang/Object;\n    move-result-object v1\n"
            + "    new-instance v2, Lt/T;\n    invoke-direct {v2}, Lt/T;-><init>()V\n"
            + "    invoke-virtual {v2, v1}, Lt/T;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;\n"
            + "    return-void\n.end method\n";
    }

    static final String T = ".class public Lt/T;\n.super Landroid/os/AsyncTask;\n"
        + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Landroid/os/AsyncTask;-><init>()V\n    return-void\n.end method\n"
        + ".method protected doInBackground([Ljava/lang/Object;)Ljava/lang/Object;\n    .locals 3\n"
        + "    const/4 v0, 0x0\n    aget-object v1, p1, v0\n    check-cast v1, Ljava/lang/String;\n"
        + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
        + "    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n    const/4 v0, 0x0\n    return-object v0\n.end method\n";

    static boolean flowInT(String aCls) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(aCls), SmaliParser.parse(T)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows)
            if (f.sink.method.startsWith("Lt/T;") && f.source.startsWith("Intent.")) return true;
        return false;
    }

    @Test public void theParamsOfExecuteReachDoInBackground() { assertTrue(flowInT(a(true))); }

    // twin: a constant file name in the params: nothing from outside reaches the File
    @Test public void twinConstantParamsAreClean() { assertFalse(flowInT(a(false))); }

    @Test public void mutantNoAsyncTaskArgs() {
        boolean was = TaintIr.ASYNC_TASK_ARGS;
        TaintIr.ASYNC_TASK_ARGS = false;
        try { assertFalse(flowInT(a(true))); } finally { TaintIr.ASYNC_TASK_ARGS = was; }
    }
}
