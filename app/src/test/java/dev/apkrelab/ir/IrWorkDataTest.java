package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.0 step 2 (real-CVE benchmark C01, CVE-2023-39957): an exported activity puts Intent data into WorkManager input Data under a literal key,
 * a Worker reads the same key and builds a File from it. The worker's flow carries the activity's Intent source.
 */
public class IrWorkDataTest {

    static String a(String putKey) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"p\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
            + "    new-instance v3, Landroidx/work/Data$Builder;\n    invoke-direct {v3}, Landroidx/work/Data$Builder;-><init>()V\n"
            + "    const-string v1, \"" + putKey + "\"\n"
            + "    invoke-virtual {v3, v1, v2}, Landroidx/work/Data$Builder;->putString(Ljava/lang/String;Ljava/lang/String;)Landroidx/work/Data$Builder;\n"
            + "    invoke-virtual {v3}, Landroidx/work/Data$Builder;->build()Landroidx/work/Data;\n"
            + "    return-void\n.end method\n";
    }

    static final String W = ".class public Lt/W;\n.super Landroidx/work/Worker;\n"
        + ".method public doWork()Landroidx/work/ListenableWorker$Result;\n    .locals 3\n"
        + "    invoke-virtual {p0}, Lt/W;->getInputData()Landroidx/work/Data;\n    move-result-object v0\n"
        + "    const-string v1, \"name\"\n    invoke-virtual {v0, v1}, Landroidx/work/Data;->getString(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
        + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
        + "    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n    const/4 v0, 0x0\n    return-object v0\n.end method\n";

    static TaintIr.Flow flowInW(String aCls) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(aCls), SmaliParser.parse(W)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/W;")) return f;
        return null;
    }

    @Test public void theWorkerReadsTheActivityIntentThroughInputData() {
        TaintIr.Flow f = flowInW(a("name"));
        assertNotNull("the File built in the worker carries the Intent extra", f);
        assertTrue(f.source, f.source.startsWith("Intent."));
    }

    @Test public void twinAnotherKeyIsNotLinked() { assertFalse(flowInW(a("other")) != null); }

    @Test public void mutantNoWorkData() {
        boolean was = TaintIr.WORK_DATA;
        TaintIr.WORK_DATA = false;
        try { assertFalse(flowInW(a("name")) != null); } finally { TaintIr.WORK_DATA = was; }
    }
}
