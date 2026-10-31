package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.0 step 2 (real-CVE benchmark C05 / C08: ownCloud and Nextcloud UriUploader): an exported activity hands the shared Uri list to the constructor of a
 * helper that keeps it in a collection field; a later method of the helper reads the field and opens the files.
 */
public class IrCtorCollectionTest {

    static String a() {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"android.intent.extra.STREAM\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringArrayListExtra(Ljava/lang/String;)Ljava/util/ArrayList;\n    move-result-object v0\n"
            + "    new-instance v2, Lt/U;\n    invoke-direct {v2, v0}, Lt/U;-><init>(Ljava/util/ArrayList;)V\n"
            + "    invoke-virtual {v2}, Lt/U;->upload()V\n"
            + "    return-void\n.end method\n";
    }

    static String u(String fieldType) {
        return ".class public Lt/U;\n.super Ljava/lang/Object;\n.field private uris:" + fieldType + "\n"
            + ".method public constructor <init>(Ljava/util/ArrayList;)V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n"
            + "    iput-object p1, p0, Lt/U;->uris:" + fieldType + "\n    return-void\n.end method\n"
            + ".method public upload()V\n    .locals 3\n"
            + "    iget-object v0, p0, Lt/U;->uris:" + fieldType + "\n"
            + "    check-cast v0, Ljava/util/List;\n"
            + "    const/4 v1, 0x0\n    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;\n    move-result-object v0\n"
            + "    check-cast v0, Ljava/lang/String;\n"
            + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
    }

    static boolean flowInU(String fieldType) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(a()), SmaliParser.parse(u(fieldType))));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows)
            if (f.sink.method.startsWith("Lt/U;->upload") && f.source.startsWith("Intent.")) return true;
        return false;
    }

    @Test public void aListKeptByAConstructorCarriesTheCallersTaint() { assertTrue(flowInU("Ljava/util/ArrayList;")); }

    // twin: the same constructor storing into a field of an app type (not a collection) is not captured outside deferred tasks
    @Test public void twinAnAppTypedFieldIsNotCaptured() { assertFalse(flowInU("Lt/Holder;")); }

    @Test public void mutantNoCtorCollections() {
        boolean was = TaintIr.CTOR_COLLECTIONS;
        TaintIr.CTOR_COLLECTIONS = false;
        try { assertFalse(flowInU("Ljava/util/ArrayList;")); } finally { TaintIr.CTOR_COLLECTIONS = was; }
    }
}
