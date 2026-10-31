package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.0 step 2 (real-CVE benchmark C01, CVE-2023-39957, Nextcloud Talk ConversationsListController): onCreate fills a list held in a field
 * (iget-object filesToShare; add(intent.getData().toString())), onResume reads the field and builds a File from an element.
 */
public class IrContainerFieldTest {

    static String cls(String fieldType, boolean fromField) {
        String list = fromField
            ? "    iget-object v1, p0, Lt/A;->files:" + fieldType + "\n"
            : "    new-instance v1, Ljava/util/ArrayList;\n    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V\n";
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.field private files:" + fieldType + "\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;\n    move-result-object v0\n"
            + "    invoke-virtual {v0}, Landroid/net/Uri;->toString()Ljava/lang/String;\n    move-result-object v0\n"
            + list
            + "    invoke-interface {v1, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z\n"
            + "    return-void\n.end method\n"
            + ".method public onResume()V\n    .locals 3\n"
            + "    iget-object v0, p0, Lt/A;->files:" + fieldType + "\n"
            + "    const/4 v1, 0x0\n    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;\n    move-result-object v0\n"
            + "    check-cast v0, Ljava/lang/String;\n"
            + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
    }

    static boolean flowInOnResume(String c) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(c)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/A;->onResume")) return true;
        return false;
    }

    @Test public void aListFieldFilledWithIntentDataTaintsItsLaterReads() { assertTrue(flowInOnResume(cls("Ljava/util/ArrayList;", true))); }

    // twin: the list filled in onCreate is a local, never stored in the field: the field read in onResume is clean
    @Test public void twinALocalListLeavesTheFieldClean() { assertFalse(flowInOnResume(cls("Ljava/util/ArrayList;", false))); }

    // twin: a field of an app type is not a container of the table (no write-back through an arbitrary object)
    @Test public void twinAnAppTypedFieldIsNotWrittenBack() { assertFalse(TaintIr.isCollectionField("Lt/A;->files:Lt/Holder;")); }

    @Test public void mutantNoWriteback() {
        boolean was = TaintIr.CONTAINER_FIELD_WRITEBACK;
        TaintIr.CONTAINER_FIELD_WRITEBACK = false;
        try { assertFalse(flowInOnResume(cls("Ljava/util/ArrayList;", true))); } finally { TaintIr.CONTAINER_FIELD_WRITEBACK = was; }
    }
}
