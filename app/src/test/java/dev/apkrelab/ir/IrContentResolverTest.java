package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.77.0: the sharer's file name read from a cursor on the caller's content URI (Termux FileReceiverActivity, set 2). */
public class IrContentResolverTest {

    private static List<TaintIr.Flow> flows(String uriSetup) {
        String t = ".class public Lt/R;\n.super Landroid/app/Activity;\n\n.method public onResume()V\n    .locals 8\n"
                + uriSetup
                + "    invoke-virtual {p0}, Lt/R;->getContentResolver()Landroid/content/ContentResolver;\n    move-result-object v1\n"
                + "    const/4 v3, 0x0\n    const/4 v4, 0x0\n    const/4 v5, 0x0\n    const/4 v6, 0x0\n"
                + "    invoke-virtual/range {v1 .. v6}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;\n"
                + "    move-result-object v3\n"
                + "    const-string v4, \"_display_name\"\n"
                + "    invoke-interface {v3, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I\n    move-result v4\n"
                + "    invoke-interface {v3, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;\n    move-result-object v5\n"
                + "    new-instance v6, Ljava/io/File;\n    const-string v7, \"/data/data/x/files/downloads\"\n"
                + "    invoke-direct {v6, v7, v5}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V\n"
                + "    new-instance v7, Ljava/io/FileOutputStream;\n    invoke-direct {v7, v6}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V\n"
                + "    return-void\n.end method\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/R;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows;
    }

    @Test public void displayNameOfTheCallersUriReachesTheFileSink() {
        List<TaintIr.Flow> f = flows("    invoke-virtual {p0}, Lt/R;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                + "    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;\n    move-result-object v2\n");
        assertTrue(!f.isEmpty());
        assertEquals(TaintIr.T_FILE, f.get(0).sink.title);
    }

    @Test public void aCursorOnTheAppsOwnConstantUriIsQuiet() {
        assertTrue(flows("    const-string v0, \"content://com.example.own/files\"\n"
                + "    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;\n    move-result-object v2\n").isEmpty());
    }
}
