package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.84.0: provider parameters of a provider the manifest does not export, and file-name flows that take a basename (real-app set 8). */
public class IrSetEightTest {

    private static final String PROVIDER = ".class public Lt/P;\n.super Landroid/content/ContentProvider;\n\n"
            + ".method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I\n    .locals 3\n"
            + "    invoke-virtual {p0}, Lt/P;->db()Landroid/database/sqlite/SQLiteDatabase;\n    move-result-object v0\n"
            + "    const-string v1, \"t\"\n"
            + "    invoke-virtual {v0, v1, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I\n    move-result v2\n    return v2\n.end method\n";

    private static List<SsaBridge.Item> provider(List<String> entries) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(PROVIDER));
        return SsaBridge.newFlows(cs, entries, new ArrayList<TaintIr.Old>());
    }

    @Test public void anExportedProviderKeepsItsParameterSource() {
        List<SsaBridge.Item> it = provider(Arrays.asList("Lt/P;"));
        assertEquals(1, it.size());
        assertEquals("HIGH", it.get(0).sev);
    }

    @Test public void aProviderThatIsNotAnExportedEntryIsAWeakLead() {
        // the manifest lists an exported component (another class), the provider is not among them
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(PROVIDER));
        cs.add(SmaliParser.parse(".class public Lt/Main;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 1\n    return-void\n.end method\n"));
        List<SsaBridge.Item> it = SsaBridge.newFlows(cs, Arrays.asList("Lt/Main;"), new ArrayList<TaintIr.Old>());
        // the provider's methods are still analysed, but the source is internal: LOW confidence, one level lower
        int seen = 0;
        for (SsaBridge.Item i : it) if (i.classType.equals("Lt/P;")) {
            seen++;
            assertEquals("LOW", i.confidence);
            assertEquals("LOW", i.sev);                        // SQL sink HIGH: -1 for the weak lead, -1 for the unexported provider
            assertTrue(i.detail.contains("not exported"));
        }
        assertEquals(1, seen);
    }

    private static String fileFlow(String cleaning) {
        return ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n"
                + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"n\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + cleaning
                + "    new-instance v3, Ljava/io/FileOutputStream;\n    invoke-direct {v3, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";
    }

    private static List<SsaBridge.Item> file(String cleaning) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(fileFlow(cleaning)));
        return SsaBridge.newFlows(cs, Arrays.asList("Lt/D;"), new ArrayList<TaintIr.Old>());
    }

    @Test public void aBasenameStepLowersTheFileNameCardAndPlainFlowsStayHigh() {
        assertEquals("HIGH", file("").get(0).sev);
        String basename = "    const/16 v4, 0x2f\n    invoke-virtual {v2, v4}, Ljava/lang/String;->lastIndexOf(I)I\n    move-result v4\n    add-int/lit8 v4, v4, 0x1\n"
                + "    invoke-virtual {v2, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;\n    move-result-object v2\n";
        SsaBridge.Item i = file(basename).get(0);
        assertEquals("LOW", i.confidence);
        assertTrue(!i.sev.equals("HIGH"));
        assertTrue(i.detail.contains("base name"));
        // a helper only NAMED sanitize* is a one-step drop (see IrItemPathTest), not the structural basename
        // a lastIndexOf alone (no substring) is not a basename
        String onlyIndex = "    const/16 v4, 0x2f\n    invoke-virtual {v2, v4}, Ljava/lang/String;->lastIndexOf(I)I\n    move-result v4\n";
        assertEquals("HIGH", file(onlyIndex).get(0).sev);
    }

    @Test public void theBasenameHelperCanBeACalleeOfTheMethodOnThePath() {                  // OpenTracks importNameForFilename
        String t = ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n"
                + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"n\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-static {v2}, Lt/D;->cleanName(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    new-instance v3, Ljava/io/FileOutputStream;\n    invoke-direct {v3, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n\n"
                + ".method public static cleanName(Ljava/lang/String;)Ljava/lang/String;\n    .locals 3\n"
                + "    const/16 v0, 0x2f\n    invoke-virtual {p0, v0}, Ljava/lang/String;->lastIndexOf(I)I\n    move-result v1\n    add-int/lit8 v1, v1, 0x1\n"
                + "    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;\n    move-result-object v2\n    return-object v2\n.end method\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        List<SsaBridge.Item> it = SsaBridge.newFlows(cs, Arrays.asList("Lt/D;"), new ArrayList<TaintIr.Old>());
        assertEquals(1, it.size());
        assertEquals("LOW", it.get(0).confidence);
        assertTrue(it.get(0).detail.contains("base name"));
    }

    @Test public void fileSeparatorCharAndReplaceAreSeparatorCleaningToo() {                  // the real OpenTracks importNameForFilename
        String sep = "    sget-char v4, Ljava/io/File;->separatorChar:C\n";
        String basename = sep + "    invoke-virtual {v2, v4}, Ljava/lang/String;->lastIndexOf(I)I\n    move-result v4\n    add-int/lit8 v4, v4, 0x1\n"
                + "    invoke-virtual {v2, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;\n    move-result-object v2\n";
        assertEquals("LOW", file(basename).get(0).confidence);
        String replace = sep + "    const/16 v3, 0x2d\n    invoke-virtual {v2, v4, v3}, Ljava/lang/String;->replace(CC)Ljava/lang/String;\n    move-result-object v2\n";
        assertEquals("LOW", file(replace).get(0).confidence);
        // a replace(CC) that does not involve the separator is not a cleaning
        String other = "    const/16 v4, 0x61\n    const/16 v3, 0x62\n    invoke-virtual {v2, v4, v3}, Ljava/lang/String;->replace(CC)Ljava/lang/String;\n    move-result-object v2\n";
        assertEquals("HIGH", file(other).get(0).sev);
    }
}

