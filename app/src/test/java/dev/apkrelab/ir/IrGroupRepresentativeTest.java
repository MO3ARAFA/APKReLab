package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.1 (real-CVE benchmark C04, Tasks ShareLinkActivity -> FileHelper.copyStream): two flows end at the same sink of the same method, one from
 * SharedPreferences and one from an exported component's Intent. One card is shown per sink; it must be the Intent one.
 */
public class IrGroupRepresentativeTest {

    private static final String PREFS = "    invoke-virtual {p0}, Lt/A;->getPrefs()Landroid/content/SharedPreferences;\n    move-result-object v0\n"
        + "    const-string v1, \"k\"\n    invoke-interface {v0, v1, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n";
    private static final String INTENT = "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
        + "    const-string v1, \"p\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v3\n";
    private static final String OPEN2 = "    new-instance v4, Ljava/io/FileInputStream;\n    invoke-direct {v4, v2}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n"
        + "    new-instance v4, Ljava/io/FileInputStream;\n    invoke-direct {v4, v3}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n";

    private static List<SsaBridge.Item> items(String firstSource, String secondSource, boolean prefsFirst) {
        String t = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n"
            + (prefsFirst ? PREFS + INTENT : INTENT + PREFS) + OPEN2 + "    return-void\n.end method\n"
            + ".method public getPrefs()Landroid/content/SharedPreferences;\n    .locals 1\n    const/4 v0, 0x0\n    return-object v0\n.end method\n";
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(t)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return SsaBridge.newFlows(g, null);
    }

    private static boolean intentCardShown(boolean prefsFirst) {
        List<SsaBridge.Item> it = items(null, null, prefsFirst);
        assertEquals(it.toString(), 1, it.size());
        return it.get(0).detail.startsWith("Data from Intent.");
    }

    @Test public void theIntentFlowIsTheCardWhateverTheOrder() {
        assertTrue(intentCardShown(true));
        assertTrue(intentCardShown(false));
    }

    @Test public void mutantNoPreferenceShowsThePrefsFlowWhenItComesFirst() {
        boolean was = SsaBridge.PREFER_OUTSIDE_SOURCE;
        SsaBridge.PREFER_OUTSIDE_SOURCE = false;
        try {
            boolean a = intentCardShown(true), b = intentCardShown(false);
            assertTrue("with the preference off the shown flow depends on the order", !(a && b));
        } finally { SsaBridge.PREFER_OUTSIDE_SOURCE = was; }
    }
}
