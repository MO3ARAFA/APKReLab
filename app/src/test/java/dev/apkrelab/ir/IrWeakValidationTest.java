package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.1.0 (real-CVE benchmark C05, ownCloud ReceiveExternalFilesActivity.prepareStreamsToUpload: uri.toString().contains("/data") && contains(packageName)): a substring or
 * suffix test alone is not a sanitizer. A regex full match, an allow-list lookup, a canonical path or a named validator is.
 */
public class IrWeakValidationTest {
    static List<SsaBridge.Item> items(String check) {
        String t = ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n"
            + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"p\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
            + check
            + "    new-instance v4, Ljava/io/FileInputStream;\n    invoke-direct {v4, v2}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(t)));
        return SsaBridge.newFlows(CallGraph.build(all, Arrays.asList("Lt/D;"), CallGraph.Mode.RTA, null), null);
    }

    static final String CONTAINS = "    const-string v3, \"/data\"\n    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z\n    move-result v5\n";
    static final String ENDS = "    const-string v3, \"example.com\"\n    invoke-virtual {v2, v3}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z\n    move-result v5\n";
    static final String STARTS = "    const-string v3, \"https://\"\n    invoke-virtual {v2, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n    move-result v5\n";
    static final String MATCHES = "    const-string v3, \"[a-z]+\"\n    invoke-virtual {v2, v3}, Ljava/lang/String;->matches(Ljava/lang/String;)Z\n    move-result v5\n";
    static final String CANON = "    new-instance v3, Ljava/io/File;\n    invoke-direct {v3, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v3}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;\n    move-result-object v5\n";

    @Test public void aSubstringTestAloneIsNotCountedAsAValidation() {
        for (String weak : new String[]{CONTAINS, ENDS}) {
            SsaBridge.Item it = items(weak).get(0);
            assertEquals("HIGH", it.confidence);
            assertTrue(it.detail, it.detail.contains("only WEAK checks"));
            assertFalse(it.detail, it.detail.contains("validation-like calls"));
        }
    }

    // twins: strong checks still count
    // 2.2 (session 3a.2): this sink is a FILE path, and a startsWith("https://") prefix test no longer counts for a file sink (IrSinkKindValidationTest); it still counts for a WebView sink
    @Test public void aFullMatchOrACanonicalPathStillCounts() {
        for (String strong : new String[]{MATCHES, CANON}) {
            SsaBridge.Item it = items(strong).get(0);
            assertEquals("MEDIUM", it.confidence);
            assertTrue(it.detail, it.detail.contains("validation-like calls"));
            assertFalse(it.detail, it.detail.contains("only WEAK checks"));
        }
    }

    @Test public void aStrongCheckBesideAWeakOneStillCounts() {
        SsaBridge.Item it = items(CONTAINS + MATCHES).get(0);
        assertEquals("MEDIUM", it.confidence);
        assertFalse(it.detail.contains("only WEAK checks"));
    }

    @Test public void noCheckAtAllSaysNeither() {
        SsaBridge.Item it = items("").get(0);
        assertEquals("HIGH", it.confidence);
        assertFalse(it.detail.contains("only WEAK checks")); assertFalse(it.detail.contains("validation-like"));
    }

    @Test public void mutantSwitchOffCountsASubstringAsValidation() {
        boolean was = SsaBridge.WEAK_VALIDATION;
        SsaBridge.WEAK_VALIDATION = false;
        try { SsaBridge.Item it = items(CONTAINS).get(0); assertEquals("MEDIUM", it.confidence); assertTrue(it.detail.contains("validation-like calls")); } finally { SsaBridge.WEAK_VALIDATION = was; }
    }
}
