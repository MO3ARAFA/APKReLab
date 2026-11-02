package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.2 session 3a.2: a validation-like call counts only when it can restrict the KIND of sink the value reaches. A path check says nothing about which page a WebView
 * loads; a scheme / host / authority test says nothing about which file a path names; a prefix test (startsWith("http")) restricts neither a file path nor an opened
 * content URI. "Counts" = the card's confidence steps down and it says "validation-like calls" (FindingScore reads that sentence as evidence 0.3, which takes the card out
 * of MUST FIX); "does not count" = the card is what it would be with no validation at all.
 */
public class IrSinkKindValidationTest {

    static final String HEAD = ".class public Lt/A;\n.super Landroid/app/Activity;\n.field public w:Landroid/webkit/WebView;\n.field public cr:Landroid/content/ContentResolver;\n"
        + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 9\n    new-instance v0, Landroid/content/Intent;\n";
    static final String STR_SRC = "    const-string v1, \"p\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v3\n";
    static final String URI_SRC = "    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;\n    move-result-object v3\n";
    static final String TAIL = "    return-void\n.end method\n";

    static final String FILE_SINK = "    new-instance v4, Ljava/io/File;\n    invoke-direct {v4, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v4}, Ljava/io/File;->delete()Z\n";
    static final String WEB_SINK = "    iget-object v5, p0, Lt/A;->w:Landroid/webkit/WebView;\n    invoke-virtual {v5, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n";
    static final String URI_SINK = "    iget-object v5, p0, Lt/A;->cr:Landroid/content/ContentResolver;\n    invoke-virtual {v5, v3}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;\n";

    static final String STARTS_HTTP = "    const-string v6, \"http\"\n    invoke-virtual {v3, v6}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n";
    static final String CANONICAL = "    new-instance v7, Ljava/io/File;\n    invoke-direct {v7, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v7}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;\n";
    static final String HOST = "    invoke-static {v3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;\n    move-result-object v8\n    invoke-virtual {v8}, Landroid/net/Uri;->getHost()Ljava/lang/String;\n";
    static final String AUTHORITY = "    invoke-virtual {v3}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;\n";
    static final String CANON_THEN_PREFIX = CANONICAL + "    invoke-virtual {v7}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;\n    move-result-object v6\n"
        + "    invoke-virtual {v6, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n";

    static SsaBridge.Item item(String src, String validation, String sink, String title) {
        ClassIr c = SmaliParser.parse(HEAD + src + validation + sink + TAIL);
        List<ClassIr> all = new ArrayList<>(Arrays.asList(c));
        for (SsaBridge.Item it : SsaBridge.newFlows(all, Arrays.asList("Lt/A;"), new ArrayList<TaintIr.Old>())) if (it.title.equals(title)) return it;
        throw new AssertionError("no flow titled " + title);
    }

    static void counts(SsaBridge.Item base, SsaBridge.Item it) {
        assertTrue(it.detail, it.detail.contains("The chain also contains validation-like calls"));
        assertFalse(it.detail, it.detail.contains("none of them restricts this kind of sink"));
        assertFalse("confidence must step down: " + it.confidence, base.confidence.equals(it.confidence));
    }

    static void doesNotCount(SsaBridge.Item base, SsaBridge.Item it) {
        assertFalse(it.detail, it.detail.contains("The chain also contains validation-like calls"));      // FindingScore would otherwise take the card out of MUST FIX
        assertTrue(it.detail, it.detail.contains("none of them restricts this kind of sink"));
        assertEquals(base.confidence, it.confidence);
        assertEquals(base.sev, it.sev);
    }

    // ---- file sink (CWE-22)
    @Test public void wrongKindValidationDoesNotSuppressFileSink() {
        doesNotCount(item(STR_SRC, "", FILE_SINK, TaintIr.T_FILE), item(STR_SRC, STARTS_HTTP, FILE_SINK, TaintIr.T_FILE));
    }
    @Test public void rightKindValidationSuppressesFileSink() {
        counts(item(STR_SRC, "", FILE_SINK, TaintIr.T_FILE), item(STR_SRC, CANON_THEN_PREFIX, FILE_SINK, TaintIr.T_FILE));
    }

    // ---- WebView sink
    @Test public void wrongKindValidationDoesNotSuppressWebViewSink() {
        doesNotCount(item(STR_SRC, "", WEB_SINK, TaintIr.T_WEB), item(STR_SRC, CANONICAL, WEB_SINK, TaintIr.T_WEB));
    }
    @Test public void rightKindValidationSuppressesWebViewSink() {
        counts(item(STR_SRC, "", WEB_SINK, TaintIr.T_WEB), item(STR_SRC, HOST, WEB_SINK, TaintIr.T_WEB));
    }

    @Test public void aPrefixSchemeCheckStillSuppressesWebViewSink() {
        counts(item(STR_SRC, "", WEB_SINK, TaintIr.T_WEB), item(STR_SRC, STARTS_HTTP, WEB_SINK, TaintIr.T_WEB));
    }

    // ---- content URI sink (CWE-73)
    @Test public void wrongKindValidationDoesNotSuppressUriSink() {
        doesNotCount(item(URI_SRC, "", URI_SINK, TaintIr.T_URI), item(URI_SRC, STARTS_HTTP, URI_SINK, TaintIr.T_URI));
    }
    @Test public void rightKindValidationSuppressesUriSink() {
        counts(item(URI_SRC, "", URI_SINK, TaintIr.T_URI), item(URI_SRC, AUTHORITY, URI_SINK, TaintIr.T_URI));
    }

    // ---- mutant: every validation matches every sink kind
    @Test public void mutantEveryValidationCountsEverywhere() {
        boolean was = SsaBridge.SINK_KIND_VALIDATION;
        SsaBridge.SINK_KIND_VALIDATION = false;
        try {
            SsaBridge.Item it = item(STR_SRC, STARTS_HTTP, FILE_SINK, TaintIr.T_FILE);
            assertTrue(it.detail, it.detail.contains("The chain also contains validation-like calls"));
        } finally { SsaBridge.SINK_KIND_VALIDATION = was; }
    }
}
