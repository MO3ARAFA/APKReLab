package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * Maturity phase 3.5 (blind round 1, Chaka viewer): a replace whose constant pattern removes every '/' leaves one path segment, so a CWE-22 file sink does not
 * take the value; every other sink still does.
 */
public class IrPathStripSanitizerTest {

    private static final String HEAD = ".class public Lt/A;\n.super Landroid/app/Activity;\n"
        + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 8\n"
        + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
        + "    const-string v1, \"name\"\n"
        + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n";
    private static final String FILE_SINK = "    new-instance v4, Ljava/io/File;\n    const-string v5, \"/data/x\"\n"
        + "    invoke-direct {v4, v5, v0}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V\n"
        + "    new-instance v6, Ljava/io/FileInputStream;\n    invoke-direct {v6, v4}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V\n";
    private static final String SQL_SINK = "    const/4 v7, 0x0\n    invoke-virtual {v7, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V\n";
    private static final String END = "    return-void\n.end method\n";

    private static String replaceAll(String smaliPattern, String smaliRepl) {
        return "    const-string v2, \"" + smaliPattern + "\"\n    const-string v3, \"" + smaliRepl + "\"\n"
            + "    invoke-virtual {v0, v2, v3}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n";
    }

    private static List<TaintIr.Flow> flows(String body, String... more) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(HEAD + body + END));
        for (String m : more) cs.add(SmaliParser.parse(m));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows;
    }

    private static long fileFlows(List<TaintIr.Flow> f) {
        return f.stream().filter(x -> x.sink.title.equals(TaintIr.T_FILE)).count();
    }

    // ---- the Chaka shape and its twins ----
    @Test
    public void anAllowListThatDropsTheSlashCleansTheFilePath() {
        assertEquals(0, fileFlows(flows(replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + FILE_SINK)));
    }

    @Test
    public void twinWhitespaceReplacementKeepsSlashAndDots() {
        assertEquals(1, fileFlows(flows(replaceAll("\\\\s+", "_") + FILE_SINK)));
    }

    @Test
    public void twinAnAllowListThatKeepsTheSlashIsNoSanitizer() {
        assertEquals(1, fileFlows(flows(replaceAll("[^a-zA-Z0-9/._]+", "_") + FILE_SINK)));
    }

    @Test
    public void twinAReplacementThatPutsASlashBackIsNoSanitizer() {
        assertEquals(1, fileFlows(flows(replaceAll("[^a-z]+", "/") + FILE_SINK)));
        assertEquals(1, fileFlows(flows(replaceAll("([^a-z]+)", "$1") + FILE_SINK)));
    }

    @Test
    public void twinTheCleanValueStillReachesSql() {                          // only file sinks honour it
        List<TaintIr.Flow> f = flows(replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + FILE_SINK + SQL_SINK);
        assertEquals(0, fileFlows(f));
        assertEquals(1, f.size() - fileFlows(f));
    }

    // ---- the other replace forms ----
    @Test
    public void literalReplaceOfTheSlash() {
        String lit = "    const-string v2, \"/\"\n    const-string v3, \"_\"\n"
            + "    invoke-virtual {v0, v2, v3}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;\n    move-result-object v0\n";
        assertEquals(0, fileFlows(flows(lit + FILE_SINK)));
        assertEquals(1, fileFlows(flows(lit.replace("\"/\"", "\"..\"") + FILE_SINK)));      // twin: removing ".." leaves "/"
        assertEquals(1, fileFlows(flows(lit.replace("const-string v3, \"_\"", "const-string v3, \"a/\"") + FILE_SINK)));   // twin: the slash is put back
    }

    @Test
    public void charReplaceOfTheSlash() {
        String ch = "    const/16 v2, 0x2f\n    const/16 v3, 0x5f\n"
            + "    invoke-virtual {v0, v2, v3}, Ljava/lang/String;->replace(CC)Ljava/lang/String;\n    move-result-object v0\n";
        assertEquals(0, fileFlows(flows(ch + FILE_SINK)));
        assertEquals(1, fileFlows(flows(ch.replace("0x2f\n", "0x2e\n") + FILE_SINK)));      // twin: '.' -> '_' keeps '/'
    }

    @Test
    public void kotlinStringsReplaceDefault() {
        String k = "    const-string v2, \"/\"\n    const-string v3, \"\"\n    const/4 v5, 0x0\n    const/4 v6, 0x4\n    const/4 v7, 0x0\n"
            + "    invoke-static/range {v0 .. v7}, Lkotlin/text/StringsKt;->replace$default(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Ljava/lang/String;\n"
            + "    move-result-object v0\n";
        String k2 = "    const-string v2, \"/\"\n    const-string v3, \"\"\n    const/4 v4, 0x0\n    const/4 v5, 0x4\n    const/4 v6, 0x0\n"
            + "    invoke-static {v0, v2, v3, v4, v5, v6}, Lkotlin/text/StringsKt;->replace$default(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Ljava/lang/String;\n"
            + "    move-result-object v0\n";
        assertEquals(0, fileFlows(flows(k2 + FILE_SINK)));
        assertEquals(1, fileFlows(flows(k2.replace("const-string v2, \"/\"", "const-string v2, \" \"") + FILE_SINK)));
    }

    @Test
    public void kotlinRegexReplaceOnAConstantRegex() {
        String r = "    new-instance v2, Lkotlin/text/Regex;\n    const-string v3, \"[^a-z0-9]\"\n"
            + "    invoke-direct {v2, v3}, Lkotlin/text/Regex;-><init>(Ljava/lang/String;)V\n    const-string v3, \"_\"\n"
            + "    invoke-virtual {v2, v0, v3}, Lkotlin/text/Regex;->replace(Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n";
        List<TaintIr.Flow> f = flows(r + FILE_SINK + SQL_SINK);
        assertEquals(0, fileFlows(f));
        assertEquals("the cleaned value is still tainted for SQL", 1, f.size());
        assertEquals(1, fileFlows(flows(r.replace("[^a-z0-9]", "[^a-z0-9/]") + FILE_SINK)));
    }

    // ---- across a field (the Chaka shape: cleaned in onCreate, opened in another method) and across a callee ----
    private static final String HOLDER = ".class public Lt/H;\n.super Ljava/lang/Object;\n.field public static n:Ljava/lang/String;\n"
        + ".method public static open()V\n    .locals 4\n    sget-object v0, Lt/H;->n:Ljava/lang/String;\n" + FILE_SINK.replace("v6", "v3").replace("v4", "v1").replace("v5", "v2") + END;

    @Test
    public void throughAStaticField() {
        String put = "    sput-object v0, Lt/H;->n:Ljava/lang/String;\n    invoke-static {}, Lt/H;->open()V\n";
        assertEquals(0, fileFlows(flows(replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + put, HOLDER)));
        assertEquals(1, fileFlows(flows(put, HOLDER)));                                      // twin: the raw value through the same field
    }

    private static String cleaner(String extra) {
        return ".class public Lt/C;\n.super Ljava/lang/Object;\n.method public static c(Ljava/lang/String;)Ljava/lang/String;\n    .locals 4\n"
            + extra
            + "    const-string v1, \"[^a-zA-Z0-9._]+\"\n    const-string v2, \"_\"\n"
            + "    invoke-virtual {p0, v1, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
            + "    return-object v0\n.end method\n";
    }

    @Test
    public void throughACleaningCallee() {
        String call = "    invoke-static {v0}, Lt/C;->c(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n";
        assertEquals(0, fileFlows(flows(call + FILE_SINK, cleaner(""))));
        // twin: the callee returns the raw value on one path
        String early = "    if-nez p0, :go\n    return-object p0\n    :go\n";
        assertEquals(1, fileFlows(flows(call + FILE_SINK, cleaner(early))));
    }

    // ---- a clean path joined with a raw one, a field written both ways, a clean value handed to a callee ----
    @Test
    public void twinOnlyOneBranchCleans() {
        String b = "    if-eqz p1, :raw\n" + replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + "    :raw\n";
        assertEquals(1, fileFlows(flows(b + FILE_SINK)));
    }

    @Test
    public void twinAFieldWrittenCleanAndRaw() {
        String put = "    move-object v7, v0\n" + replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + "    sput-object v0, Lt/H;->n:Ljava/lang/String;\n"
            + "    sput-object v7, Lt/H;->n:Ljava/lang/String;\n    invoke-static {}, Lt/H;->open()V\n";
        assertEquals(1, fileFlows(flows(put, HOLDER)));
    }

    private static final String OPENER = ".class public Lt/O;\n.super Ljava/lang/Object;\n.method public static o(Ljava/lang/String;)V\n    .locals 4\n    move-object v0, p0\n"
        + FILE_SINK.replace("v6", "v3").replace("v4", "v1").replace("v5", "v2") + END;

    @Test
    public void aCleanValueHandedToACalleeThatOpensIt() {
        String call = "    invoke-static {v0}, Lt/O;->o(Ljava/lang/String;)V\n";
        assertEquals(0, fileFlows(flows(replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + call, OPENER)));
        assertEquals(1, fileFlows(flows(call, OPENER)));
    }

    @Test
    public void twinKotlinReplacesThatKeepTheSlash() {
        for (String fn : new String[]{"replaceFirst$default", "replaceAfter$default", "replaceBefore$default", "replaceIndentByMargin$default"}) {
            String k = "    const-string v2, \"/\"\n    const-string v3, \"\"\n    const/4 v4, 0x0\n    const/4 v5, 0x4\n    const/4 v6, 0x0\n"
                + "    invoke-static {v0, v2, v3, v4, v5, v6}, Lkotlin/text/StringsKt;->" + fn + "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Ljava/lang/String;\n"
                + "    move-result-object v0\n";
            assertEquals(fn, 1, fileFlows(flows(k + FILE_SINK)));
        }
    }

    // ---- the pattern analysis ----
    @Test
    public void patternAnalysis() {
        assertTrue(TaintIr.stripsSlash("[^a-zA-Z0-9\\._]+", "_"));
        assertTrue(TaintIr.stripsSlash("[^ -.]", ""));                    // range 0x20-0x2E stops before '/'
        assertTrue(TaintIr.stripsSlash("[/\\\\]+", "_"));                 // a class that matches '/'
        assertTrue(TaintIr.stripsSlash("/", "-"));
        assertFalse(TaintIr.stripsSlash("[^ -0]", ""));                   // 0x20-0x30 contains '/'
        assertFalse(TaintIr.stripsSlash("[^\\W]", ""));                   // \W contains '/'
        assertFalse(TaintIr.stripsSlash("\\s+", "_"));
        assertFalse(TaintIr.stripsSlash("[^a-z]+", "/"));
        assertFalse(TaintIr.stripsSlash("[^a-z]+", "$0"));
        assertFalse(TaintIr.stripsSlash(null, "_"));
        assertFalse(TaintIr.stripsSlash("[^a-z", "_"));                   // does not compile
        assertFalse(TaintIr.stripsSlash("(/)", "_"));                     // a group: not a shape the rule reads
        assertFalse(TaintIr.stripsSlash("/(?!q)", ""));                   // passes every probe ("/q" is not one) but is no shape the rule reads
        assertFalse(TaintIr.stripsSlash("[a-z]+", "_"));                  // a positive class without '/'
        assertTrue(TaintIr.stripsSlash("\\/+", "_"));
        assertEquals("[^a-z\\.]", TaintIr.unsmali("\"[^a-z\\\\.]\""));
        assertEquals(null, TaintIr.unsmali("v1"));
    }

    @Test
    public void mutantSwitchOffBringsTheChakaFlowBack() {
        boolean was = TaintIr.PATH_STRIP_SANITIZER;
        TaintIr.PATH_STRIP_SANITIZER = false;
        try {
            assertEquals(1, fileFlows(flows(replaceAll("[^a-zA-Z0-9\\\\._]+", "_") + FILE_SINK)));
        } finally {
            TaintIr.PATH_STRIP_SANITIZER = was;
        }
    }
}
