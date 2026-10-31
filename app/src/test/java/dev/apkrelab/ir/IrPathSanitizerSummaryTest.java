package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

/**
 * Maturity phase 3 (Paperless ClipboardFileProvider): a callee that canonicalises the path and throws unless it still starts with the root is a sanitizer for the
 * value it returns, but ONLY when that check dominates every reference return. A check that some return skips keeps the taint, as a weak (LOW) flow.
 */
public class IrPathSanitizerSummaryTest {

    private static final String PROVIDER =
        ".class public Lt/P;\n.super Landroid/content/ContentProvider;\n"
        + ".method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;\n    .locals 3\n"
        + "CALL"
        + "    move-result-object v0\n"
        + "    const/high16 v1, 0x10000000\n"
        + "    invoke-static {v0, v1}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;\n"
        + "    move-result-object v0\n    return-object v0\n.end method\n";

    private static final String HEAD =
        "    .locals 6\n"
        + "    invoke-virtual {p1}, Landroid/net/Uri;->getPath()Ljava/lang/String;\n    move-result-object v0\n"
        + "    const-string v2, \"/data/root\"\n";
    private static final String CHECKED =
        "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V\n"
        + "    invoke-virtual {v1}, Ljava/io/File;->getCanonicalFile()Ljava/io/File;\n    move-result-object v1\n"
        + "    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;\n    move-result-object v3\n"
        + "    invoke-virtual {v3, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n    move-result v3\n"
        + "    if-eqz v3, :bad\n    return-object v1\n"
        + "    :bad\n    new-instance v4, Ljava/lang/SecurityException;\n    invoke-direct {v4}, Ljava/lang/SecurityException;-><init>()V\n    throw v4\n";
    // a second return, before the check, that hands the raw path back
    private static final String EARLY_RETURN =
        "    const-string v5, \"raw\"\n    invoke-virtual {v0, v5}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z\n    move-result v5\n"
        + "    if-eqz v5, :checked\n    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    return-object v1\n"
        + "    :checked\n";

    private static String helper(String cls, String body, String iface) {
        return ".class public " + cls + ";\n.super Ljava/lang/Object;\n" + (iface == null ? "" : ".implements " + iface + ";\n")
            + ".method public a(Landroid/net/Uri;)Ljava/io/File;\n" + HEAD + body + ".end method\n";
    }

    private static List<TaintIr.Flow> run(String providerCall, String... classes) {
        List<ClassIr> all = new ArrayList<>();
        all.add(SmaliParser.parse(PROVIDER.replace("CALL", providerCall)));
        for (String c : classes) all.add(SmaliParser.parse(c));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/P;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows;
    }

    private static final String DIRECT_CALL =
        "    new-instance v0, Lt/H;\n    invoke-direct {v0}, Lt/H;-><init>()V\n"
        + "    invoke-virtual {v0, p1}, Lt/H;->a(Landroid/net/Uri;)Ljava/io/File;\n";
    private static final String INTERFACE_CALL =
        "    new-instance v0, Lt/H;\n    invoke-direct {v0}, Lt/H;-><init>()V\n"
        + "    invoke-interface {v0, p1}, Lt/Strategy;->a(Landroid/net/Uri;)Ljava/io/File;\n";
    private static final String CTOR = ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n";
    private static final String IFACE = ".class public interface abstract Lt/Strategy;\n.super Ljava/lang/Object;\n"
        + ".method public abstract a(Landroid/net/Uri;)Ljava/io/File;\n.end method\n";

    private static String h(String body, String iface) {
        return helper("Lt/H", body, iface).replace(".method public a(", CTOR + ".method public a(");
    }

    @Test
    public void aCheckOnEveryReturnSanitizesTheCalleesResult() {
        assertEquals(0, run(DIRECT_CALL, h(CHECKED, null)).size());
    }

    @Test
    public void theSameThroughAnInterfaceCall() {                              // the Paperless shape: the path strategy is an interface
        assertEquals(0, run(INTERFACE_CALL, h(CHECKED, "Lt/Strategy"), IFACE).size());
    }

    @Test
    public void twinAReturnThatSkipsTheCheckKeepsTheFlowAsLowConfidence() {
        List<TaintIr.Flow> f = run(DIRECT_CALL, h(EARLY_RETURN + CHECKED, null));
        assertEquals(1, f.size());
        assertTrue("a partial check must make the flow weak (LOW)", f.get(0).weak);
        assertTrue(f.get(0).via, f.get(0).via != null && f.get(0).via.startsWith(TaintIr.SANITIZER_PARTIAL_MARK));
    }

    @Test
    public void twinCanonicalisationWithoutAStartsWithCheckIsNoSanitizer() {
        String noCheck = CHECKED.replace("Ljava/lang/String;->startsWith(", "Ljava/lang/String;->contains(");
        List<TaintIr.Flow> f = run(DIRECT_CALL, h(noCheck, null));
        assertEquals(1, f.size());
        assertFalse(f.get(0).weak);
    }

    @Test
    public void twinACheckWhoseResultNoBranchTestsIsNoSanitizer() {
        String untested = CHECKED.replace("    if-eqz v3, :bad\n    return-object v1\n", "    return-object v1\n");
        List<TaintIr.Flow> f = run(DIRECT_CALL, h(untested, null));
        assertEquals(1, f.size());
    }

    @Test
    public void twinAFailingBranchThatReturnsTheRawFileIsPartial() {      // the check is there and dominates the return, but the failing side returns too
        String bad = CHECKED.replace("    :bad\n    new-instance v4, Ljava/lang/SecurityException;\n    invoke-direct {v4}, Ljava/lang/SecurityException;-><init>()V\n    throw v4\n",
            "    :bad\n    new-instance v4, Ljava/io/File;\n    invoke-direct {v4, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    return-object v4\n");
        assertEquals(2, kind(HEAD + bad));
        List<TaintIr.Flow> f = run(DIRECT_CALL, h(bad, null));
        assertEquals(1, f.size());
        assertTrue(f.get(0).weak);
    }

    @Test
    public void kotlinShapeIfNezToThePassingSide() {                       // if (!p.startsWith(root)) throw ... compiled as if-nez :ok
        String k = CHECKED.replace("    if-eqz v3, :bad\n    return-object v1\n    :bad\n", "    if-nez v3, :ok\n")
            .replace("    throw v4\n", "    throw v4\n    :ok\n    return-object v1\n");
        assertEquals(1, kind(HEAD + k));
        // twin: the same test jumping to the throw side when startsWith is TRUE is a broken check
        assertEquals(2, kind(HEAD + k.replace("if-nez v3, :ok", "if-eqz v3, :ok")));
    }

    // ---- the check must really guard the returns ----
    @Test
    public void twinABranchThatSkipsTheCanonicalisationIsPartial() {          // canonical only on one branch, the check reads the raw path otherwise
        String body = "    if-eqz v2, :raw\n    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-virtual {v1}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;\n    move-result-object v0\n    :raw\n"
            + "    invoke-virtual {v0, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n    move-result v3\n"
            + "    if-eqz v3, :bad\n    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    return-object v1\n"
            + "    :bad\n    new-instance v4, Ljava/lang/SecurityException;\n    invoke-direct {v4}, Ljava/lang/SecurityException;-><init>()V\n    throw v4\n";
        assertEquals(2, kind(HEAD + body));
    }

    @Test
    public void twinAPathThatJumpsToTheTestWithoutTheCheckIsPartial() {      // v3 = true, then straight to the IF: the check is bypassed
        String bypass = "    const/4 v3, 0x1\n    if-nez p1, :test\n" + CHECKED.replace("    move-result v3\n    if-eqz v3, :bad\n", "    move-result v3\n    :test\n    if-eqz v3, :bad\n");
        assertEquals(2, kind(HEAD + bypass));
    }

    @Test
    public void twinAPassLabelReachedFromElsewhereIsPartial() {               // an early jump to the passing side, before any check
        String k = CHECKED.replace("    if-eqz v3, :bad\n    return-object v1\n    :bad\n", "    if-nez v3, :ok\n")
            .replace("    throw v4\n", "    throw v4\n    :ok\n    return-object v1\n");
        String early = "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    if-eqz p1, :ok\n";
        assertEquals(1, kind(HEAD + k));
        assertEquals(2, kind(HEAD + early + k));
    }

    @Test
    public void twinAnIfOnAnotherRegisterIsNotTheTest() {
        String other = CHECKED.replace("    if-eqz v3, :bad\n", "    if-eqz v0, :bad\n");
        assertEquals(0, kind(HEAD + other));
        assertEquals(1, run(DIRECT_CALL, h(other, null)).size());
    }

    @Test
    public void twinATwoRegisterCompareIsNotTrusted() {                        // if-ne v3, v6 with v6 = 0 means "startsWith is true": the side is not read from it
        String k = CHECKED.replace("    if-eqz v3, :bad\n    return-object v1\n    :bad\n", "    const/4 v5, 0x0\n    if-ne v3, v5, :ok\n")
            .replace("    throw v4\n", "    throw v4\n    :ok\n    return-object v1\n");
        assertEquals(2, kind(HEAD + k));
    }

    // ---- a source read INSIDE the sanitizing callee (its summary's own returned source) ----
    private static List<TaintIr.Flow> runActivity(String helperBody) {
        String act = ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
            + "    new-instance v1, Lt/G;\n    invoke-direct {v1}, Lt/G;-><init>()V\n"
            + "    invoke-virtual {v1, p0}, Lt/G;->b(Landroid/app/Activity;)Ljava/io/File;\n    move-result-object v0\n"
            + "    invoke-virtual {v0}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
        String g = ".class public Lt/G;\n.super Ljava/lang/Object;\n" + CTOR
            + ".method public b(Landroid/app/Activity;)Ljava/io/File;\n    .locals 6\n"
            + "    invoke-virtual {p1}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"name\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
            + "    const-string v2, \"/data/root\"\n" + helperBody + ".end method\n";
        CallGraph cg = CallGraph.build(Arrays.asList(SmaliParser.parse(act), SmaliParser.parse(g)), Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(cg, false, null).flows;
    }

    @Test
    public void aSourceReadInsideTheSanitizerIsCleanAndThePartialOneIsWeak() {
        assertEquals(0, runActivity(CHECKED).size());
        List<TaintIr.Flow> partial = runActivity(EARLY_RETURN + CHECKED);
        assertEquals(1, partial.size());
        assertTrue(partial.get(0).weak);
        boolean was = TaintIr.PATH_SANITIZER_SUMMARY;
        TaintIr.PATH_SANITIZER_SUMMARY = false;
        try { assertEquals(1, runActivity(CHECKED).size()); } finally { TaintIr.PATH_SANITIZER_SUMMARY = was; }
    }

    // ---- an R8-renamed helper (Paperless: kotlin.io.FilesKt.startsWith(File, File) became LH5/j;->p) is recognised by its shape, not its name ----
    private static final String R8 =
        "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V\n"
        + "    invoke-virtual {v1}, Ljava/io/File;->getCanonicalFile()Ljava/io/File;\n    move-result-object v1\n"
        + "    new-instance v5, Ljava/io/File;\n    invoke-direct {v5, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
        + "    invoke-static {v1, v5}, LH5/j;->p(Ljava/io/File;Ljava/io/File;)Z\n    move-result v3\n"
        + "    if-eqz v3, :bad\n    return-object v1\n"
        + "    :bad\n    new-instance v4, Ljava/lang/SecurityException;\n    invoke-direct {v4}, Ljava/lang/SecurityException;-><init>()V\n    throw v4\n";

    @Test
    public void aRenamedFileFileHelperOnTheCanonicalValueIsTheCheck() {
        assertEquals(1, kind(HEAD + R8));
        assertEquals(0, run(DIRECT_CALL, h(R8, null)).size());
    }

    @Test
    public void twinsOfTheRenamedHelperShape() {
        // the helper is applied to another value, not the canonical one
        assertEquals(0, kind(HEAD + R8.replace("invoke-static {v1, v5}, LH5/j;->p", "invoke-static {v5, v5}, LH5/j;->p")));
        // mixed types (File, String): not a containment shape
        assertEquals(0, kind(HEAD + R8.replace("invoke-static {v1, v5}, LH5/j;->p(Ljava/io/File;Ljava/io/File;)Z", "invoke-static {v1, v2}, LH5/j;->p(Ljava/io/File;Ljava/lang/String;)Z")));
        // a virtual app method of the same shape is not trusted (only static helpers stand for renamed library functions)
        assertEquals(0, kind(HEAD + R8.replace("invoke-static {v1, v5}, LH5/j;->p", "invoke-virtual {v1, v5}, LH5/j;->p")));
        // a framework boolean that is not confinement (String.endsWith) is not the check, whatever its shape
        assertEquals(0, kind(HEAD + CHECKED.replace("Ljava/lang/String;->startsWith(", "Ljava/lang/String;->endsWith(")));
    }

    @Test
    public void structuralKinds() {
        assertEquals(1, kind(HEAD + CHECKED));
        assertEquals(2, kind(HEAD + EARLY_RETURN + CHECKED));
        assertEquals(0, kind(HEAD + "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    return-object v1\n"));
    }

    private static int kind(String body) {
        ClassIr c = SmaliParser.parse(".class public Lt/K;\n.super Ljava/lang/Object;\n.method public a(Landroid/net/Uri;)Ljava/io/File;\n" + body + ".end method\n");
        MethodIr m = c.methods.get(0);
        return TaintIr.pathSanitizerKind(m, Cfg.build(m));
    }

    @Test
    public void mutantSummaryOffBringsTheFlowBack() {
        boolean was = TaintIr.PATH_SANITIZER_SUMMARY;
        TaintIr.PATH_SANITIZER_SUMMARY = false;
        try {
            assertEquals(1, run(DIRECT_CALL, h(CHECKED, null)).size());
            List<TaintIr.Flow> f = run(DIRECT_CALL, h(EARLY_RETURN + CHECKED, null));
            assertFalse("without the summary the partial twin is no longer LOW", f.get(0).weak);
        } finally {
            TaintIr.PATH_SANITIZER_SUMMARY = was;
        }
    }

    @SuppressWarnings("unused")
    private static final List<String> NONE = Collections.emptyList();
}
