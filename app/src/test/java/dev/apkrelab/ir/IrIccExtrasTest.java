package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.0 pillar 1.2: an exported component A builds an explicit Intent to an in-app component B (const-class, or a class-name string), puts a tainted extra under a
 * literal key and launches it; B reads the same literal key from its Intent. B is reachable through A, and B's read carries A's real source (strong), instead of
 * the weak "read in a component that is not exported" source it had before.
 */
public class IrIccExtrasTest {

    static String a(String target, String putKey, boolean launch) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"p\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
            + "    new-instance v3, Landroid/content/Intent;\n" + target
            + "    const-string v1, \"" + putKey + "\"\n    invoke-virtual {v3, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n"
            + (launch ? "    invoke-virtual {p0, v3}, Lt/A;->startActivity(Landroid/content/Intent;)V\n" : "")
            + "    return-void\n.end method\n";
    }
    static final String BY_CLASS = "    const-class v4, Lt/B;\n    invoke-direct {v3, p0, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n";
    static final String BY_NAME = "    invoke-direct {v3}, Landroid/content/Intent;-><init>()V\n    const-string v4, \"t.B\"\n"
        + "    invoke-virtual {v3, p0, v4}, Landroid/content/Intent;->setClassName(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;\n";

    static final String B = ".class public Lt/B;\n.super Landroid/app/Activity;\n"
        + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 3\n"
        + "    invoke-virtual {p0}, Lt/B;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
        + "    const-string v1, \"path\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
        + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
        + "    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";

    static CallGraph graph(String aCls) {
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(aCls), SmaliParser.parse(B)));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);   // only A is exported
        return g;
    }
    static TaintIr.Flow flowInB(String aCls) {
        for (TaintIr.Flow f : TaintIr.analyze(graph(aCls), false, null).flows) if (f.sink.method.startsWith("Lt/B;")) return f;
        return null;
    }

    static boolean forwarded(TaintIr.Flow f) { return f != null && f.via != null && f.via.contains(TaintIr.ICC_EXTRA_PREFIX + "Lt/B;:path"); }

    @Test public void theExtraOfAnExplicitIntentCarriesItsProvenance() {
        TaintIr.Flow f = flowInB(a(BY_CLASS, "path", true));
        assertTrue(f != null && !f.internal);
        assertTrue("B's card names the extra A set: " + (f == null ? null : f.via), forwarded(f));
    }

    @Test public void aClassNameStringIsAnExplicitTargetToo() {
        assertTrue(graph(a(BY_NAME, "path", true)).isReachable("Lt/B;->onCreate(Landroid/os/Bundle;)V"));
        TaintIr.Flow f = flowInB(a(BY_NAME, "path", true));
        assertTrue(f != null && !f.internal && forwarded(f));
    }

    // twins
    @Test public void twinAnotherKeyIsNotLinked() { assertFalse(forwarded(flowInB(a(BY_CLASS, "other", true)))); }

    @Test public void twinAnIntentThatIsNeverLaunchedForwardsNothing() { assertFalse(forwarded(flowInB(a(BY_CLASS, "path", false)))); }

    @Test public void mutantNoForwarding() {
        boolean was = TaintIr.ICC_EXTRAS;
        TaintIr.ICC_EXTRAS = false;
        try { assertFalse(forwarded(flowInB(a(BY_CLASS, "path", true)))); } finally { TaintIr.ICC_EXTRAS = was; }
    }

    @Test public void mutantNoClassNameTargetsLeavesBUnreached() {
        boolean was = CallGraph.ICC_BY_NAME;
        CallGraph.ICC_BY_NAME = false;
        try { assertFalse(graph(a(BY_NAME, "path", true)).isReachable("Lt/B;->onCreate(Landroid/os/Bundle;)V")); } finally { CallGraph.ICC_BY_NAME = was; }
    }

    @Test public void aComponentNameTargetIsLinkedToo() {
        String byCn = "    invoke-direct {v3}, Landroid/content/Intent;-><init>()V\n    new-instance v4, Landroid/content/ComponentName;\n    const-class v1, Lt/B;\n"
            + "    invoke-direct {v4, p0, v1}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
            + "    invoke-virtual {v3, v4}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;\n";
        assertTrue(forwarded(flowInB(a(byCn, "path", true))));
    }

    @Test public void theKeyIsReadNotAssumed() {                          // another literal key on both sides is linked under that key
        String b2 = B.replace("\"path\"", "\"file\"");
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(a(BY_CLASS, "file", true)), SmaliParser.parse(b2)));
        TaintIr.Flow hit = null;
        for (TaintIr.Flow f : TaintIr.analyze(CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null), false, null).flows)
            if (f.sink.method.startsWith("Lt/B;")) hit = f;
        assertTrue(hit != null && hit.via != null && hit.via.contains(TaintIr.ICC_EXTRA_PREFIX + "Lt/B;:file"));
    }
}
