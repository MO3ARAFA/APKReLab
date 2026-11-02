package dev.apkrelab.ir;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.Test;

/** 3.0.0: an open redirector reads an INTENT from the extras; reading another Parcelable and starting an unrelated activity does not switch the private-component rule off. */
public class IrStrictRedirectorTest {
    static String exported(String castType) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n" + IrBridgeSupport.CTOR
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"x\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n    move-result-object v2\n"
            + "    check-cast v2, " + castType + "\n    new-instance v3, Landroid/content/Intent;\n    invoke-direct {v3}, Landroid/content/Intent;-><init>()V\n"
            + "    invoke-virtual {p0, v3}, Lt/A;->startActivity(Landroid/content/Intent;)V\n    return-void\n.end method\n";
    }
    static final String PRIVATE = ".class public Lt/B;\n.super Landroid/app/Activity;\n" + IrBridgeSupport.CTOR;
    static boolean bIsPrivate(String castType) {
        CallGraph g = CallGraph.build(new ArrayList<>(Arrays.asList(SmaliParser.parse(exported(castType)), SmaliParser.parse(PRIVATE))), Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return g.isPrivateComponent("Lt/B;");
    }

    @Test public void readingAnIntentFromTheExtrasAndLaunchingIsARedirector() { assertFalse(bIsPrivate("Landroid/content/Intent;")); }
    @Test public void anotherParcelableIsNotARedirector() { assertTrue(bIsPrivate("Lt/User;")); }                                  // twin
    @Test public void theMutationTreatsAnyParcelableAsARedirector() {
        boolean was = CallGraph.STRICT_REDIRECTOR;
        CallGraph.STRICT_REDIRECTOR = false;
        try { assertFalse(bIsPrivate("Lt/User;")); } finally { CallGraph.STRICT_REDIRECTOR = was; }
    }
}
