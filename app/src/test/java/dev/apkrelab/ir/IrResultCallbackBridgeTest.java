package dev.apkrelab.ir;

import static dev.apkrelab.ir.IrBridgeSupport.*;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** 2.2 session 3b, bridge (ii): registerForActivityResult(contract, callback). REACH ONLY: the callback's onActivityResult becomes reachable from the registering method. The result is NOT made a source here; the existing 0.70.0 onActivityResult rules decide that. */
public class IrResultCallbackBridgeTest {

    static final String AR_CB = ".class public Lt/T;\n.super Ljava/lang/Object;\n.implements Landroidx/activity/result/ActivityResultCallback;\n" + CTOR
        + ".method public onActivityResult(Ljava/lang/Object;)V\n    .locals 4\n" + SRC + SINK + "    return-void\n.end method\n";
    static final String AR_NEW = "    new-instance v4, Lt/T;\n    invoke-direct {v4}, Lt/T;-><init>()V\n    const/4 v3, 0x0\n";
    static final String AR_REG = "    invoke-virtual {p0, v3, v4}, Lt/A;->registerForActivityResult(Landroidx/activity/result/contract/ActivityResultContract;Landroidx/activity/result/ActivityResultCallback;)Landroidx/activity/result/ActivityResultLauncher;\n";

    @Test public void anActivityResultCallbackThatIsRegisteredIsReached() {
        TaintIr.Flow f = flowOn("Lt/T;", activity(AR_NEW + AR_REG), AR_CB);
        assertTrue(f != null && f.reachable);
    }
    @Test public void anActivityResultCallbackThatIsNeverRegisteredIsNotReached() {
        TaintIr.Flow f = flowIn("Lt/T;", activity(AR_NEW), AR_CB);
        assertTrue(f == null || !f.reachable);
    }

    @Test public void theBridgeIsOffByDefault() {
        TaintIr.Flow f = flowIn("Lt/T;", activity(AR_NEW + AR_REG), AR_CB);
        assertTrue(f == null || !f.reachable);
    }
}
