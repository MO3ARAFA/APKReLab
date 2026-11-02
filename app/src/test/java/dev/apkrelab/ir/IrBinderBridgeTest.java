package dev.apkrelab.ir;

import static dev.apkrelab.ir.IrBridgeSupport.*;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** 2.2 session 3b, bridge (iii): a reached method that instantiates a Binder (an AIDL Stub) gets an edge to its onTransact. REACH ONLY: the Parcel reads inside onTransact are already sources; the reply Parcel is not made a sink. */
public class IrBinderBridgeTest {

    static final String BINDER = ".class public Lt/T;\n.super Landroid/os/Binder;\n" + CTOR
        + ".method protected onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z\n    .locals 4\n" + SRC + SINK + "    const/4 v3, 0x1\n    return v3\n.end method\n";
    static String service(boolean makesBinder) {
        return ".class public Lt/A;\n.super Landroid/app/Service;\n.field public b:Landroid/os/IBinder;\n"
            + ".method public constructor <init>()V\n    .locals 1\n    invoke-direct {p0}, Landroid/app/Service;-><init>()V\n"
            + (makesBinder ? "    new-instance v0, Lt/T;\n    invoke-direct {v0}, Lt/T;-><init>()V\n    iput-object v0, p0, Lt/A;->b:Landroid/os/IBinder;\n" : "")
            + "    return-void\n.end method\n"
            + ".method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;\n    .locals 1\n    iget-object v0, p0, Lt/A;->b:Landroid/os/IBinder;\n    return-object v0\n.end method\n";
    }

    @Test public void aBinderTheServiceBuildsHasItsOnTransactReached() {
        TaintIr.Flow f = flowIn("Lt/T;", service(true), BINDER);
        assertTrue(f != null && f.reachable);
    }
    @Test public void aBinderClassNobodyBuildsIsNotReached() {
        TaintIr.Flow f = flowIn("Lt/T;", service(false), BINDER);
        assertTrue(f == null || !f.reachable);
    }

}
