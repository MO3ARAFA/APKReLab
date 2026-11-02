package dev.apkrelab.ir;

import static dev.apkrelab.ir.IrBridgeSupport.*;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** 2.2 session 3b, bridge (iv): ALREADY EXISTS (the 'suspend' call edge since 2.1.0 and the constructor-captured-field transport of 2.0.0 CTOR_CAPTURE, which covers a lambda that implements kotlin.jvm.functions.Function). Pinned here with a positive test and a twin. */
public class IrSuspendLambdaTransportTest {

    static final String LAMBDA = ".class public final Lt/T;\n.super Lkotlin/coroutines/jvm/internal/SuspendLambda;\n.implements Lkotlin/jvm/functions/Function2;\n.field public final u:Ljava/lang/String;\n"
        + ".method public constructor <init>(Ljava/lang/String;)V\n    .locals 0\n    iput-object p1, p0, Lt/T;->u:Ljava/lang/String;\n    return-void\n.end method\n"
        + ".method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;\n    .locals 3\n    iget-object v0, p0, Lt/T;->u:Ljava/lang/String;\n" + SINK + "    const/4 v1, 0x0\n    return-object v1\n.end method\n";

    @Test public void aSuspendLambdaCarriesItsCapturedFieldIntoInvokeSuspend() {
        TaintIr.Flow f = flowIn("Lt/T;", activity(SRC + "    new-instance v3, Lt/T;\n    invoke-direct {v3, v0}, Lt/T;-><init>(Ljava/lang/String;)V\n"), LAMBDA);
        assertTrue(f != null && f.reachable);
        assertTrue(f.source, f.source.startsWith("Intent."));
    }
    @Test public void aSuspendLambdaNobodyConstructsCarriesNothing() {
        TaintIr.Flow f = flowIn("Lt/T;", activity(SRC), LAMBDA);
        assertTrue(f == null);
    }
}
