package dev.apkrelab.ir;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 2.1.0 (real-CVE benchmark C01 Talk, C04 Tasks): the framework runs a Conductor controller, a WorkManager worker and a Kotlin suspend lambda after the app creates / schedules it. */
public class IrFrameworkRunTest {
    static CallGraph graph(String host, String... others) {
        List<ClassIr> all = new ArrayList<>();
        all.add(SmaliParser.parse(host));
        for (String o : others) all.add(SmaliParser.parse(o));
        return CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
    }

    static String host(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n" + body + "    return-void\n.end method\n";
    }

    static String cls(String name, String sup, String method) {
        return ".class public " + name + "\n.super " + sup + "\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, " + sup + "-><init>()V\n    return-void\n.end method\n"
            + ".method public " + method + "\n    .locals 1\n    return-void\n.end method\n";
    }

    @Test public void aConductorControllerCreatedByAReachedMethodIsReached() {
        String h = host("    new-instance v0, Lt/C;\n    invoke-direct {v0}, Lt/C;-><init>()V\n");
        String c = cls("Lt/C;", "Lcom/bluelinelabs/conductor/Controller;", "onViewBound(Landroid/view/View;)V");
        assertTrue(graph(h, c).isReachable("Lt/C;->onViewBound(Landroid/view/View;)V"));
        // twin: a class of another library with the same method name is not hosted
        assertFalse(graph(h, cls("Lt/C;", "Lorg/other/Controller;", "onViewBound(Landroid/view/View;)V")).isReachable("Lt/C;->onViewBound(Landroid/view/View;)V"));
    }

    @Test public void aWorkerNamedInARequestBuilderIsReached() {
        String h = host("    const-class v1, Lt/W;\n    new-instance v0, Landroidx/work/OneTimeWorkRequest$Builder;\n    invoke-direct {v0, v1}, Landroidx/work/OneTimeWorkRequest$Builder;-><init>(Ljava/lang/Class;)V\n");
        String w = cls("Lt/W;", "Landroidx/work/Worker;", "doWork()Landroidx/work/ListenableWorker$Result;");
        assertTrue(graph(h, w).isReachable("Lt/W;->doWork()Landroidx/work/ListenableWorker$Result;"));
        // twin: a worker nobody schedules
        assertFalse(graph(host(""), w).isReachable("Lt/W;->doWork()Landroidx/work/ListenableWorker$Result;"));
    }

    @Test public void aSuspendLambdaCreatedByAReachedMethodIsReached() {
        String h = host("    new-instance v0, Lt/L;\n    invoke-direct {v0}, Lt/L;-><init>()V\n");
        String l = cls("Lt/L;", "Lkotlin/coroutines/jvm/internal/SuspendLambda;", "invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;");
        assertTrue(graph(h, l).isReachable("Lt/L;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;"));
        assertFalse(graph(host(""), l).isReachable("Lt/L;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;"));
    }

    @Test public void mutantsLeaveThemUnreached() {
        String hc = host("    new-instance v0, Lt/C;\n    invoke-direct {v0}, Lt/C;-><init>()V\n");
        String c = cls("Lt/C;", "Lcom/bluelinelabs/conductor/Controller;", "onViewBound(Landroid/view/View;)V");
        String hw = host("    const-class v1, Lt/W;\n    new-instance v0, Landroidx/work/OneTimeWorkRequest$Builder;\n    invoke-direct {v0, v1}, Landroidx/work/OneTimeWorkRequest$Builder;-><init>(Ljava/lang/Class;)V\n");
        String w = cls("Lt/W;", "Landroidx/work/Worker;", "doWork()Landroidx/work/ListenableWorker$Result;");
        String hl = host("    new-instance v0, Lt/L;\n    invoke-direct {v0}, Lt/L;-><init>()V\n");
        String l = cls("Lt/L;", "Lkotlin/coroutines/jvm/internal/SuspendLambda;", "invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;");
        boolean a = CallGraph.CONTROLLER_HOSTING, b = CallGraph.WORK_EDGES, d = CallGraph.SUSPEND_LAMBDAS;
        try {
            CallGraph.CONTROLLER_HOSTING = false; assertFalse(graph(hc, c).isReachable("Lt/C;->onViewBound(Landroid/view/View;)V"));
            CallGraph.WORK_EDGES = false; assertFalse(graph(hw, w).isReachable("Lt/W;->doWork()Landroidx/work/ListenableWorker$Result;"));
            CallGraph.SUSPEND_LAMBDAS = false; assertFalse(graph(hl, l).isReachable("Lt/L;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;"));
        } finally { CallGraph.CONTROLLER_HOSTING = a; CallGraph.WORK_EDGES = b; CallGraph.SUSPEND_LAMBDAS = d; }
    }
}
