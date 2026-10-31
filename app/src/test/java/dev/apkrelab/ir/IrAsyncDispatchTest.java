package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.0.0 pillar 1.1: taint across async dispatch (Executor.execute / ExecutorService.submit / Handler.post / Activity.runOnUiThread) to the CONCRETE
 * Runnable's run(), and a Kotlin FunctionN.invoke whose receiver is one known class in the method. The common shape: the source is captured in a field by
 * the Runnable's constructor and read back in run().
 */
public class IrAsyncDispatchTest {

    private static final String CTOR_R = ".method public constructor <init>(Ljava/lang/String;)V\n    .locals 0\n"
        + "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    iput-object p1, p0, Lt/R;->f:Ljava/lang/String;\n    return-void\n.end method\n";
    private static final String RUN_SINK = ".method public run()V\n    .locals 2\n    iget-object v0, p0, Lt/R;->f:Ljava/lang/String;\n"
        + "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
        + "    invoke-virtual {v1}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
    static final String RUNNABLE = ".class public Lt/R;\n.super Ljava/lang/Object;\n.implements Ljava/lang/Runnable;\n.field private final f:Ljava/lang/String;\n" + CTOR_R + RUN_SINK;
    // a second Runnable that never touches a sink: the dispatch must not mix the two up
    static final String OTHER = ".class public Lt/Q;\n.super Ljava/lang/Object;\n.implements Ljava/lang/Runnable;\n"
        + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
        + ".method public run()V\n    .locals 0\n    return-void\n.end method\n";

    static String activity(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.field private ex:Ljava/util/concurrent/Executor;\n.field private h:Landroid/os/Handler;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"path\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
            + body + "    return-void\n.end method\n";
    }

    static final String NEW_R = "    new-instance v2, Lt/R;\n    invoke-direct {v2, v0}, Lt/R;-><init>(Ljava/lang/String;)V\n";
    static final String NEW_R_CONST = "    const-string v4, \"/data/x\"\n    new-instance v2, Lt/R;\n    invoke-direct {v2, v4}, Lt/R;-><init>(Ljava/lang/String;)V\n";

    static int flows(String... classes) {
        List<ClassIr> all = new ArrayList<>();
        for (String c : classes) all.add(SmaliParser.parse(c));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows.size();
    }

    static final String EXECUTE = "    iget-object v3, p0, Lt/A;->ex:Ljava/util/concurrent/Executor;\n    invoke-interface {v3, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V\n";
    static final String SUBMIT = "    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;\n    move-result-object v3\n"
        + "    invoke-interface {v3, v2}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;\n";
    static final String POST = "    iget-object v3, p0, Lt/A;->h:Landroid/os/Handler;\n    invoke-virtual {v3, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z\n";
    static final String UI = "    invoke-virtual {p0, v2}, Lt/A;->runOnUiThread(Ljava/lang/Runnable;)V\n";

    @Test public void executorExecuteReachesTheConcreteRun() { assertEquals(1, flows(activity(NEW_R + EXECUTE), RUNNABLE, OTHER)); }
    @Test public void executorServiceSubmit() { assertEquals(1, flows(activity(NEW_R + SUBMIT), RUNNABLE, OTHER)); }
    @Test public void handlerPost() { assertEquals(1, flows(activity(NEW_R + POST), RUNNABLE, OTHER)); }
    @Test public void runOnUiThread() { assertEquals(1, flows(activity(NEW_R + UI), RUNNABLE, OTHER)); }

    // twins: the same dispatch with a constant captured stays quiet; a Runnable of unknown class (a parameter) is not guessed
    @Test public void directRunCallCarriesTheCapturedField() { assertEquals(1, flows(activity(NEW_R + "    invoke-virtual {v2}, Lt/R;->run()V\n"), RUNNABLE, OTHER)); }
    @Test public void twinAConstantCapturedIsQuiet() { assertEquals(0, flows(activity(NEW_R_CONST + EXECUTE), RUNNABLE, OTHER)); }

    // ---- what each part adds ----
    static TaintIr.Result result(String... classes) {
        List<ClassIr> all = new ArrayList<>();
        for (String c : classes) all.add(SmaliParser.parse(c));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null);
    }

    /** The Runnable is created in onCreate and kept in a field; onResume dispatches it: no new-instance in the dispatching method. */
    static final String FIELD_HELD = ".class public Lt/A;\n.super Landroid/app/Activity;\n.field private r:Lt/R;\n.field private ex:Ljava/util/concurrent/Executor;\n"
        + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n"
        + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
        + "    const-string v1, \"path\"\n    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
        + NEW_R + "    iput-object v2, p0, Lt/A;->r:Lt/R;\n    return-void\n.end method\n"
        + ".method public onResume()V\n    .locals 2\n    iget-object v0, p0, Lt/A;->r:Lt/R;\n    iget-object v1, p0, Lt/A;->ex:Ljava/util/concurrent/Executor;\n"
        + "    invoke-interface {v1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V\n    return-void\n.end method\n";

    @Test public void aFieldHeldRunnableIsReachedThroughTheAsyncEdge() {
        TaintIr.Result r = result(FIELD_HELD, RUNNABLE, OTHER);
        assertEquals(1, r.flows.size());
        assertTrue("run() must be reachable from the activity through the dispatch site", r.flows.get(0).reachable);
    }

    @Test public void mutantNoAsyncEdgeLeavesTheFlowUnreachable() {
        boolean was = CallGraph.ASYNC_EDGES;
        CallGraph.ASYNC_EDGES = false;
        try {
            TaintIr.Result r = result(FIELD_HELD, RUNNABLE, OTHER);
            assertEquals(1, r.flows.size());
            assertFalse(r.flows.get(0).reachable);
        } finally { CallGraph.ASYNC_EDGES = was; }
    }

    /** A Runnable that itself carries real taint: read from the Intent (getParcelableExtra) and cast to [cast]. */
    static String taintedRunnable(String cast) {
        return "    const-string v1, \"r\"\n    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v3\n"
            + "    invoke-virtual {v3, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n    move-result-object v2\n"
            + "    check-cast v2, " + cast + "\n";
    }
    static boolean executorDrop(String body) {
        return result(activity(body), RUNNABLE, OTHER).stats.owners.containsKey("java/util/concurrent/Executor");
    }

    @Test public void aFollowedDispatchIsNotADrop() {
        assertFalse(executorDrop(taintedRunnable("Lt/R;") + EXECUTE));
        boolean was = TaintIr.ASYNC_DISPATCH;
        TaintIr.ASYNC_DISPATCH = false;
        try { assertTrue("the same site without the dispatch rule is a drop", executorDrop(taintedRunnable("Lt/R;") + EXECUTE)); }
        finally { TaintIr.ASYNC_DISPATCH = was; }
    }

    @Test public void twinARunnableOfUnknownClassStaysADrop() {             // cast to the interface only: no class is guessed
        assertTrue(executorDrop(taintedRunnable("Ljava/lang/Runnable;") + EXECUTE));
    }

    @Test public void twinAPhiOfTwoClassesIsNotResolved() {
        String phi = "    if-eqz v0, :other\n" + taintedRunnable("Lt/R;") + "    goto :go\n    :other\n    new-instance v2, Lt/Q;\n    invoke-direct {v2}, Lt/Q;-><init>()V\n    :go\n" + EXECUTE;
        assertTrue(executorDrop(phi));
        // and the same phi over ONE class resolves
        String one = "    if-eqz v0, :other\n" + taintedRunnable("Lt/R;") + "    goto :go\n    :other\n" + taintedRunnable("Lt/R;") + "    :go\n" + EXECUTE;
        assertFalse(executorDrop(one));
    }

    // ---- Kotlin FunctionN.invoke devirtualisation ----
    static final String SRC_HOLDER = ".class public Lt/S;\n.super Ljava/lang/Object;\n.field public static v:Ljava/lang/String;\n";
    static String lambda(String cls, boolean returnsSource) {
        return ".class public final " + cls + ";\n.super Lkotlin/jvm/internal/Lambda;\n.implements Lkotlin/jvm/functions/Function0;\n"
            + ".method public constructor <init>()V\n    .locals 1\n    const/4 v0, 0x0\n    invoke-direct {p0, v0}, Lkotlin/jvm/internal/Lambda;-><init>(I)V\n    return-void\n.end method\n"
            + ".method public final invoke()Ljava/lang/Object;\n    .locals 1\n"
            + (returnsSource ? "    sget-object v0, Lt/S;->v:Ljava/lang/String;\n" : "    const-string v0, \"/data/fixed\"\n") + "    return-object v0\n.end method\n";
    }
    static String lambdaUser(String cls) {
        return activity("    sput-object v0, Lt/S;->v:Ljava/lang/String;\n    new-instance v3, Lt/L1;\n    invoke-direct {v3}, Lt/L1;-><init>()V\n"
            + "    new-instance v2, " + cls + ";\n    invoke-direct {v2}, " + cls + ";-><init>()V\n"
            + "    invoke-interface {v2}, Lkotlin/jvm/functions/Function0;->invoke()Ljava/lang/Object;\n    move-result-object v4\n"
            + "    check-cast v4, Ljava/lang/String;\n    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v4}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-virtual {v1}, Ljava/io/File;->delete()Z\n");
    }

    @Test public void aKnownLambdaClassIsTheOnlyTarget() {
        assertEquals(0, flows(lambdaUser("Lt/L2"), SRC_HOLDER, lambda("Lt/L1", true), lambda("Lt/L2", false)));   // L2 returns a constant
        assertEquals(1, flows(lambdaUser("Lt/L1"), SRC_HOLDER, lambda("Lt/L1", true), lambda("Lt/L2", false)));   // twin: L1 returns the source
    }

    @Test public void mutantNoDevirtMixesTheLambdas() {
        boolean was = TaintIr.LAMBDA_DEVIRT;
        TaintIr.LAMBDA_DEVIRT = false;
        try { assertEquals(1, flows(lambdaUser("Lt/L2"), SRC_HOLDER, lambda("Lt/L1", true), lambda("Lt/L2", false))); }
        finally { TaintIr.LAMBDA_DEVIRT = was; }
    }

    @Test public void mutantNoCtorCaptureLosesTheCapturedSource() {
        boolean was = TaintIr.CTOR_CAPTURE;
        TaintIr.CTOR_CAPTURE = false;
        try { assertEquals(0, flows(activity(NEW_R + "    invoke-virtual {v2}, Lt/R;->run()V\n"), RUNNABLE, OTHER)); }
        finally { TaintIr.CTOR_CAPTURE = was; }
    }

    // ---- the async edge itself, per API ----
    static int asyncEdges(String... classes) {
        List<ClassIr> all = new ArrayList<>();
        for (String c : classes) all.add(SmaliParser.parse(c));
        return CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null).asyncEdges;
    }

    @Test public void eachDispatchApiGetsAnAsyncEdge() {
        for (String api : new String[]{EXECUTE, SUBMIT, POST, UI}) assertEquals(api, 1, asyncEdges(activity(NEW_R + api), RUNNABLE, OTHER));
        String delayed = "    iget-object v3, p0, Lt/A;->h:Landroid/os/Handler;\n    const-wide/16 v4, 0x64\n    invoke-virtual {v3, v2, v4, v5}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z\n";
        assertEquals(1, asyncEdges(activity(NEW_R + delayed), RUNNABLE, OTHER));
    }

    @Test public void twinAnAppOverrideOfExecuteIsAnOrdinaryCall() {
        String myExec = ".class public Lt/E;\n.super Ljava/lang/Object;\n.implements Ljava/util/concurrent/Executor;\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public execute(Ljava/lang/Runnable;)V\n    .locals 0\n    invoke-interface {p1}, Ljava/lang/Runnable;->run()V\n    return-void\n.end method\n";
        String use = NEW_R + "    new-instance v3, Lt/E;\n    invoke-direct {v3}, Lt/E;-><init>()V\n    invoke-virtual {v3, v2}, Lt/E;->execute(Ljava/lang/Runnable;)V\n";
        assertEquals(0, asyncEdges(activity(use), RUNNABLE, OTHER, myExec));
    }

    @Test public void twinADefinitionBeyondTheWindowIsNotGuessed() {   // more than 12 instructions between the definition and the dispatch: no graph edge, no follow
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < 13; i++) pad.append("    nop\n");
        assertTrue(executorDrop(taintedRunnable("Lt/R;") + pad + EXECUTE));
    }

    @Test public void aMovedAndAFieldHeldTaintedRunnableAreFollowed() {
        assertFalse(executorDrop(taintedRunnable("Lt/R;") + "    move-object v4, v2\n    move-object v2, v4\n" + EXECUTE));
        String viaField = taintedRunnable("Lt/R;") + "    iput-object v2, p0, Lt/A;->held:Lt/R;\n    iget-object v2, p0, Lt/A;->held:Lt/R;\n" + EXECUTE;
        assertFalse(executorDrop(viaField.replace("", "")));
    }

    // ---- scope of the constructor capture ----
    static final String PLAIN = ".class public Lt/P;\n.super Ljava/lang/Object;\n.field private final f:Ljava/lang/String;\n"
        + CTOR_R.replace("Lt/R;", "Lt/P;") + RUN_SINK.replace("Lt/R;", "Lt/P;").replace(".method public run()V", ".method public go()V");

    @Test public void twinAnOrdinaryClassIsNotCaptured() {
        assertEquals(0, flows(activity(NEW_R.replace("Lt/R;", "Lt/P;") + "    invoke-virtual {v2}, Lt/P;->go()V\n"), PLAIN, RUNNABLE, OTHER));
    }

    @Test public void twinAConstructorWritingIntoAnotherObjectIsNotCaptured() {
        String r2 = RUNNABLE.replace("    iput-object p1, p0, Lt/R;->f:Ljava/lang/String;\n",
            "    new-instance v0, Lt/X;\n    invoke-direct {v0}, Lt/X;-><init>()V\n    iput-object p1, v0, Lt/X;->g:Ljava/lang/String;\n").replace(".locals 0", ".locals 1");
        String x = ".class public Lt/X;\n.super Ljava/lang/Object;\n.field public g:Ljava/lang/String;\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public use()V\n    .locals 2\n    iget-object v0, p0, Lt/X;->g:Ljava/lang/String;\n    new-instance v1, Ljava/io/File;\n"
            + "    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v1}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
        assertEquals(0, flows(activity(NEW_R), r2, x, OTHER));
    }

    // ---- scope of the devirtualisation ----
    @Test public void twinAnAppInterfaceIsNotDevirtualised() {         // only kotlin FunctionN: other interfaces keep their RTA targets
        String iface = ".class public interface abstract Lt/Sup;\n.super Ljava/lang/Object;\n.method public abstract invoke()Ljava/lang/Object;\n.end method\n";
        String l1 = lambda("Lt/L1", true).replace("Lkotlin/jvm/functions/Function0;", "Lt/Sup;");
        String l2 = lambda("Lt/L2", false).replace("Lkotlin/jvm/functions/Function0;", "Lt/Sup;");
        String user = lambdaUser("Lt/L2").replace("Lkotlin/jvm/functions/Function0;->invoke", "Lt/Sup;->invoke");
        assertEquals(1, flows(user, SRC_HOLDER, iface, l1, l2));
    }

    @Test public void runOnATaintedRunnableReachesASinkOnThis() {          // run() hands "this" (the tainted object) to a sink: slot 0 of its summary
        String r = ".class public Lt/R;\n.super Ljava/lang/Object;\n.implements Ljava/lang/Runnable;\n.implements Landroid/os/Parcelable;\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public run()V\n    .locals 2\n    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;\n    move-result-object v0\n"
            + "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v1}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
        assertEquals(1, flows(activity(taintedRunnable("Lt/R;") + EXECUTE), r, OTHER));
    }

    @Test public void aKotlinLambdaCapturesItsArgument() {                  // a FunctionN class, not a Runnable: its constructor capture counts too
        String lam = ".class public final Lt/K;\n.super Lkotlin/jvm/internal/Lambda;\n.implements Lkotlin/jvm/functions/Function0;\n.field final f:Ljava/lang/String;\n"
            + ".method public constructor <init>(Ljava/lang/String;)V\n    .locals 1\n    iput-object p1, p0, Lt/K;->f:Ljava/lang/String;\n    const/4 v0, 0x0\n"
            + "    invoke-direct {p0, v0}, Lkotlin/jvm/internal/Lambda;-><init>(I)V\n    return-void\n.end method\n"
            + ".method public final invoke()Ljava/lang/Object;\n    .locals 2\n    iget-object v0, p0, Lt/K;->f:Ljava/lang/String;\n    new-instance v1, Ljava/io/File;\n"
            + "    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v1}, Ljava/io/File;->delete()Z\n    const/4 v0, 0x0\n    return-object v0\n.end method\n";
        String use = "    new-instance v2, Lt/K;\n    invoke-direct {v2, v0}, Lt/K;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-interface {v2}, Lkotlin/jvm/functions/Function0;->invoke()Ljava/lang/Object;\n";
        assertEquals(1, flows(activity(use), lam, RUNNABLE, OTHER));
    }

    @Test public void twinACastToANonLeafClassIsNotResolved() {           // Base has a run() body and a subclass: the cast does not name the runtime class
        String base = ".class public abstract Lt/Base;\n.super Ljava/lang/Object;\n.implements Ljava/lang/Runnable;\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
            + ".method public run()V\n    .locals 0\n    return-void\n.end method\n";
        String sub = ".class public Lt/Sub;\n.super Lt/Base;\n"
            + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Lt/Base;-><init>()V\n    return-void\n.end method\n";
        assertEquals(1, asyncEdges(activity(taintedRunnable("Lt/Base;") + EXECUTE), base, sub, RUNNABLE));   // the graph has a candidate ...
        assertTrue(result(activity(taintedRunnable("Lt/Base;") + EXECUTE), base, sub, RUNNABLE).stats.owners.containsKey("java/util/concurrent/Executor"));  // ... SSA does not follow it
    }

    @Test public void twinAnObjectTypedFieldIsNotCaptured() {               // R8-merged / erased fields conflate unrelated values (K-9: this$0:Ljava/lang/Object;)
        String r = RUNNABLE.replace("f:Ljava/lang/String;", "f:Ljava/lang/Object;");
        assertEquals(0, flows(activity(NEW_R + "    invoke-virtual {v2}, Lt/R;->run()V\n"), r, OTHER));
    }
}
