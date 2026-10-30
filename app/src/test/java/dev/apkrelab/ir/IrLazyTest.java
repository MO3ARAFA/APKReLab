package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.76.0: Kotlin `val path by lazy { intent.getStringExtra("FILE_PATH") }` (Password Store BasePGPActivity, lost before). */
public class IrLazyTest {

    private static String lambda(String body) {
        return ".class final Lt/A$name$2;\n.super Lkotlin/jvm/internal/Lambda;\n.implements Lkotlin/jvm/functions/Function0;\n\n"
                + ".field final synthetic this$0:Lt/A;\n\n"
                + ".method constructor <init>(Lt/A;)V\n    .locals 0\n    iput-object p1, p0, Lt/A$name$2;->this$0:Lt/A;\n    return-void\n.end method\n\n"
                + ".method public final invoke()Ljava/lang/Object;\n    .locals 2\n" + body + "    return-object v0\n.end method\n";
    }

    private static final String ACTIVITY = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.field private final name$delegate:Lkotlin/Lazy;\n\n"
            + ".method public constructor <init>()V\n    .locals 1\n    invoke-direct {p0}, Landroid/app/Activity;-><init>()V\n"
            + "    new-instance v0, Lt/A$name$2;\n    invoke-direct {v0, p0}, Lt/A$name$2;-><init>(Lt/A;)V\n"
            + "    invoke-static {v0}, Lkotlin/LazyKt;->lazy(Lkotlin/jvm/functions/Function0;)Lkotlin/Lazy;\n    move-result-object v0\n"
            + "    iput-object v0, p0, Lt/A;->name$delegate:Lkotlin/Lazy;\n    return-void\n.end method\n\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 2\n"
            + "    iget-object v0, p0, Lt/A;->name$delegate:Lkotlin/Lazy;\n"
            + "    invoke-interface {v0}, Lkotlin/Lazy;->getValue()Ljava/lang/Object;\n    move-result-object v0\n    check-cast v0, Ljava/lang/String;\n"
            + "    new-instance v1, Ljava/io/FileInputStream;\n    invoke-direct {v1, v0}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";

    private static TaintIr.Result run(String lambdaBody) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(ACTIVITY));
        cs.add(SmaliParser.parse(lambda(lambdaBody)));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        assertEquals(1, g.lazyEdges);
        return TaintIr.analyze(g, false, null);
    }

    @Test public void intentExtraReadInALazyLambdaReachesTheSink() {
        TaintIr.Result r = run("    iget-object v0, p0, Lt/A$name$2;->this$0:Lt/A;\n"
                + "    invoke-virtual {v0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                + "    const-string v1, \"FILE_PATH\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n");
        assertTrue(!r.flows.isEmpty());
        TaintIr.Flow f = r.flows.get(0);
        assertEquals(TaintIr.T_FILE, f.sink.title);
        assertTrue(f.source.startsWith("Intent.getStringExtra"));
    }

    @Test public void aConstantInTheLazyLambdaIsQuiet() {
        TaintIr.Result r = run("    const-string v0, \"/data/local/fixed\"\n");
        assertTrue(r.flows.isEmpty());
    }

    @Test public void r8RenamedLazyHelperIsRecognisedByItsShape() {
        String act = ACTIVITY.replace("Lkotlin/LazyKt;->lazy(", "Lkotlin/ExceptionsKt;->unsafeLazy(");
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(act));
        cs.add(SmaliParser.parse(lambda("    iget-object v0, p0, Lt/A$name$2;->this$0:Lt/A;\n"
                + "    invoke-virtual {v0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                + "    const-string v1, \"FILE_PATH\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n")));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        assertEquals(1, g.lazyEdges);
        assertTrue(!TaintIr.analyze(g, false, null).flows.isEmpty());
    }
}
