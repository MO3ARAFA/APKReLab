package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 1.0.0: R8 horizontal class merging told apart by the class id (MergeTags, MergeFacts). A taint written through an object of one class id is not seen by a read through an
 * object of another id; writes of unknown id stay visible to every read.
 *
 * Ground truth: the FX_* classes are the real output of R8 8.13.25 (tools/bin/r8.jar, --release, min-api 26, keep MainActivity) for the Java program in
 * tools/benchmark/r8_merge_fixture (its build.sh rebuilds them; verified to reproduce), decoded by baksmali 3.0.9 (debug lines dropped). R8 merged TokenEntry (class id 1) and Metadata (class id 0) into fx.a; their String fields share fx.a.b. The negative
 * program writes the caller's token into TokenEntry objects only: the delete in Metadata.flush (fx.a.b()) never sees it. The positive program also writes the caller's session id
 * into a Metadata object: the delete does see it.
 *
 * The synthetic Lt/ classes check each signal alone, with a twin that must keep its flow.
 */
public class IrMergeTagsTest {

    private static final String FX_MERGED = """
.class public final Lfx/a;
.super Ljava/lang/Object;
.field public final synthetic a:I
.field public b:Ljava/lang/String;
.field public c:I
.field public final d:Ljava/lang/Object;
.method public constructor <init>(Ljava/lang/String;Ljava/io/File;)V
    .registers 4
    const/4 v0, 0x0
    iput v0, p0, Lfx/a;->a:I
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lfx/a;->b:Ljava/lang/String;
    new-instance p1, Lfx/c;
    invoke-direct {p1, p2}, Lfx/c;-><init>(Ljava/io/File;)V
    iput-object p1, p0, Lfx/a;->d:Ljava/lang/Object;
    return-void
.end method
.method public constructor <init>(Ljava/lang/StringBuilder;)V
    .registers 3
    const/4 v0, 0x1
    iput v0, p0, Lfx/a;->a:I
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const-string v0, ""
    iput-object v0, p0, Lfx/a;->b:Ljava/lang/String;
    iput-object p1, p0, Lfx/a;->d:Ljava/lang/Object;
    return-void
.end method
.method public a()Ljava/lang/String;
    .registers 4
    iget-object v0, p0, Lfx/a;->d:Ljava/lang/Object;
    check-cast v0, Ljava/lang/StringBuilder;
    iget v1, p0, Lfx/a;->c:I
    add-int/lit8 v1, v1, 0x1
    iput v1, p0, Lfx/a;->c:I
    const/4 v1, 0x0
    :goto_b
    iget v2, p0, Lfx/a;->c:I
    if-ge v1, v2, :cond_1c
    iget-object v2, p0, Lfx/a;->b:Ljava/lang/String;
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const/16 v2, 0x2f
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    add-int/lit8 v1, v1, 0x1
    goto :goto_b
    :cond_1c
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
.method public b()V
    .registers 5
    iget v0, p0, Lfx/a;->c:I
    add-int/lit8 v0, v0, 0x1
    iput v0, p0, Lfx/a;->c:I
    const/4 v0, 0x0
    :goto_7
    iget v1, p0, Lfx/a;->c:I
    if-ge v0, v1, :cond_26
    iget-object v1, p0, Lfx/a;->d:Ljava/lang/Object;
    check-cast v1, Lfx/c;
    iget-object v2, p0, Lfx/a;->b:Ljava/lang/String;
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    new-instance v3, Ljava/io/File;
    iget-object v1, v1, Lfx/c;->a:Ljava/io/File;
    invoke-direct {v3, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    invoke-virtual {v3}, Ljava/io/File;->delete()Z
    move-result v1
    if-nez v1, :cond_23
    sput-object v2, Lfx/MainActivity;->sink:Ljava/lang/Object;
    :cond_23
    add-int/lit8 v0, v0, 0x1
    goto :goto_7
    :cond_26
    return-void
.end method
.method public final toString()Ljava/lang/String;
    .registers 5
    iget v0, p0, Lfx/a;->a:I
    packed-switch v0, :pswitch_data_3e
    iget v0, p0, Lfx/a;->c:I
    iget-object v1, p0, Lfx/a;->d:Ljava/lang/Object;
    check-cast v1, Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I
    move-result v1
    new-instance v2, Ljava/lang/StringBuilder;
    const-string v3, "T"
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
    :pswitch_21
    iget v0, p0, Lfx/a;->c:I
    iget-object v1, p0, Lfx/a;->d:Ljava/lang/Object;
    check-cast v1, Lfx/c;
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I
    move-result v1
    new-instance v2, Ljava/lang/StringBuilder;
    const-string v3, "M"
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
    nop
    :pswitch_data_3e
    .packed-switch 0x0
        :pswitch_21
    .end packed-switch
.end method
""";

    private static final String FX_HOLDERS_NEG = """
.class public abstract Lfx/b;
.super Ljava/lang/Object;
.field public static a:Lfx/a;
.field public static b:Lfx/a;
.field public static c:Lfx/a;
.field public static d:Lfx/a;
""";

    private static final String FX_HOLDERS_POS = """
.class public abstract Lfx/b;
.super Ljava/lang/Object;
.field public static a:Lfx/a;
.field public static b:Lfx/a;
.field public static c:Lfx/a;
.field public static d:Lfx/a;
.field public static e:Lfx/a;
""";

    private static final String FX_STORE = """
.class public final Lfx/c;
.super Ljava/lang/Object;
.field public final a:Ljava/io/File;
.method public constructor <init>(Ljava/io/File;)V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lfx/c;->a:Ljava/io/File;
    return-void
.end method
""";

    private static final String FX_ACTIVITY_NEG = """
.class public Lfx/MainActivity;
.super Landroid/app/Activity;
.field static volatile sink:Ljava/lang/Object;
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method
.method public onCreate(Landroid/os/Bundle;)V
    .registers 5
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object p1
    new-instance v0, Lfx/a;
    new-instance v1, Ljava/lang/StringBuilder;
    const/16 v2, 0x10
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(I)V
    invoke-direct {v0, v1}, Lfx/a;-><init>(Ljava/lang/StringBuilder;)V
    sput-object v0, Lfx/b;->a:Lfx/a;
    const-string v1, "token"
    invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    iput-object v1, v0, Lfx/a;->b:Ljava/lang/String;
    new-instance v0, Lfx/a;
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(I)V
    invoke-direct {v0, v1}, Lfx/a;-><init>(Ljava/lang/StringBuilder;)V
    sput-object v0, Lfx/b;->b:Lfx/a;
    const-string v1, "token2"
    invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object p1
    iput-object p1, v0, Lfx/a;->b:Ljava/lang/String;
    new-instance p1, Lfx/a;
    const-string v0, "session-1"
    invoke-virtual {p0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v1
    invoke-direct {p1, v0, v1}, Lfx/a;-><init>(Ljava/lang/String;Ljava/io/File;)V
    sput-object p1, Lfx/b;->c:Lfx/a;
    new-instance p1, Lfx/a;
    const-string v0, "session-2"
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;
    move-result-object v1
    invoke-direct {p1, v0, v1}, Lfx/a;-><init>(Ljava/lang/String;Ljava/io/File;)V
    sput-object p1, Lfx/b;->d:Lfx/a;
    sget-object p1, Lfx/b;->c:Lfx/a;
    invoke-virtual {p1}, Lfx/a;->b()V
    sget-object p1, Lfx/b;->d:Lfx/a;
    invoke-virtual {p1}, Lfx/a;->b()V
    sget-object p1, Lfx/b;->a:Lfx/a;
    invoke-virtual {p1}, Lfx/a;->a()Ljava/lang/String;
    move-result-object p1
    sget-object v0, Lfx/b;->b:Lfx/a;
    invoke-virtual {v0}, Lfx/a;->a()Ljava/lang/String;
    move-result-object v0
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object p1
    sput-object p1, Lfx/MainActivity;->sink:Ljava/lang/Object;
    sget-object p1, Lfx/b;->a:Lfx/a;
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object p1
    sget-object v0, Lfx/b;->c:Lfx/a;
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object p1
    sput-object p1, Lfx/MainActivity;->sink:Ljava/lang/Object;
    return-void
.end method
""";

    private static final String FX_ACTIVITY_POS = """
.class public Lfx/MainActivity;
.super Landroid/app/Activity;
.field static volatile sink:Ljava/lang/Object;
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method
.method public onCreate(Landroid/os/Bundle;)V
    .registers 6
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object p1
    new-instance v0, Lfx/a;
    new-instance v1, Ljava/lang/StringBuilder;
    const/16 v2, 0x10
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(I)V
    invoke-direct {v0, v1}, Lfx/a;-><init>(Ljava/lang/StringBuilder;)V
    sput-object v0, Lfx/b;->a:Lfx/a;
    const-string v1, "token"
    invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    iput-object v1, v0, Lfx/a;->b:Ljava/lang/String;
    new-instance v0, Lfx/a;
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(I)V
    invoke-direct {v0, v1}, Lfx/a;-><init>(Ljava/lang/StringBuilder;)V
    sput-object v0, Lfx/b;->b:Lfx/a;
    const-string v1, "token2"
    invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    iput-object v1, v0, Lfx/a;->b:Ljava/lang/String;
    new-instance v0, Lfx/a;
    const-string v1, "session-1"
    invoke-virtual {p0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v2
    invoke-direct {v0, v1, v2}, Lfx/a;-><init>(Ljava/lang/String;Ljava/io/File;)V
    sput-object v0, Lfx/b;->c:Lfx/a;
    new-instance v0, Lfx/a;
    const-string v1, "session-2"
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;
    move-result-object v2
    invoke-direct {v0, v1, v2}, Lfx/a;-><init>(Ljava/lang/String;Ljava/io/File;)V
    sput-object v0, Lfx/b;->d:Lfx/a;
    const-string v0, "s"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z
    move-result v1
    if-eqz v1, :cond_66
    new-instance v1, Lfx/a;
    const-string v2, "session-3"
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;
    move-result-object v3
    invoke-direct {v1, v2, v3}, Lfx/a;-><init>(Ljava/lang/String;Ljava/io/File;)V
    sput-object v1, Lfx/b;->e:Lfx/a;
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object p1
    iput-object p1, v1, Lfx/a;->b:Ljava/lang/String;
    :cond_66
    sget-object p1, Lfx/b;->c:Lfx/a;
    invoke-virtual {p1}, Lfx/a;->b()V
    sget-object p1, Lfx/b;->d:Lfx/a;
    invoke-virtual {p1}, Lfx/a;->b()V
    sget-object p1, Lfx/b;->e:Lfx/a;
    if-eqz p1, :cond_77
    invoke-virtual {p1}, Lfx/a;->b()V
    :cond_77
    sget-object p1, Lfx/b;->a:Lfx/a;
    invoke-virtual {p1}, Lfx/a;->a()Ljava/lang/String;
    move-result-object p1
    sget-object v0, Lfx/b;->b:Lfx/a;
    invoke-virtual {v0}, Lfx/a;->a()Ljava/lang/String;
    move-result-object v0
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object p1
    sput-object p1, Lfx/MainActivity;->sink:Ljava/lang/Object;
    sget-object p1, Lfx/b;->a:Lfx/a;
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object p1
    sget-object v0, Lfx/b;->c:Lfx/a;
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object p1
    sput-object p1, Lfx/MainActivity;->sink:Ljava/lang/Object;
    return-void
.end method
""";

    private static List<ClassIr> parse(String... texts) {
        List<ClassIr> cs = new ArrayList<>();
        for (String t : texts) cs.add(SmaliParser.parse(t));
        return cs;
    }

    private static int flows(List<ClassIr> cs, String entry) {
        CallGraph g = CallGraph.build(cs, Arrays.asList(entry), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null).flows.size();
    }

    private static int flowsWithoutTags(List<ClassIr> cs, String entry) {
        boolean was = TaintIr.MERGE_TAGS;
        TaintIr.MERGE_TAGS = false;
        try {
            return flows(cs, entry);
        } finally {
            TaintIr.MERGE_TAGS = was;
        }
    }

    // ---------------------------------------------------------------------------------------------- real R8 output

    @Test
    public void r8MergedClassesDoNotShareTaintAcrossClassIds() {
        List<ClassIr> neg = parse(FX_MERGED, FX_HOLDERS_NEG, FX_STORE, FX_ACTIVITY_NEG);
        assertEquals(0, flows(neg, "Lfx/MainActivity;"));
        assertEquals(1, flowsWithoutTags(neg, "Lfx/MainActivity;"));          // the merge false positive the class id removes
        assertEquals(1, flows(parse(FX_MERGED, FX_HOLDERS_POS, FX_STORE, FX_ACTIVITY_POS), "Lfx/MainActivity;"));   // the real flow through the same field stays
    }

    // ---------------------------------------------------------------------------------------------- synthetic, one signal each

    private static final String M = """
        .class public final Lt/M;
        .super Ljava/lang/Object;
        .field public final synthetic i:I
        .field public n:I
        .field public j:Ljava/lang/Object;
        .field public k:Ljava/lang/Object;
        .method public constructor <init>()V
            .locals 1
            const/4 v0, 0x0
            iput v0, p0, Lt/M;->i:I
            invoke-direct {p0}, Ljava/lang/Object;-><init>()V
            return-void
        .end method
        .method public synthetic constructor <init>(IZ)V
            .locals 0
            iput p1, p0, Lt/M;->i:I
            invoke-direct {p0}, Ljava/lang/Object;-><init>()V
            return-void
        .end method
        .method public constructor <init>(Lt/Y;)V
            .locals 1
            const/4 v0, 0x1
            iput v0, p0, Lt/M;->i:I
            invoke-direct {p0}, Ljava/lang/Object;-><init>()V
            iput-object p1, p0, Lt/M;->k:Ljava/lang/Object;
            return-void
        .end method
        .method public read()V
            .locals 2
            iget-object v0, p0, Lt/M;->j:Ljava/lang/Object;
            check-cast v0, Ljava/lang/String;
            new-instance v1, Ljava/io/File;
            invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
            invoke-virtual {v1}, Ljava/io/File;->delete()Z
            return-void
        .end method
        .method public run()V
            .locals 2
            iget v0, p0, Lt/M;->SWITCHED:I
            packed-switch v0, :pswitch_data_0
            iget-object v0, p0, Lt/M;->j:Ljava/lang/Object;
            check-cast v0, Ljava/lang/String;
            new-instance v1, Ljava/io/File;
            invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
            invoke-virtual {v1}, Ljava/io/File;->delete()Z
            return-void
            :pswitch_1
            iget-object v0, p0, Lt/M;->j:Ljava/lang/Object;
            invoke-static {v0}, Lt/A;->keep(Ljava/lang/Object;)V
            return-void
            :pswitch_data_0
            .packed-switch 0x1
                :pswitch_1
            .end packed-switch
        .end method
        """;

    private static final String B = """
        .class public final Lt/B;
        .super Ljava/lang/Object;
        .method public static make()Lt/M;
            .locals 3
            new-instance v0, Lt/M;
            const/4 v1, 0x2
            const/4 v2, 0x0
            invoke-direct {v0, v1, v2}, Lt/M;-><init>(IZ)V
            return-object v0
        .end method
        """;

    private static final String H = ".class public final Lt/H;\n.super Ljava/lang/Object;\n.field public static m:Lt/M;\n";
    private static final String X = ".class public Lt/X;\n.super Ljava/lang/Object;\n.method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n";
    private static final String Y = X.replace("Lt/X;", "Lt/Y;");

    private static final String HELPERS = """
        .method public static keep(Ljava/lang/Object;)V
            .locals 0
            return-void
        .end method
        .method public static go(Lt/M;)V
            .locals 0
            invoke-virtual {p0}, Lt/M;->run()V
            return-void
        .end method
        .method public static viaHolder()V
            .locals 2
            sget-object v0, Lt/H;->m:Lt/M;
            iget-object v0, v0, Lt/M;->j:Ljava/lang/Object;
            check-cast v0, Ljava/lang/String;
            new-instance v1, Ljava/io/File;
            invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
            invoke-virtual {v1}, Ljava/io/File;->delete()Z
            return-void
        .end method
        .method public static use(Lt/M;)V
            .locals 2
            iget-object v0, p0, Lt/M;->k:Ljava/lang/Object;
            check-cast v0, Lt/Y;
            invoke-static {v0}, Lt/A;->keep(Ljava/lang/Object;)V
            iget-object v0, p0, Lt/M;->j:Ljava/lang/Object;
            check-cast v0, Ljava/lang/String;
            new-instance v1, Ljava/io/File;
            invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
            invoke-virtual {v1}, Ljava/io/File;->delete()Z
            return-void
        .end method
        .method public static use2(Lt/M;Z)V
            .locals 2
            if-eqz p1, :cond_0
            iget-object v0, p0, Lt/M;->k:Ljava/lang/Object;
            check-cast v0, Lt/Y;
            invoke-static {v0}, Lt/A;->keep(Ljava/lang/Object;)V
            :cond_0
            iget-object v0, p0, Lt/M;->j:Ljava/lang/Object;
            check-cast v0, Ljava/lang/String;
            new-instance v1, Ljava/io/File;
            invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
            invoke-virtual {v1}, Ljava/io/File;->delete()Z
            return-void
        .end method
        """;

    /**
     * The activity reads the caller's string into v1 and makes three objects of t.M: v2 with class id 0 (allocated here), v3 with id 2 (from the builder B.make, which passes
     * the id to R8's synthetic constructor) whose k holds an X, and v4 with id 1 whose k holds a Y; then [body].
     */
    private static String activity(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"u\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1\n"
            + "    new-instance v2, Lt/M;\n    invoke-direct {v2}, Lt/M;-><init>()V\n"
            + "    invoke-static {}, Lt/B;->make()Lt/M;\n    move-result-object v3\n"
            + "    new-instance v4, Lt/X;\n    invoke-direct {v4}, Lt/X;-><init>()V\n    iput-object v4, v3, Lt/M;->k:Ljava/lang/Object;\n"
            + "    new-instance v5, Lt/Y;\n    invoke-direct {v5}, Lt/Y;-><init>()V\n    new-instance v4, Lt/M;\n    invoke-direct {v4, v5}, Lt/M;-><init>(Lt/Y;)V\n"
            + body.replace("\n", "\n    ").replaceFirst("^", "    ") + "\n    return-void\n.end method\n" + HELPERS.replace("\n        ", "\n").replaceFirst("^        ", "");
    }

    private static int run(String body) {
        return flows(app(body, false), "Lt/A;");
    }

    private static List<ClassIr> app(String body, boolean switchOnOtherField) {
        String m = M.replace("\n        ", "\n").replaceFirst("^        ", "").replace("SWITCHED", switchOnOtherField ? "n" : "i");
        return parse(activity(body), m, B.replace("\n        ", "\n").replaceFirst("^        ", ""), H, X, Y);
    }

    @Test
    public void methodPartitionTheCallersOfAMethodTellItsClassId() {
        // read() is only ever called on the id-0 object: the id-2 write is not its field
        assertEquals(0, run("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-virtual {v2}, Lt/M;->read()V"));
        assertEquals(1, run("iput-object v1, v2, Lt/M;->j:Ljava/lang/Object;\ninvoke-virtual {v2}, Lt/M;->read()V"));    // twin: same id
        assertEquals(1, flowsWithoutTags(app("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-virtual {v2}, Lt/M;->read()V", false), "Lt/A;"));
    }

    @Test
    public void builderResultsCarryTheIdTheBuilderPassed() {
        // reader and writer objects both come from B.make (id 2): the flow stays
        assertEquals(1, run("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {}, Lt/B;->make()Lt/M;\nmove-result-object v5\ninvoke-virtual {v5}, Lt/M;->read()V"));
        // a reader called on objects of two ids is not decided: every write stays visible
        assertEquals(1, run("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-virtual {v2}, Lt/M;->read()V\ninvoke-virtual {v3}, Lt/M;->read()V"));
    }

    @Test
    public void holderProvenanceTheFieldAnObjectIsReadFromTellsItsClassId() {
        assertEquals(0, run("sput-object v2, Lt/H;->m:Lt/M;\niput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {}, Lt/A;->viaHolder()V"));
        assertEquals(1, run("sput-object v3, Lt/H;->m:Lt/M;\niput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {}, Lt/A;->viaHolder()V"));   // twin
    }

    @Test
    public void aClassIdSwitchPartitionsADispatchMethod() {
        // go() calls run() on a parameter (id unknown); the delete is on run()'s default path, which id 1 never takes
        assertEquals(0, run("iput-object v1, v4, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {v2}, Lt/A;->go(Lt/M;)V"));
        assertEquals(1, run("iput-object v1, v2, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {v2}, Lt/A;->go(Lt/M;)V"));   // twin: id 0 takes the default path
        // negative twin: a switch on an ordinary int field says nothing about the class id
        assertEquals(1, flows(app("iput-object v1, v4, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {v2}, Lt/A;->go(Lt/M;)V", true), "Lt/A;"));
    }

    @Test
    public void aSiblingFieldCastThatAlwaysRunsExcludesTheOtherClassIds() {
        // use() casts the object's k to Y before reading j: id 2 keeps an X in k, so the object is not an id-2 object
        assertEquals(0, run("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {v4}, Lt/A;->use(Lt/M;)V"));
        assertEquals(1, run("iput-object v1, v4, Lt/M;->j:Ljava/lang/Object;\ninvoke-static {v4}, Lt/A;->use(Lt/M;)V"));     // twin: id 1 keeps a Y in k
        // twin: in use2 the cast runs on one path only, so it says nothing about the read
        assertEquals(1, run("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\nconst/4 v5, 0x1\ninvoke-static {v4, v5}, Lt/A;->use2(Lt/M;Z)V"));
    }

    @Test
    public void appWideFactsSeeTheBuilderOutsideTheGroup() {
        String body = "iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;\ninvoke-virtual {v2}, Lt/M;->read()V";
        List<ClassIr> all = app(body, false);
        final List<String> texts = new ArrayList<>();
        texts.add(activity(body));
        texts.add(M.replace("\n        ", "\n").replaceFirst("^        ", "").replace("SWITCHED", "i"));
        texts.add(B.replace("\n        ", "\n").replaceFirst("^        ", ""));
        texts.add(H);
        texts.add(X);
        texts.add(Y);
        List<ClassIr> group = new ArrayList<>(all);
        group.remove(2);                                                   // the group holds no builder: the writer's id is unknown there
        assertEquals(1, readFlows(SsaBridge.newFlows(group, Arrays.asList("Lt/A;"), null, null, null, null)));
        MergeFacts facts = MergeFacts.of(new ScopePlanner.Source() {
            public int count() { return texts.size(); }
            public String type(int i) { return all.get(i).type; }
            public String text(int i) { return texts.get(i); }
        });
        assertEquals(1, facts.mergedClasses);
        assertEquals(0, readFlows(SsaBridge.newFlows(group, Arrays.asList("Lt/A;"), null, null, null, facts)));
    }

    /** Cards whose sink is in M.read() (the bridge analyses every method, the other helpers too). */
    private static int readFlows(List<SsaBridge.Item> items) {
        int n = 0;
        for (SsaBridge.Item it : items) if (it.method.contains("->read()")) n++;
        return n;
    }

    // ---------------------------------------------------------------------------------------------- parsing

    @Test
    public void theParserKeepsTheClassIdFieldAndTheSwitchKeys() {
        ClassIr m = SmaliParser.parse(M.replace("\n        ", "\n").replaceFirst("^        ", "").replace("SWITCHED", "i"));
        assertEquals("i:I", m.discriminator);
        assertNull(SmaliParser.parse(H).discriminator);                    // a static field is no class id
        assertNull(SmaliParser.parse(".class public La;\n.super Ljava/lang/Object;\n.field public b:I\n").discriminator);   // nor a field R8 did not add
        MethodIr run = null;
        for (MethodIr x : m.methods) if (x.name.equals("run")) run = x;
        assertTrue(Arrays.equals(new long[]{1}, run.switchKeys.get(":pswitch_data_0")));
        ClassIr s = SmaliParser.parse(".class public La;\n.super Ljava/lang/Object;\n.method public static f(I)V\n    .locals 0\n    sparse-switch p0, :sw\n    return-void\n"
            + "    :c1\n    return-void\n    :c2\n    return-void\n    :sw\n    .sparse-switch\n        -0x1 -> :c1\n        0x10 -> :c2\n    .end sparse-switch\n.end method\n");
        assertTrue(Arrays.equals(new long[]{-1, 16}, s.methods.get(0).switchKeys.get(":sw")));
    }

    @Test
    public void theDigestMarksMergedClassesAndTheFieldsAClassWrites() {
        String m = M.replace("\n        ", "\n").replaceFirst("^        ", "").replace("SWITCHED", "i");
        CallSkeleton.Digest d = CallSkeleton.digest(m);
        assertTrue((d.bits & CallSkeleton.D_MERGED) != 0);
        assertFalse((CallSkeleton.digest(H).bits & CallSkeleton.D_MERGED) != 0);
        CallSkeleton.Digest a = CallSkeleton.digest(activity("iput-object v1, v3, Lt/M;->j:Ljava/lang/Object;"));
        assertEquals(Arrays.asList("Lt/M;"), Arrays.asList(a.fieldOwners));     // its own fields and static fields are not listed
        assertEquals(0, d.fieldOwners.length);
    }
}
