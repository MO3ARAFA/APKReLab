package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.105.0: R8 merges unrelated classes into one class with shared Object fields. When every tainted write to such a field stored a String, a read whose every use casts
 * the value to a type no String can have (here File) cannot be that tainted String: the cast would throw. The read carries no taint then. Twins: a written value that is not
 * statically a String, a cast to String, a read that is also used without a cast.
 */
public class IrCastGuardTest {

    /** A writes [writeCall]'s result into H.o:Object; A.use() reads H.o, casts it to [castType] and deletes it as a File. [extraUse]: the read is also passed to a method. */
    private static int flows(String writeCall, String castType, boolean extraUse) {
        return flows(writeCall, castType, extraUse, null);
    }

    private static int flows(String writeCall, String castType, boolean extraUse, String secondWrite) {
        StringBuilder a = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n");
        a.append(".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n");
        a.append("    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"u\"\n");
        a.append("    ").append(writeCall).append("\n    move-result-object v2\n");
        a.append("    sput-object v2, Laa;->o:Ljava/lang/Object;\n");
        if (secondWrite != null) a.append("    ").append(secondWrite).append("\n    move-result-object v2\n    sput-object v2, Laa;->o:Ljava/lang/Object;\n");
        a.append("    invoke-virtual {p0}, Lt/A;->use()V\n    return-void\n.end method\n\n");
        a.append(".method public use()V\n    .locals 3\n    sget-object v0, Laa;->o:Ljava/lang/Object;\n");
        if (extraUse) a.append("    invoke-static {v0}, Lt/A;->keep(Ljava/lang/Object;)V\n");
        a.append("    check-cast v0, ").append(castType).append("\n");
        if (castType.equals("Ljava/lang/String;")) {
            a.append("    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    move-object v0, v1\n");
        }
        a.append("    invoke-virtual {v0}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n\n");
        a.append(".method public static keep(Ljava/lang/Object;)V\n    .locals 0\n    return-void\n.end method\n");
        String h = ".class public Laa;\n.super Ljava/lang/Object;\n\n.field public static o:Ljava/lang/Object;\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(a.toString()));
        cs.add(SmaliParser.parse(h));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        int n = 0;
        for (TaintIr.Flow f : TaintIr.analyze(g, true, null).flows) if (f.sink.method.startsWith("Lt/A;->use")) n++;
        return n;
    }

    private static final String STRING_EXTRA = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String PARCEL_EXTRA = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;";

    @Test
    public void aTaintedStringReadBackAsAFileIsNoFlow() {
        assertEquals(0, flows(STRING_EXTRA, "Ljava/io/File;", false));
    }

    @Test
    public void theTwinsKeepTheirFlow() {
        assertEquals(1, flows(PARCEL_EXTRA, "Ljava/io/File;", false));      // the written value is not statically a String: it may be a File
        assertEquals(1, flows(STRING_EXTRA, "Ljava/lang/String;", false));  // a cast a String passes
        assertEquals(1, flows(STRING_EXTRA, "Ljava/io/File;", true));       // the read is also used without a cast: nothing is dropped
        assertEquals(1, flows(STRING_EXTRA, "Ljava/io/File;", false, PARCEL_EXTRA));   // a second tainted write that may be a File: every write must be a String
    }
}
