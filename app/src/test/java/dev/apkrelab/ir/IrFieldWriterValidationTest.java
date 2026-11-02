package dev.apkrelab.ir;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.Test;

/**
 * 3.0.0 (real-CVE benchmark C03, Omni-Notes 6.2.8): the value is checked (validatePath) in the method that stores it in a field, and the sink reads the field in another
 * class. The check is in the field's WRITER, which is not on the value's chain: it must count. Twin: the same code without the check stays unvalidated.
 */
public class IrFieldWriterValidationTest {
    static List<SsaBridge.Item> items(boolean check) {
        String d = ".class public Lt/D;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n"
            + "    invoke-virtual {p0}, Lt/D;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"p\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
            + (check ? "    invoke-static {v2}, Lt/U;->validatePath(Ljava/lang/String;)Z\n    move-result v5\n    if-eqz v5, :skip\n" : "")
            + "    new-instance v4, Lt/T;\n    invoke-direct {v4}, Lt/T;-><init>()V\n    iput-object v2, v4, Lt/T;->p:Ljava/lang/String;\n"
            + "    invoke-virtual {v4}, Lt/T;->run()V\n"
            + (check ? "    :skip\n" : "")
            + "    return-void\n.end method\n";
        String t = ".class public Lt/T;\n.super Ljava/lang/Object;\n.field public p:Ljava/lang/String;\n\n.method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n\n"
            + ".method public run()V\n    .locals 3\n    iget-object v0, p0, Lt/T;->p:Ljava/lang/String;\n"
            + "    new-instance v1, Ljava/io/FileInputStream;\n    invoke-direct {v1, v0}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";
        String u = ".class public Lt/U;\n.super Ljava/lang/Object;\n\n.method public static validatePath(Ljava/lang/String;)Z\n    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method\n";
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(d), SmaliParser.parse(t), SmaliParser.parse(u)));
        return SsaBridge.newFlows(CallGraph.build(all, Arrays.asList("Lt/D;"), CallGraph.Mode.RTA, null), null);
    }

    static SsaBridge.Item fileItem(boolean check) {
        for (SsaBridge.Item it : items(check)) if (it.detail.contains("FileInputStream")) return it;
        return null;
    }

    @Test public void aCheckInTheFieldWriterCounts() {
        SsaBridge.Item it = fileItem(true);
        assertNotNull(it);
        assertTrue(it.detail, it.detail.contains("written in"));          // the value came through the field
        assertTrue(it.detail, it.detail.contains("validation-like calls"));
    }

    @Test public void withoutTheCheckTheFieldFlowStaysUnvalidated() {           // twin
        SsaBridge.Item it = fileItem(false);
        assertNotNull(it);
        assertFalse(it.detail, it.detail.contains("validation-like calls"));
    }

    @Test public void theMutationLosesIt() {
        boolean was = SsaBridge.WRITER_OF_FIELD;
        SsaBridge.WRITER_OF_FIELD = false;
        try { assertFalse(fileItem(true).detail.contains("validation-like calls")); } finally { SsaBridge.WRITER_OF_FIELD = was; }
    }
}
