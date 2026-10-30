package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

/** 1.1.0: Kotlin's substringAfterLast with a constant '/' leaves a bare file name; any other separator keeps the directory part. */
public class IrBasenameSanitizerTest {

    private static int flows(String sep) {
        String s = ".class public Lt/A;\n.super Landroid/app/Activity;\n"
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n"
            + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
            + "    const-string v1, \"name\"\n"
            + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n"
            + "    const/16 v1, " + sep + "\n    const/4 v2, 0x0\n    const/4 v3, 0x2\n"
            + "    invoke-static {v0, v1, v2, v3, v2}, Lkotlin/text/StringsKt;->substringAfterLast$default(Ljava/lang/String;CLjava/lang/String;ILjava/lang/Object;)Ljava/lang/String;\n"
            + "    move-result-object v0\n"
            + "    new-instance v4, Ljava/io/File;\n    invoke-direct {v4, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-virtual {v4}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n";
        CallGraph g = CallGraph.build(Collections.singletonList(SmaliParser.parse(s)), Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, false, null).flows.size();
    }

    @Test
    public void aSlashBasenameIsSanitized() {
        assertEquals(0, flows("0x2f"));
    }

    @Test
    public void anotherSeparatorIsNot() {
        assertEquals(1, flows("0x2e"));
    }

    @Test
    public void theRuleIsTheSwitchedPart() {
        boolean was = TaintIr.BASENAME_SANITIZER;
        TaintIr.BASENAME_SANITIZER = false;
        try {
            assertEquals(1, flows("0x2f"));
        } finally {
            TaintIr.BASENAME_SANITIZER = was;
        }
    }
}
