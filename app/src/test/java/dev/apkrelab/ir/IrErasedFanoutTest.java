package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 1.1.0: the result of a call through an erased generic callback (every parameter Object, as Function.invoke or a coroutine's invokeSuspend) that resolves to
 * FANOUT_WEAK or more bodies does not carry a source read inside one of those bodies: it is the union of every lambda of that shape. Twins: fewer bodies,
 * a typed signature, and the caller's own argument returned by a body.
 */
public class IrErasedFanoutTest {

    /**
     * [n] classes implement Lt/F;->call[desc]; body 0 returns a value read with Intent.getStringExtra (or, when [echo], its own argument). Lt/A;->use(Lt/F;) calls
     * the callback on a receiver of unknown origin and deletes the file named by the result.
     */
    private static int flows(int n, String desc, boolean echo) {
        String param = desc.substring(1, desc.indexOf(')'));
        String ret = desc.substring(desc.indexOf(')') + 1);
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(".class public interface abstract Lt/F;\n.super Ljava/lang/Object;\n.method public abstract call" + desc + "\n.end method\n"));
        for (int i = 0; i < n; i++) {
            StringBuilder b = new StringBuilder(".class public final Lt/L" + i + ";\n.super Ljava/lang/Object;\n.implements Lt/F;\n");
            b.append(".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n");
            b.append(".method public call" + desc + "\n    .locals 2\n");
            if (i == 0 && echo) b.append("    return-object p1\n");
            else if (i == 0) {
                b.append("    new-instance v0, Landroid/content/Intent;\n    invoke-direct {v0}, Landroid/content/Intent;-><init>()V\n    const-string v1, \"k\"\n");
                b.append("    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n    return-object v0\n");
            } else b.append("    const-string v0, \"fixed\"\n    return-object v0\n");
            b.append(".end method\n");
            cs.add(SmaliParser.parse(b.toString()));
        }
        StringBuilder a = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n.field public static h:Lt/F;\n");
        a.append(".method public onCreate(Landroid/os/Bundle;)V\n    .locals 2\n");
        for (int i = 0; i < n; i++) a.append("    new-instance v0, Lt/L" + i + ";\n    invoke-direct {v0}, Lt/L" + i + ";-><init>()V\n    sput-object v0, Lt/A;->h:Lt/F;\n");
        a.append("    sget-object v0, Lt/A;->h:Lt/F;\n");
        if (echo) {
            a.append("    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v1\n    const-string p1, \"k\"\n");
            a.append("    invoke-virtual {v1, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v1\n");
        } else a.append("    const-string v1, \"in\"\n");
        a.append("    invoke-static {v0, v1}, Lt/A;->use(Lt/F;" + param + ")V\n    return-void\n.end method\n");
        a.append(".method public static use(Lt/F;" + param + ")V\n    .locals 2\n");
        a.append("    invoke-interface {p0, p1}, Lt/F;->call" + desc + "\n    move-result-object v0\n");
        if (!ret.equals("Ljava/lang/String;")) a.append("    check-cast v0, Ljava/lang/String;\n");
        a.append("    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n");
        a.append("    invoke-virtual {v1}, Ljava/io/File;->delete()Z\n    return-void\n.end method\n");
        cs.add(SmaliParser.parse(a.toString()));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        int k = 0;
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/A;->use")) k++;
        return k;
    }

    private static final String ERASED = "(Ljava/lang/Object;)Ljava/lang/Object;";
    private static final String TYPED = "(Ljava/lang/String;)Ljava/lang/String;";

    @Test
    public void aSourceInsideOneOfManyErasedCallbacksIsNotTheCallsResult() {
        assertEquals(0, flows(TaintIr.FANOUT_WEAK, ERASED, false));
    }

    @Test
    public void theTwinsKeepTheirFlow() {
        assertEquals(1, flows(TaintIr.FANOUT_WEAK - 1, ERASED, false));       // fewer bodies: the existing weak lead
        assertEquals(1, flows(TaintIr.FANOUT_WEAK, TYPED, false));            // a typed signature is not a generic callback
        assertEquals(1, flows(TaintIr.FANOUT_WEAK, ERASED, true));            // the caller's own argument, returned by a body
    }

    @Test
    public void theRuleIsTheSwitchedPart() {
        boolean was = TaintIr.ERASED_FANOUT_DROP;
        TaintIr.ERASED_FANOUT_DROP = false;
        try {
            assertEquals(1, flows(TaintIr.FANOUT_WEAK, ERASED, false));       // mutation: without the rule the union comes back
        } finally {
            TaintIr.ERASED_FANOUT_DROP = was;
        }
    }

    @Test
    public void erasedSignatures() {
        assertTrue(TaintIr.erasedGeneric("(Ljava/lang/Object;)Ljava/lang/Object;"));
        assertTrue(TaintIr.erasedGeneric("(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"));
        assertTrue(TaintIr.erasedGeneric("(Ljava/lang/Object;)V"));
        assertFalse(TaintIr.erasedGeneric("()Ljava/lang/Object;"));                        // a nullary getter (Iterator.next, Lazy.getValue)
        assertFalse(TaintIr.erasedGeneric("(Ljava/lang/String;)Ljava/lang/Object;"));
        assertFalse(TaintIr.erasedGeneric("(Ljava/lang/Object;)Ljava/lang/String;"));
    }
}
