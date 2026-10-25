package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.Test;

/**
 * 1.0.0 (allocation work, no result may change): the call-site facts parsed once into a shared table (TaintIr.Call), the invoke kind read without a substring, the sink
 * owners built once, and the taint-only edges deduplicated per call site instead of with a "caller|insn|callee" string per edge.
 */
public class IrCallInfoTest {

    private static Insn invoke(String line) {
        ClassIr c = SmaliParser.parse(".class public La;\n.super Ljava/lang/Object;\n.method public f()V\n    .locals 6\n    " + line + "\n    return-void\n.end method\n");
        return c.methods.get(0).insns.get(0);
    }

    @Test
    public void callFactsAreTheReferenceParsedOnceAndKeyedByTheInvokeKind() {
        Insn v = invoke("invoke-virtual {v0, v1, v2, v3}, Lx/Y;->put(JLjava/lang/String;)V");
        TaintIr.Call c = TaintIr.Call.of(v);
        assertEquals("Lx/Y;", c.owner);
        assertEquals("put", c.name);
        assertEquals("(JLjava/lang/String;)V", c.desc);
        assertEquals("V", c.ret);
        assertTrue(Arrays.equals(new int[]{0, 1, 3}, c.phys));                     // receiver, the wide long (two registers), the String
        assertSame(c, TaintIr.Call.of(invoke("invoke-virtual {v0, v1, v2, v3}, Lx/Y;->put(JLjava/lang/String;)V")));   // the same reference: the same facts, no new parse
        TaintIr.Call s = TaintIr.Call.of(invoke("invoke-static {v1, v2, v3}, Lx/Y;->put(JLjava/lang/String;)V"));
        assertTrue(s.isStatic);
        assertTrue(Arrays.equals(new int[]{0, 2}, s.phys));                        // no receiver: another layout for the same reference
        assertTrue(TaintIr.Call.of(v).phys.length == 3 && !TaintIr.Call.of(v).isStatic);
    }

    @Test
    public void sinkCandidatesComeWithTheFacts() {
        assertNotNull(TaintIr.Call.of(invoke("invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V")).cands);
        assertNull(TaintIr.Call.of(invoke("invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;")).cands);
    }

    @Test
    public void theInvokeKindIsTheOneTheOpcodeNames() {
        String[][] cases = {{"invoke-virtual", "virtual"}, {"invoke-virtual/range", "virtual"}, {"invoke-static", "static"}, {"invoke-static/range", "static"},
            {"invoke-direct", "direct"}, {"invoke-direct/range", "direct"}, {"invoke-interface", "interface"}, {"invoke-interface/range", "interface"},
            {"invoke-super", "super"}, {"invoke-super/range", "super"}, {"invoke-polymorphic", "polymorphic"}, {"invoke-custom", "custom"}};
        for (String[] k : cases) {
            String args = k[0].endsWith("/range") ? "{v0 .. v1}" : "{v0, v1}";
            Insn in = invoke(k[0] + " " + args + ", Lx/Y;->m(I)V");
            assertEquals(k[0], k[1], in.invokeKind());
        }
    }

    @Test
    public void sinkOwnersAreBuiltOnceAndCannotBeChanged() {
        Set<String> a = TaintIr.sinkOwners();
        assertSame(a, TaintIr.sinkOwners());
        assertTrue(a.contains("Landroid/webkit/WebView;"));
        try {
            a.add("Lx;");
            throw new AssertionError("the shared set must not be writable");
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test
    public void twoCallSitesOfTheSameMethodAreTwoEdgesAndOneSiteIsOne() {
        String a = ".class public Lt/A;\n.super Ljava/lang/Object;\n"
            + ".method public f()V\n    .locals 1\n"
            + "    invoke-static {}, Lt/B;->g()V\n"
            + "    invoke-static {}, Lt/B;->g()V\n"
            + "    return-void\n.end method\n";
        String b = ".class public Lt/B;\n.super Ljava/lang/Object;\n.method public static g()V\n    .locals 0\n    return-void\n.end method\n";
        List<ClassIr> cs = new ArrayList<>(Arrays.asList(SmaliParser.parse(a), SmaliParser.parse(b)));
        CallGraph g = CallGraph.build(cs, Collections.<String>emptyList(), CallGraph.Mode.RTA, null);   // no entry: every edge is a taint-only edge
        List<CallGraph.Edge> es = g.taintEdgesFrom("Lt/A;->f()V");
        assertEquals(2, es.size());
        assertTrue(es.get(0).insn != es.get(1).insn);
    }
}
