package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** 0.104.2: the engine's cached SSA form drops what only its construction needed (dominator children, dominance frontiers) and trims its lists; the form itself is unchanged. */
public class IrSsaMemoryTest {
    private static final String CLS = ".class public Lt/A;\n.super Ljava/lang/Object;\n"
            + ".method public static f(I)I\n    .locals 2\n    if-eqz p0, :a\n    const/4 v0, 0x1\n    goto :b\n    :a\n    const/4 v0, 0x2\n    :b\n"
            + "    add-int v1, v0, p0\n    :loop\n    if-lez v1, :end\n    add-int/lit8 v1, v1, -0x1\n    goto :loop\n    :end\n    return v1\n.end method\n";

    private static String shape(SsaForm s) {
        StringBuilder sb = new StringBuilder();
        for (int b = 0; b < s.phis.length; b++) sb.append(b).append(':').append(s.phis[b].size()).append(';');
        for (Cfg.BasicBlock bb : s.cfg.blocks) sb.append('[').append(bb.id).append(' ').append(bb.succs.size()).append('/').append(bb.preds.size()).append(']');
        sb.append(java.util.Arrays.toString(s.cfg.idom)).append(java.util.Arrays.toString(s.cfg.rpo)).append(s.phiCount());
        return sb.toString();
    }

    @Test
    public void theCachedFormIsTheSameFormWithoutItsConstructionLists() {
        MethodIr m1 = SmaliParser.parse(CLS).methods.get(0), m2 = SmaliParser.parse(CLS).methods.get(0);
        SsaForm plain = SsaForm.build(m1);
        SsaForm cached = SsaForm.buildCached(m2);
        assertEquals(shape(plain), shape(cached));                       // the same blocks, edges, dominators, phis
        assertTrue(plain.phiCount() > 0);                                 // the method really has joins (so the frontiers mattered)
        assertNull(cached.cfg.df); assertNull(cached.cfg.domChildren);    // released after construction
        assertNotNull(plain.cfg.df); assertNotNull(plain.cfg.domChildren);  // twin: a form built directly keeps them (tests and tools read them)
        assertTrue(SsaForm.buildCached(m2) == cached);                    // and the cache still returns the one form
    }
}
