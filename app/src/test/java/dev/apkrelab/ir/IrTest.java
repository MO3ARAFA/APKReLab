package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

/** 0.53.0 (P0): JVM tests for the IR layer (SmaliParser -> Cfg -> SsaForm) on tiny hand-written smali. */
public class IrTest {

    private static final String HEAD = ".class public Lt/A;\n.super Ljava/lang/Object;\n\n";

    private static MethodIr method(String body, String sig) {
        ClassIr c = SmaliParser.parse(HEAD + body);
        MethodIr m = c.method(sig);
        assertNotNull("method " + sig + " not parsed", m);
        return m;
    }

    private static final String DIAMOND =
            ".method public static f(I)I\n"
                    + "    .locals 2\n"
                    + "    if-eqz p0, :zero\n"
                    + "    const/4 v0, 0x1\n"
                    + "    goto :end\n"
                    + "    :zero\n"
                    + "    const/4 v0, 0x2\n"
                    + "    :end\n"
                    + "    return v0\n"
                    + ".end method\n";

    private static final String LOOP =
            ".method public static g(I)I\n"
                    + "    .locals 2\n"
                    + "    const/4 v0, 0x0\n"
                    + "    :loop\n"
                    + "    if-ge v0, p0, :done\n"
                    + "    add-int/lit8 v0, v0, 0x1\n"
                    + "    goto :loop\n"
                    + "    :done\n"
                    + "    return v0\n"
                    + ".end method\n";

    private static final String TRY =
            ".method public static h(Ljava/lang/String;)I\n"
                    + "    .locals 2\n"
                    + "    const/4 v0, 0x0\n"
                    + "    :try_start\n"
                    + "    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I\n"
                    + "    move-result v0\n"
                    + "    :try_end\n"
                    + "    .catch Ljava/lang/NumberFormatException; {:try_start .. :try_end} :handler\n"
                    + "    return v0\n"
                    + "    :handler\n"
                    + "    move-exception v1\n"
                    + "    return v0\n"
                    + ".end method\n";

    private static final String SWITCH =
            ".method public static s(I)I\n"
                    + "    .locals 1\n"
                    + "    packed-switch p0, :pswitch_data\n"
                    + "    const/4 v0, 0x0\n"
                    + "    return v0\n"
                    + "    :pswitch_1\n"
                    + "    const/4 v0, 0x1\n"
                    + "    return v0\n"
                    + "    :pswitch_2\n"
                    + "    const/4 v0, 0x2\n"
                    + "    return v0\n"
                    + "    :pswitch_data\n"
                    + "    .packed-switch 0x0\n"
                    + "        :pswitch_1\n"
                    + "        :pswitch_2\n"
                    + "    .end packed-switch\n"
                    + ".end method\n";

    private static final String WIDE =
            ".method public foo(JLjava/lang/String;)J\n"
                    + "    .locals 3\n"
                    + "    invoke-virtual {p0, p3}, Lt/A;->bar(Ljava/lang/String;)J\n"
                    + "    move-result-wide v0\n"
                    + "    return-wide v0\n"
                    + ".end method\n";

    // ---------- parser ----------

    @Test
    public void parserReadsClassHeader() {
        ClassIr c = SmaliParser.parse(".class public final Lt/B;\n.super Lt/A;\n.implements Ljava/lang/Runnable;\n"
                + ".field private x:I\n.field static final y:Ljava/lang/String; = \"a b\"\n");
        assertEquals("Lt/B;", c.type);
        assertEquals("Lt/A;", c.superType);
        assertEquals("public final", c.flags);
        assertEquals(Arrays.asList("Ljava/lang/Runnable;"), c.interfaces);
        assertEquals(Arrays.asList("x:I", "y:Ljava/lang/String;"), c.fields);
    }

    @Test
    public void registerMappingAndWideSlots() {
        MethodIr m = method(WIDE, "foo(JLjava/lang/String;)J");
        assertEquals(4, m.ins);          // this + long(2) + String
        assertEquals(3, m.locals);
        assertEquals(3, m.reg("p0"));
        assertEquals(6, m.reg("p3"));
        assertEquals(1, m.reg("v1"));
        assertEquals(-1, m.reg("x1"));
        assertEquals("p3", m.regName(6));
    }

    @Test
    public void invokeIsFusedWithMoveResult() {
        MethodIr m = method(WIDE, "foo(JLjava/lang/String;)J");
        assertEquals(2, m.insns.size());          // invoke(+result), return-wide
        Insn inv = m.insns.get(0);
        assertTrue(inv.isInvoke());
        assertTrue(inv.hasResult);
        assertEquals("virtual", inv.invokeKind());
        assertEquals("Lt/A;", inv.targetOwner());
        assertEquals("bar", inv.targetName());
        assertTrue(Arrays.equals(new int[]{3, 6}, inv.uses));
        assertTrue(Arrays.equals(new int[]{0, 1}, inv.defs));   // wide: both halves
        assertTrue(Arrays.equals(new int[]{0, 1}, m.insns.get(1).uses));
    }

    @Test
    public void rangeInvokeAndRegistersDirective() {
        ClassIr c = SmaliParser.parse(HEAD
                + ".method public static r(IIII)V\n    .registers 6\n"
                + "    invoke-static/range {p0 .. p3}, Lt/A;->r(IIII)V\n    return-void\n.end method\n");
        MethodIr m = c.method("r(IIII)V");
        assertEquals(4, m.ins);
        assertEquals(2, m.locals);   // .registers 6 - ins 4
        assertTrue(Arrays.equals(new int[]{2, 3, 4, 5}, m.insns.get(0).uses));
    }

    @Test
    public void offsetMapsBackToInstruction() {
        String text = HEAD + DIAMOND;
        MethodIr m = SmaliParser.parse(text).method("f(I)I");
        Insn goTo = null;
        for (Insn in : m.insns) if (in.kind == Insn.Kind.GOTO) goTo = in;
        assertNotNull(goTo);
        int off = text.indexOf("goto :end");
        assertEquals(off, goTo.offset);
        assertSame(goTo, m.insnAtOffset(off + 2));
    }

    @Test
    public void garbageInputNeverThrows() {
        SmaliParser.parse(null);
        SmaliParser.parse("");
        SmaliParser.parse(".method public static x()V\n    const/4\n    invoke-static {v0\n    iget v0\n");
        SmaliParser.parse(HEAD + ".method public a()V\n    .locals 1\n    :x\n    goto :nowhere\n");
    }

    // ---------- CFG ----------

    @Test
    public void diamondCfg() {
        Cfg g = Cfg.build(method(DIAMOND, "f(I)I"));
        assertEquals(4, g.blocks.size());
        Cfg.BasicBlock b0 = g.blocks.get(0), b3 = g.blocks.get(3);
        assertEquals(2, b0.succs.size());
        assertEquals(2, b3.preds.size());
        assertEquals(0, g.idom[3]);                       // the join is dominated by the branch
        assertTrue(g.df[1].contains(3) && g.df[2].contains(3));
        assertTrue(g.backEdges.isEmpty());
        assertTrue(g.dominates(0, 3));
        assertFalse(g.dominates(1, 3));
    }

    @Test
    public void loopCfg() {
        Cfg g = Cfg.build(method(LOOP, "g(I)I"));
        assertEquals(1, g.backEdges.size());
        assertEquals(2, g.backEdges.get(0)[0]);
        assertEquals(1, g.backEdges.get(0)[1]);
        assertTrue(g.loopHeaders.get(1));
    }

    @Test
    public void switchCfg() {
        Cfg g = Cfg.build(method(SWITCH, "s(I)I"));
        assertEquals(4, g.blocks.size());
        assertEquals(3, g.blocks.get(0).succs.size());   // two cases + fall-through (default)
        assertTrue(g.blocks.get(0).succs.stream().anyMatch(e -> (e.kinds & Cfg.K_SWITCH) != 0));
    }

    @Test
    public void tryCatchHasExceptionEdgeAndPseudoBlock() {
        MethodIr m = method(TRY, "h(Ljava/lang/String;)I");
        assertEquals(1, m.catches.size());
        Cfg g = Cfg.build(m);
        Cfg.BasicBlock tryBlock = g.blockOfInsn(1);
        assertTrue(tryBlock.hasExceptionSucc());
        assertTrue(tryBlock.defersLast);                  // the invoke defines v0
        long pseudo = g.blocks.stream().filter(b -> b.pseudo).count();
        assertEquals(1, pseudo);
        Cfg.BasicBlock handler = g.blockOfInsn(3);
        assertEquals(1, handler.preds.size());
        assertTrue(handler.preds.get(0).isOnlyException());
        assertEquals("Ljava/lang/NumberFormatException;", handler.preds.get(0).excType);
    }

    // ---------- SSA ----------

    @Test
    public void diamondGetsOnePhi() {
        SsaForm s = SsaForm.build(method(DIAMOND, "f(I)I"));
        assertEquals(1, s.phiCount());
        SsaForm.Phi p = s.phis[3].get(0);
        assertEquals(2, p.operands.length);
        assertNotNull(p.operands[0]);
        assertNotNull(p.operands[1]);
        assertTrue(p.operands[0] != p.operands[1]);
        // the return reads the phi result
        Insn ret = s.cfg.method.insns.get(4);
        assertSame(p.result, s.usesOf(ret)[0]);
    }

    @Test
    public void loopHeaderPhi() {
        SsaForm s = SsaForm.build(method(LOOP, "g(I)I"));
        assertEquals(1, s.phis[1].size());
        SsaForm.Phi p = s.phis[1].get(0);
        // operand from the entry = the const, operand from the back edge = the add
        boolean sawConst = false, sawAdd = false;
        for (SsaForm.Value v : p.operands) {
            if (v.def != null && v.def.op.equals("const/4")) sawConst = true;
            if (v.def != null && v.def.op.startsWith("add-int")) sawAdd = true;
        }
        assertTrue(sawConst && sawAdd);
        // p0 is read as the parameter (entry value)
        Insn ifge = s.cfg.method.insns.get(1);
        SsaForm.Value pv = s.usesOf(ifge)[1];
        assertTrue(pv.entry && pv.param);
    }

    @Test
    public void handlerSeesValueBeforeTheThrowingInvoke() {
        SsaForm s = SsaForm.build(method(TRY, "h(Ljava/lang/String;)I"));
        MethodIr m = s.cfg.method;
        Insn retNormal = m.insns.get(2), retHandler = m.insns.get(4);
        assertEquals("invoke-static", s.usesOf(retNormal)[0].def.op);   // result of parseInt
        assertEquals("const/4", s.usesOf(retHandler)[0].def.op);        // the old v0
        assertEquals(0, s.phiCount());
    }

    @Test
    public void wideValuesKeepBothHalves() {
        SsaForm s = SsaForm.build(method(WIDE, "foo(JLjava/lang/String;)J"));
        Insn inv = s.cfg.method.insns.get(0);
        assertEquals(2, s.defsOf(inv).length);
        Insn ret = s.cfg.method.insns.get(1);
        assertEquals(2, s.usesOf(ret).length);
        assertSame(s.defsOf(inv)[0], s.usesOf(ret)[0]);
        assertSame(s.defsOf(inv)[1], s.usesOf(ret)[1]);
    }

    @Test
    public void ssaInvariantsHoldOnEveryTestMethod() {
        String[][] cases = {
                {DIAMOND, "f(I)I"}, {LOOP, "g(I)I"}, {TRY, "h(Ljava/lang/String;)I"},
                {SWITCH, "s(I)I"}, {WIDE, "foo(JLjava/lang/String;)J"}
        };
        for (String[] c : cases) {
            SsaForm s = SsaForm.build(method(c[0], c[1]));
            for (java.util.List<SsaForm.Phi> l : s.phis) {
                for (SsaForm.Phi p : l) {
                    assertEquals(p.block.preds.size(), p.operands.length);
                    for (SsaForm.Value v : p.operands) assertNotNull(c[1] + " phi operand", v);
                }
            }
            for (Insn in : s.cfg.method.insns) {
                for (SsaForm.Value v : s.usesOf(in)) assertNotNull(c[1] + " use of " + in, v);
                for (SsaForm.Value v : s.defsOf(in)) assertNotNull(c[1] + " def of " + in, v);
            }
        }
    }

    @Test
    public void emptyMethodAndAbstractMethodBuild() {
        ClassIr c = SmaliParser.parse(HEAD + ".method public abstract z()V\n.end method\n");
        MethodIr m = c.method("z()V");
        assertNotNull(m);
        assertTrue(m.isAbstract());
        SsaForm s = SsaForm.build(m);
        assertEquals(0, s.phiCount());
        assertNull(s.cfg.blockOfInsn(0));
    }
}
