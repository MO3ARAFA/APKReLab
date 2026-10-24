package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/** 0.104.3: an instruction keeps its line as (shared head, shared reference); the engine's cached SSA form keeps compact read-only edge / phi lists. Nothing a reader sees changes. */
public class IrInsnCompactTest {
    private static final String CLS = ".class public Lt/A;\n.super Ljava/lang/Object;\n"
            + ".method public static f(Ljava/lang/String;)I\n    .locals 3\n"
            + "    const-string v0, \"https://example.org/a\"\n"
            + "    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n    move-result v1\n"
            + "    if-eqz v1, :a\n    sget-object v2, Ljava/lang/System;->out:Ljava/io/PrintStream;\n"
            + "    invoke-virtual {v2, p0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V\n    const/4 v1, 0x1\n    goto :b\n"
            + "    :a\n    const/4 v1, 0x2\n    :b\n    return v1\n.end method\n";

    private static List<String> lines(String cls) {
        List<String> out = new ArrayList<>();
        for (String l : cls.split("\n")) {
            String t = l.trim();
            if (t.isEmpty() || t.startsWith(".") || t.startsWith(":") || t.startsWith("move-result")) continue;
            out.add(t);
        }
        return out;
    }

    @Test
    public void textIsTheSourceLineExactlyAndTheRepeatedPartsAreShared() {
        MethodIr m1 = SmaliParser.parse(CLS).methods.get(0), m2 = SmaliParser.parse(CLS).methods.get(0);
        List<String> want = lines(CLS);
        assertEquals(want.size(), m1.insns.size());
        for (int i = 0; i < want.size(); i++) assertEquals(want.get(i), m1.insns.get(i).text());     // the line, character for character
        Insn call1 = m1.insns.get(1), call2 = m2.insns.get(1);
        assertEquals("Ljava/lang/String;->startsWith(Ljava/lang/String;)Z", call1.ref);
        assertSame(call1.ref, call2.ref);                       // two parses of the same class: one copy of the reference ...
        assertEquals(":a", m1.insns.get(2).labels[0]);
        assertSame(m1.insns.get(2).labels[0], m2.insns.get(2).labels[0]);   // ... and of a label
    }

    @Test
    public void theSharedTableNeverReturnsADifferentString() {
        // "Aa" and "BB" have the same hashCode: the same slot. Each must come back as itself (equal), never as the other.
        assertEquals("Aa".hashCode(), "BB".hashCode());
        String a = new String("Aa"), b = new String("BB");
        assertEquals("Aa", Canon.of(a)); assertEquals("BB", Canon.of(b)); assertEquals("Aa", Canon.of(new String("Aa")));
        String c1 = new String("Lt/Shared;->x()V"), c2 = new String("Lt/Shared;->x()V");
        assertSame(Canon.of(c1), Canon.of(c2));                 // equal strings in a row: one copy
    }

    @Test
    public void theCachedFormHasCompactReadOnlyListsWithTheSameEdges() {
        MethodIr m1 = SmaliParser.parse(CLS).methods.get(0), m2 = SmaliParser.parse(CLS).methods.get(0);
        SsaForm plain = SsaForm.build(m1), cached = SsaForm.buildCached(m2);
        assertEquals(plain.cfg.blocks.size(), cached.cfg.blocks.size());
        boolean sawOne = false;
        for (int i = 0; i < plain.cfg.blocks.size(); i++) {
            Cfg.BasicBlock p = plain.cfg.blocks.get(i), c = cached.cfg.blocks.get(i);
            assertEquals(p.succs.size(), c.succs.size()); assertEquals(p.preds.size(), c.preds.size());
            for (int k = 0; k < p.preds.size(); k++) {
                assertEquals(p.preds.get(k).from.id, c.preds.get(k).from.id);     // same order: phi operand k is predecessor k
                assertEquals(k, c.preds.get(k).predIdx);
            }
            for (int k = 0; k < p.succs.size(); k++) assertEquals(p.succs.get(k).to.id, c.succs.get(k).to.id);
            assertFalse(c.succs instanceof ArrayList); assertFalse(c.preds instanceof ArrayList); assertFalse(cached.phis[i] instanceof ArrayList);
            assertTrue(p.succs instanceof ArrayList);           // twin: a CFG built directly keeps its growable lists
            if (c.preds.size() == 1) sawOne = true;
        }
        assertTrue(sawOne);
        try {
            cached.cfg.blocks.get(1).preds.add(null);
            throw new IllegalStateException("a cached edge list must be read-only");
        } catch (UnsupportedOperationException expected) {
        }
    }
}
