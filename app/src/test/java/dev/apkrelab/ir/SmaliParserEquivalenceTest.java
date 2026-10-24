package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import org.junit.Test;

/**
 * 0.103.0: the allocation work on {@link SmaliParser} (no String for ignorable lines, operands read in place, shared opcode strings and one-register arrays) must not change what
 * the parser returns. {@link SmaliParserRef} is a frozen copy of the parser before that work; every input below is parsed by both and the complete IR is compared (every field
 * of every method and instruction, in order). Inputs: hand-written awkward shapes, a rich seed class mutated 4,000 times with a fixed seed (random deletions, duplicated lines,
 * odd characters, truncation), and the same text parsed from four threads at once.
 */
public class SmaliParserEquivalenceTest {

    private static String dump(ClassIr c) {
        StringBuilder sb = new StringBuilder();
        sb.append("C ").append(c.type).append('|').append(c.superType).append('|').append(c.flags).append('|').append(c.interfaces).append('|').append(c.fields).append('\n');
        for (MethodIr m : c.methods) {
            sb.append("M ").append(m.owner).append('|').append(m.name).append('|').append(m.desc).append('|').append(m.flags).append('|').append(m.isStatic).append('|').append(m.ins).append('|')
                .append(m.locals).append('|').append(m.startOffset).append('|').append(m.startLine).append('\n');
            for (Insn in : m.insns) {
                sb.append(' ').append(in.index).append('|').append(in.op).append('|').append(in.kind).append('|').append(in.offset).append('|').append(in.line).append('|').append(in.text())
                    .append('|').append(in.ref).append('|').append(java.util.Arrays.toString(in.defs)).append('|').append(java.util.Arrays.toString(in.uses)).append('|')
                    .append(java.util.Arrays.toString(in.labels)).append('|').append(in.hasResult).append('\n');
            }
            sb.append(" L ").append(new TreeMap<>(m.labels)).append('\n');
            sb.append(" P ").append(new TreeMap<>(m.payloads)).append('\n');
            for (String[] r : m.rawCatches) sb.append(" R ").append(java.util.Arrays.toString(r)).append('\n');
            for (MethodIr.Catch k : m.catches) sb.append(" K ").append(k.type).append('|').append(k.start).append('|').append(k.end).append('|').append(k.handler).append('\n');
        }
        return sb.toString();
    }

    private static void same(String text) {
        assertEquals("bodies=true", dump(SmaliParserRef.parse(text, true)), dump(SmaliParser.parse(text, true)));
        assertEquals("bodies=false", dump(SmaliParserRef.parse(text, false)), dump(SmaliParser.parse(text, false)));
    }

    private static final String SEED = String.join("\n",
        ".class public final Lcom/example/Pay;", ".super Ljava/lang/Object;", ".source \"Pay.java\"", ".implements Ljava/io/Serializable;", "",
        ".field private static final KEY:Ljava/lang/String; = \"a,b {c} \\\"d\\\"\"", ".field public x:I", "",
        "# a comment between members", ".method public static run(Ljava/lang/String;JI)Ljava/lang/String;",
        "    .locals 6", "    .param p0, \"s\"", "    .annotation runtime Lfoo/Bar;", "        value = \"x, y\"", "    .end annotation", "    .prologue", "    .line 10",
        "    const-string v0, \"he said, \\\"hi {there}\\\"\"", "    const/16 v1, 0x10", "    const-wide/high16 v2, 0x4000000000000000L", "    move-wide v2, p1", "    move-object/from16 v4, p0",
        "    invoke-static {v0, v4}, Lcom/example/Pay;->helper(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", "    move-result-object v0",
        "    invoke-virtual/range {v0 .. v3}, Ljava/lang/String;->foo(IJ)V", "    invoke-direct {}, Lx/Y;-><init>()V",
        "    filled-new-array {v0, v1}, [Ljava/lang/String;", "    move-result-object v5", "    new-array v1, v1, [B", "    fill-array-data v1, :array_0",
        "    iget-object v0, p0, Lcom/example/Pay;->f:Ljava/lang/String;", "    iput-wide v2, p0, Lcom/example/Pay;->w:J", "    sget-object v0, Lcom/example/Pay;->KEY:Ljava/lang/String;",
        "    sput v1, Lcom/example/Pay;->n:I", "    aget-byte v0, v1, v0", "    aput-object v0, v5, v1", "    add-int/2addr v0, v1", "    add-int/lit8 v0, v1, 0x2", "    shl-long/2addr v2, v0",
        "    neg-int v0, v1", "    int-to-long v2, v0", "    long-to-int v0, v2", "    cmp-long v0, v2, v2", "    check-cast v0, Ljava/lang/String;", "    instance-of v0, v0, Ljava/lang/String;",
        "    array-length v0, v1", "    new-instance v0, Ljava/lang/StringBuilder;", "    if-eqz v0, :cond_0", "    if-ne v0, v1, :cond_0", "    goto :goto_0", "    :try_start_0",
        "    monitor-enter p0", "    monitor-exit p0", "    :try_end_0", "    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :handler", "    .catchall {:try_start_0 .. :try_end_0} :handler",
        "    packed-switch v0, :pswitch_data_0", "    :pswitch_0", "    nop", "    :cond_0", "    :goto_0", "    :handler", "    move-exception v0", "    throw v0", "    return-object v0",
        "    :array_0", "    .array-data 1", "        0x1t", "        0x2t", "    .end array-data", "    :pswitch_data_0", "    .packed-switch 0x0", "        :pswitch_0", "    .end packed-switch",
        ".end method", "", ".method private abstract native foo()V", ".end method", "", ".method constructor <init>()V", "    .registers 4", "    return-void", ".end method", "");

    @Test public void hardCasesAreIdentical() {
        same(SEED);
        same("");
        same("\n\n   \n");
        same(".class public Lx/A;\r\n.super Ljava/lang/Object;\r\n.method public a()V\r\n    .locals 1\r\n    const-string v0, \"x,y\"\r\n    return-void\r\n.end method\r\n");   // CRLF
        same(".class Lx/A;\n.method a()V\n\t.locals 2\n\tconst/4\t\tv0,\t0x1\n\tinvoke-static\t{ v0 , v1 }, Lx/A;->b(I)V\n\treturn-void\n.end method");              // tabs
        same(".class Lx/A;\n.method a()V\n  .locals 2\n  const/4 \t v0,\t0x1\n  move \t v1 ,\t v0\n  invoke-static \t {v0}, \t Lx/A;->b()V \u000b\n  return-void \u000c\n.end method\n");   // space + tab, control characters at the ends
        same(".class Lx/A;\n.method a()V\n  .locals 2\n  invoke-static {v0,,v1,vx,v99999,p0,p}, Lx/A;->b(II)V\n  move-result v0\n  invoke-virtual/range {v0 .. } , Lx/A;->c()V\n.end method\n");
        same(".class Lx/A;\n.method a()V\n  .locals 2\n  invoke-static {v0 .. v1 .. v2}, Lx/A;->b()V\n  invoke-static {.. v1}, Lx/A;->c()V\n  invoke-static {v1 ..}, Lx/A;->d()V\n  invoke-static {v0}, ,Lx/A;->e()V\n.end method\n");
        same(".class Lx/A;\n.method a()V\n  .locals 2\n  const-string v0, \"unterminated, {\n  const-string v1, \"a\\\\\", v0\n  return-void\n");                                     // unterminated string, no .end method
        same(".class Lx/A;\n.method a()V\n  .locals 2\n  .line 5\n  .local v0, \"x\":I\n  .restart local v0\n  .end local v0\n  .line\n  .locals\n  .locals x\n  .catch\n  .catchall {a .. b}\n.end method\n");
        same(".class Lx/A;\n.method a()V\n  .locals 2\n  :try_start_0\n  nop\n  :try_end_0\n  .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :h\n  :h\n  move-exception v0\n.end method\n");
        same(".class Lx/A;\n.method a()V\n .locals 1\n invoke-static {v0}, Lx/A;->b()V\n move-result\n move-result-wide v0\n .end method\n");
        same(".class Lx/A;\n.method a()V\n  .locals 300\n  const v299, 0x1\n  move v300, v299\n  add-int v256, v255, v257\n.end method\n");                                      // registers above 255
        same(".class Lx/A;\n.method a()V\n  .locals 1\n  .annotation build Lx/Y;\n    k = {\n      \"a\", \"b\"\n    }\n  .end annotation\n  const/4 v0, 0x0\n.end method\n");
    }

    private static String mutate(String s, Random r) {
        StringBuilder sb = new StringBuilder(s);
        String odd = ",{}\" \t\r\\.:vp0123456789-/;<>#=\n";
        int k = 1 + r.nextInt(4);
        for (int i = 0; i < k; i++) {
            int at = sb.length() == 0 ? 0 : r.nextInt(sb.length());
            switch (r.nextInt(6)) {
                case 0: sb.delete(at, Math.min(sb.length(), at + 1 + r.nextInt(12))); break;
                case 1: sb.insert(at, odd.charAt(r.nextInt(odd.length()))); break;
                case 2: { int a = sb.lastIndexOf("\n", at) + 1, b = sb.indexOf("\n", at); if (b < 0) b = sb.length(); if (b >= a) sb.insert(b, "\n" + sb.substring(a, b)); break; }   // duplicate a line
                case 3: sb.setLength(Math.max(0, at)); break;                                                                                                                 // truncate
                case 4: sb.insert(at, "\n"); break;
                default: sb.insert(at, "  \t"); break;
            }
        }
        return sb.toString();
    }

    @Test public void fourThousandMutationsOfARichClassAreIdentical() {
        Random r = new Random(20261024L);
        int diff = 0; String first = null;
        for (int i = 0; i < 4000; i++) {
            String t = mutate(SEED, r);
            String a = dump(SmaliParserRef.parse(t, true)), b = dump(SmaliParser.parse(t, true));
            if (!a.equals(b)) { diff++; if (first == null) first = t; }
            if (i % 8 == 0) assertEquals(dump(SmaliParserRef.parse(t, false)), dump(SmaliParser.parse(t, false)));
        }
        assertEquals("inputs where the two parsers differ (first: " + first + ")", 0, diff);
    }

    @Test public void theSharedOpcodeTableIsSafeAcrossThreads() throws Exception {
        final String want = dump(SmaliParserRef.parse(SEED, true));
        final List<Throwable> bad = new ArrayList<>();
        List<Thread> ts = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
            Thread th = new Thread(() -> {
                try { for (int i = 0; i < 300; i++) assertEquals(want, dump(SmaliParser.parse(SEED, true))); } catch (Throwable e) { synchronized (bad) { bad.add(e); } }
            });
            ts.add(th); th.start();
        }
        for (Thread th : ts) th.join();
        assertTrue("threads disagreed: " + bad, bad.isEmpty());
    }

    @Test public void ignorableLinesChangeNothingAndSingleRegisterArraysAreShared() {
        String body = ".class Lx/A;\n.method a(I)V\n  .locals 2\n  const/4 v0, 0x1\n  return-void\n.end method\n";
        String noisy = ".class Lx/A;\n.method a(I)V\n  .locals 2\n  .line 1\n  # c\n  .prologue\n  const/4 v0, 0x1\n  .local v0, \"n\":I\n  return-void\n.end method\n";
        MethodIr a = SmaliParser.parse(body).methods.get(0), b = SmaliParser.parse(noisy).methods.get(0);
        assertEquals(a.insns.size(), b.insns.size());
        assertEquals(java.util.Arrays.toString(a.insns.get(0).defs), java.util.Arrays.toString(b.insns.get(0).defs));
        assertTrue(a.insns.get(0).defs == b.insns.get(0).defs);                       // the one-register array is the same object
        assertTrue(a.insns.get(0).op == b.insns.get(0).op);                           // and so is the opcode string
    }
}
