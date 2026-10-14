package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.Test;

/**
 * 0.53.1: random smali (branches both ways, packed/sparse switches, nested and overlapping try ranges, wide registers,
 * range invokes, throw/return mixes) pushed through {@link IrStress}. Real code is the real test, but this catches crashes
 * and malformed SSA before a device run. Seeded, so a failure is reproducible.
 */
public class IrFuzzTest {

    private static final class Gen {
        final Random rnd;
        final StringBuilder sb = new StringBuilder();
        int nlabels;

        Gen(long seed) {
            rnd = new Random(seed);
        }

        int v() {
            return rnd.nextInt(8);
        }

        int w() {
            return rnd.nextInt(4) * 2;
        }

        String lab(int k) {
            return ":L" + k;
        }

        String method(int id) {
            sb.setLength(0);
            int stmts = 3 + rnd.nextInt(rnd.nextInt(10) == 0 ? 400 : 40);
            nlabels = 1 + rnd.nextInt(Math.max(2, stmts / 3));
            // where each label goes: before statement index (stmts = at the very end)
            int[] at = new int[nlabels];
            for (int i = 0; i < nlabels; i++) at[i] = rnd.nextInt(stmts + 1);
            List<String> payloads = new ArrayList<>();
            sb.append(".method public static m").append(id).append("(IJLjava/lang/String;)I\n    .locals 8\n");
            // try ranges: (start stmt, end stmt, handler label)
            int tries = rnd.nextInt(4);
            int[][] tr = new int[tries][3];
            for (int i = 0; i < tries; i++) {
                tr[i][0] = rnd.nextInt(stmts);
                tr[i][1] = Math.min(stmts, tr[i][0] + 1 + rnd.nextInt(12));
                tr[i][2] = rnd.nextInt(nlabels);
            }
            for (int s = 0; s <= stmts; s++) {
                for (int i = 0; i < nlabels; i++) if (at[i] == s) sb.append("    ").append(lab(i)).append('\n');
                for (int i = 0; i < tries; i++) {
                    if (tr[i][0] == s) sb.append("    :ts").append(i).append('\n');
                    if (tr[i][1] == s) {
                        sb.append("    :te").append(i).append('\n');
                        sb.append(rnd.nextBoolean()
                                ? "    .catch Ljava/lang/Exception; {:ts" + i + " .. :te" + i + "} " + lab(tr[i][2]) + "\n"
                                : "    .catchall {:ts" + i + " .. :te" + i + "} " + lab(tr[i][2]) + "\n");
                    }
                }
                if (s == stmts) break;
                stmt(payloads);
            }
            sb.append("    return v0\n");
            for (String p : payloads) sb.append(p);
            sb.append(".end method\n");
            return sb.toString();
        }

        void stmt(List<String> payloads) {
            int k = rnd.nextInt(26);
            String l = lab(rnd.nextInt(nlabels));
            switch (k) {
                case 0: sb.append("    const/4 v").append(v()).append(", 0x1\n"); break;
                case 1: sb.append("    const-wide/16 v").append(w()).append(", 0x5\n"); break;
                case 2: sb.append("    const-string v").append(v()).append(", \"a, b {c}\"\n"); break;
                case 3: sb.append("    move v").append(v()).append(", v").append(v()).append('\n'); break;
                case 4: sb.append("    move-wide v").append(w()).append(", v").append(w()).append('\n'); break;
                case 5: sb.append("    add-int v").append(v()).append(", v").append(v()).append(", v").append(v()).append('\n'); break;
                case 6: sb.append("    add-long v").append(w()).append(", v").append(w()).append(", v").append(w()).append('\n'); break;
                case 7: sb.append("    add-int/2addr v").append(v()).append(", v").append(v()).append('\n'); break;
                case 8: sb.append("    shl-long v").append(w()).append(", v").append(w()).append(", v").append(v()).append('\n'); break;
                case 9: sb.append("    int-to-long v").append(w()).append(", v").append(v()).append('\n'); break;
                case 10: sb.append("    invoke-static {v").append(v()).append(", v").append(v()).append("}, Lt/Z;->f(II)I\n    move-result v")
                        .append(v()).append('\n'); break;
                case 11: sb.append("    invoke-virtual/range {v0 .. v3}, Lt/Z;->g(III)V\n"); break;
                case 12: sb.append("    invoke-direct {v").append(v()).append("}, Lt/Z;-><init>()V\n"); break;
                case 13: sb.append("    iget v").append(v()).append(", v").append(v()).append(", Lt/Z;->a:I\n"); break;
                case 14: sb.append("    sput-wide v").append(w()).append(", Lt/Z;->b:J\n"); break;
                case 15: sb.append("    aget v").append(v()).append(", v").append(v()).append(", v").append(v()).append('\n'); break;
                case 16: sb.append("    new-instance v").append(v()).append(", Lt/Z;\n"); break;
                case 17: sb.append("    check-cast v").append(v()).append(", Lt/Z;\n"); break;
                case 18: sb.append("    cmp-long v").append(v()).append(", v").append(w()).append(", v").append(w()).append('\n'); break;
                case 19: sb.append("    if-eqz v").append(v()).append(", ").append(l).append('\n'); break;
                case 20: sb.append("    if-lt v").append(v()).append(", v").append(v()).append(", ").append(l).append('\n'); break;
                case 21: sb.append("    goto ").append(l).append('\n'); break;
                case 22: {
                    int id = payloads.size();
                    boolean packed = rnd.nextBoolean();
                    sb.append("    ").append(packed ? "packed" : "sparse").append("-switch v").append(v()).append(", :P").append(id).append('\n');
                    StringBuilder p = new StringBuilder("    :P").append(id).append('\n');
                    int n = 1 + rnd.nextInt(5);
                    p.append(packed ? "    .packed-switch 0x0\n" : "    .sparse-switch\n");
                    for (int i = 0; i < n; i++) p.append("        ").append(packed ? "" : "0x" + i + " -> ").append(lab(rnd.nextInt(nlabels))).append('\n');
                    p.append(packed ? "    .end packed-switch\n" : "    .end sparse-switch\n");
                    payloads.add(p.toString());
                    break;
                }
                case 23: sb.append("    move-exception v").append(v()).append('\n'); break;
                case 24: sb.append(rnd.nextInt(4) == 0 ? "    throw v" + v() + "\n" : "    return v" + v() + "\n"); break;
                default: sb.append("    nop\n"); break;
            }
        }
    }

    @Test
    public void fuzzedMethodsNeverBreakTheIr() {
        final List<String> classes = new ArrayList<>();
        int id = 0;
        int count = Integer.getInteger("irfuzz.classes", 60);
        for (int c = 0; c < count; c++) {
            Gen g = new Gen(1000 + c);
            StringBuilder cls = new StringBuilder(".class public Lt/F" + c + ";\n.super Ljava/lang/Object;\n\n");
            for (int m = 0; m < 50; m++) cls.append(g.method(id++)).append('\n');
            classes.add(cls.toString());
        }
        IrStress.Report r = IrStress.run(classes.size(), i -> classes.get(i));
        if (!r.clean()) System.out.println(r.format());
        assertEquals(count * 50, r.methods);
        assertTrue("failures:\n" + r.format(), r.clean());
        assertEquals(r.methods - r.methodsNoBody, r.methodsBuilt);
    }
}
