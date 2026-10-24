package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

/**
 * 0.53.0 (P0): control-flow graph of ONE method.
 *
 * Blocks split at branch targets, after every branch / return / throw, at catch handlers and at try-range borders. Inside a
 * try range every instruction that can throw ends its block, so a block has at most one throwing instruction and it is the
 * LAST one; the exception edge therefore leaves the block "before the last instruction takes effect".
 *
 * Exception edges and defining instructions: when such a last instruction defines registers (an invoke with a result, an
 * iget ...), its definitions must NOT be visible in the handler. For that the CFG puts a tiny PSEUDO block between the
 * block and its normal successor; the pseudo block carries the definitions ({@link BasicBlock#deferredFrom}). SSA and any other
 * dataflow treat the pseudo block as the place where those registers are written.
 *
 * Also computed (for reachable blocks): reverse post-order, immediate dominators (Cooper-Harvey-Kennedy), dominance frontiers,
 * back edges and loop headers.
 */
public final class Cfg {

    public static final int K_FALL = 1, K_GOTO = 2, K_TRUE = 4, K_FALSE = 8, K_SWITCH = 16, K_EXC = 32;

    public static final class Edge {
        public final BasicBlock from, to;
        public int kinds;
        public String excType;   // first caught type of an exception edge (null = catch-all or not an exception edge)
        public int predIdx;      // position of this edge in to.preds (valid after build)

        Edge(BasicBlock from, BasicBlock to, int kinds) {
            this.from = from;
            this.to = to;
            this.kinds = kinds;
        }

        public boolean isException() {
            return (kinds & K_EXC) != 0;
        }

        /** An edge that carries only the exception path (not also a normal transfer). */
        public boolean isOnlyException() {
            return kinds == K_EXC;
        }
    }

    public static final class BasicBlock {
        public final int id;
        public final int first, last;     // instruction index range, inclusive; last < first for an empty / pseudo block
        public final boolean pseudo;
        public Insn deferredFrom;         // pseudo block: the instruction whose results are written here
        public boolean defersLast;        // real block: its last instruction's defs live in the pseudo successor
        public final List<Edge> succs = new ArrayList<>();
        public final List<Edge> preds = new ArrayList<>();
        public boolean reachable;

        BasicBlock(int id, int first, int last, boolean pseudo) {
            this.id = id;
            this.first = first;
            this.last = last;
            this.pseudo = pseudo;
        }

        public int size() {
            return last < first ? 0 : last - first + 1;
        }

        public boolean hasExceptionSucc() {
            for (Edge e : succs) if (e.isException()) return true;
            return false;
        }

        @Override
        public String toString() {
            return "B" + id + (pseudo ? "*" : "") + "[" + first + ".." + last + "]";
        }
    }

    public final MethodIr method;
    public final List<BasicBlock> blocks = new ArrayList<>();
    public BasicBlock entry;
    public int[] rpo = new int[0];        // reachable block ids in reverse post-order
    public int[] idom = new int[0];       // block id -> immediate dominator id (entry -> itself, unreachable -> -1)
    public List<Integer>[] domChildren;
    public List<Integer>[] df;            // dominance frontier per block id
    public final List<int[]> backEdges = new ArrayList<>();   // {from, to} where "to" dominates "from"
    public final BitSet loopHeaders = new BitSet();
    private int[] blockOf = new int[0];   // instruction index -> block id (real blocks)

    private Cfg(MethodIr m) {
        this.method = m;
    }

    public BasicBlock blockOfInsn(int insnIndex) {
        return insnIndex >= 0 && insnIndex < blockOf.length ? blocks.get(blockOf[insnIndex]) : null;
    }

    public boolean dominates(int a, int b) {
        if (a < 0 || b < 0 || idom[b] < 0 || idom[a] < 0) return false;
        int x = b;
        while (true) {
            if (x == a) return true;
            int p = idom[x];
            if (p == x) return false;
            x = p;
        }
    }

    // ---------- construction ----------

    @SuppressWarnings("unchecked")
    public static Cfg build(MethodIr m) {
        Cfg g = new Cfg(m);
        int n = m.insns.size();
        if (n == 0) {
            BasicBlock b = new BasicBlock(0, 0, -1, false);
            g.blocks.add(b);
            g.entry = b;
            g.blockOf = new int[0];
            g.finish();
            return g;
        }
        boolean[] leader = new boolean[n + 1];
        leader[0] = true;
        for (int i = 0; i < n; i++) {
            Insn in = m.insns.get(i);
            switch (in.kind) {
                case GOTO:
                case IF: {
                    for (String l : in.labels) mark(leader, m.labelIndex(l), n);
                    if (i + 1 < n) leader[i + 1] = true;
                    break;
                }
                case SWITCH: {
                    for (int t : switchTargets(m, in)) mark(leader, t, n);
                    if (i + 1 < n) leader[i + 1] = true;
                    break;
                }
                case RETURN:
                case THROW:
                    if (i + 1 < n) leader[i + 1] = true;
                    break;
                default:
                    break;
            }
        }
        for (MethodIr.Catch c : m.catches) {
            mark(leader, c.start, n);
            mark(leader, c.end, n);
            mark(leader, c.handler, n);
            for (int i = c.start; i < c.end && i < n; i++) {
                if (m.insns.get(i).canThrow() && i + 1 < n) leader[i + 1] = true;
            }
        }
        g.blockOf = new int[n];
        int start = 0;
        for (int i = 1; i <= n; i++) {
            if (i == n || leader[i]) {
                BasicBlock b = new BasicBlock(g.blocks.size(), start, i - 1, false);
                for (int k = start; k < i; k++) g.blockOf[k] = b.id;
                g.blocks.add(b);
                start = i;
            }
        }
        g.entry = g.blocks.get(0);

        // normal edges
        for (BasicBlock b : new ArrayList<>(g.blocks)) {
            Insn last = m.insns.get(b.last);
            BasicBlock next = b.last + 1 < n ? g.blocks.get(g.blockOf[b.last + 1]) : null;
            switch (last.kind) {
                case GOTO: {
                    BasicBlock t = g.target(last.labels.length > 0 ? last.labels[0] : null);
                    if (t != null) g.edge(b, t, K_GOTO);
                    break;
                }
                case IF: {
                    BasicBlock t = g.target(last.labels.length > 0 ? last.labels[0] : null);
                    if (t != null) g.edge(b, t, K_TRUE);
                    if (next != null) g.edge(b, next, K_FALSE);
                    break;
                }
                case SWITCH: {
                    for (int t : switchTargets(m, last)) {
                        if (t >= 0 && t < n) g.edge(b, g.blocks.get(g.blockOf[t]), K_SWITCH);
                    }
                    if (next != null) g.edge(b, next, K_FALL);
                    break;
                }
                case RETURN:
                case THROW:
                    break;
                default:
                    if (next != null) g.edge(b, next, K_FALL);
                    break;
            }
        }

        // exception edges
        for (BasicBlock b : new ArrayList<>(g.blocks)) {
            boolean throwing = false;
            for (int i = b.first; i <= b.last; i++) {
                if (m.insns.get(i).canThrow()) {
                    throwing = true;
                    break;
                }
            }
            if (!throwing) continue;
            for (MethodIr.Catch c : m.catches) {
                if (b.first >= c.start && b.first < c.end) {
                    Edge e = g.edge(b, g.blocks.get(g.blockOf[c.handler]), K_EXC);
                    if (e.excType == null) e.excType = c.type;
                }
            }
        }

        // pseudo blocks that keep the defs of a throwing last instruction away from the handlers
        for (BasicBlock b : new ArrayList<>(g.blocks)) {
            if (!b.hasExceptionSucc()) continue;
            Insn last = m.insns.get(b.last);
            if (last.defs.length == 0) continue;
            List<Edge> normal = new ArrayList<>();
            for (Edge e : b.succs) if (!e.isOnlyException()) normal.add(e);
            if (normal.isEmpty()) continue;
            BasicBlock p = new BasicBlock(g.blocks.size(), b.last + 1, b.last, true);
            p.deferredFrom = last;
            g.blocks.add(p);
            b.defersLast = true;
            for (Edge e : normal) {
                b.succs.remove(e);
                e.to.preds.remove(e);
                Edge pe = new Edge(p, e.to, e.kinds & ~K_EXC);
                p.succs.add(pe);
                e.to.preds.add(pe);
                if ((e.kinds & K_EXC) != 0) { // mixed edge: keep its exception part on b
                    Edge ex = new Edge(b, e.to, K_EXC);
                    ex.excType = e.excType;
                    b.succs.add(ex);
                    e.to.preds.add(ex);
                }
            }
            Edge bp = new Edge(b, p, K_FALL);
            b.succs.add(bp);
            p.preds.add(bp);
        }
        g.finish();
        return g;
    }

    private static void mark(boolean[] leader, int idx, int n) {
        if (idx >= 0 && idx < n) leader[idx] = true;
    }

    /** Instruction indexes of a switch's cases (payload order). */
    static int[] switchTargets(MethodIr m, Insn sw) {
        if (sw.labels.length == 0) return new int[0];
        List<String> ls = m.payloads.get(sw.labels[0]);
        if (ls == null) return new int[0];
        int[] out = new int[ls.size()];
        for (int i = 0; i < out.length; i++) out[i] = m.labelIndex(ls.get(i));
        return out;
    }

    private BasicBlock target(String label) {
        if (label == null) return null;
        int t = method.labelIndex(label);
        return (t >= 0 && t < blockOf.length) ? blocks.get(blockOf[t]) : null;
    }

    private Edge edge(BasicBlock from, BasicBlock to, int kind) {
        for (Edge e : from.succs) {
            if (e.to == to) {
                e.kinds |= kind;
                return e;
            }
        }
        Edge e = new Edge(from, to, kind);
        from.succs.add(e);
        to.preds.add(e);
        return e;
    }

    // ---------- analyses ----------

    @SuppressWarnings("unchecked")
    private void finish() {
        int nb = blocks.size();

        // iterative DFS -> post order
        int[] post = new int[nb];
        int[] postNum = new int[nb];
        Arrays.fill(postNum, -1);
        int cnt = 0;
        boolean[] seen = new boolean[nb];
        int[] stack = new int[nb + 1];
        int[] itr = new int[nb];
        int sp = 0;
        stack[sp++] = entry.id;
        seen[entry.id] = true;
        while (sp > 0) {
            int b = stack[sp - 1];
            List<Edge> ss = blocks.get(b).succs;
            if (itr[b] < ss.size()) {
                int t = ss.get(itr[b]++).to.id;
                if (!seen[t]) {
                    seen[t] = true;
                    stack[sp++] = t;
                }
            } else {
                postNum[b] = cnt;
                post[cnt++] = b;
                sp--;
            }
        }
        rpo = new int[cnt];
        for (int i = 0; i < cnt; i++) rpo[i] = post[cnt - 1 - i];
        for (BasicBlock b : blocks) b.reachable = seen[b.id];
        // 0.53.1: an edge that comes from unreachable (dead) code is not a predecessor: nothing ever flows along it, so no phi
        // operand could be filled for it. The edge stays in the dead block's succs list, only the successor forgets it.
        for (BasicBlock b : blocks) {
            if (!b.reachable) continue;
            for (int i = b.preds.size() - 1; i >= 0; i--) if (!b.preds.get(i).from.reachable) b.preds.remove(i);
        }
        for (BasicBlock b : blocks) for (int i = 0; i < b.preds.size(); i++) b.preds.get(i).predIdx = i;

        // Cooper-Harvey-Kennedy
        idom = new int[nb];
        Arrays.fill(idom, -1);
        idom[entry.id] = entry.id;
        boolean changed = true;
        while (changed) {
            changed = false;
            for (int i = 1; i < cnt; i++) {
                int b = rpo[i];
                int nw = -1;
                for (Edge e : blocks.get(b).preds) {
                    int p = e.from.id;
                    if (idom[p] < 0) continue;
                    nw = nw < 0 ? p : intersect(nw, p, postNum);
                }
                if (nw >= 0 && idom[b] != nw) {
                    idom[b] = nw;
                    changed = true;
                }
            }
        }

        domChildren = new List[nb];
        df = new List[nb];
        for (int i = 0; i < nb; i++) {
            domChildren[i] = new ArrayList<>();
            df[i] = new ArrayList<>();
        }
        for (int i = 1; i < cnt; i++) {
            int b = rpo[i];
            if (idom[b] >= 0 && idom[b] != b) domChildren[idom[b]].add(b);
        }
        for (int i = 0; i < cnt; i++) {
            int b = rpo[i];
            BasicBlock bb = blocks.get(b);
            int reachablePreds = 0;
            for (Edge e : bb.preds) if (idom[e.from.id] >= 0) reachablePreds++;
            if (reachablePreds < 2) continue;
            for (Edge e : bb.preds) {
                int runner = e.from.id;
                if (idom[runner] < 0) continue;
                while (runner != idom[b]) {
                    if (!df[runner].contains(b)) df[runner].add(b);
                    if (idom[runner] == runner) break;
                    runner = idom[runner];
                }
            }
        }
        backEdges.clear();
        loopHeaders.clear();
        for (int i = 0; i < cnt; i++) {
            BasicBlock bb = blocks.get(rpo[i]);
            for (Edge e : bb.succs) {
                if (dominates(e.to.id, bb.id)) {
                    backEdges.add(new int[]{bb.id, e.to.id});
                    loopHeaders.set(e.to.id);
                }
            }
        }
    }

    private int intersect(int a, int b, int[] postNum) {
        while (a != b) {
            while (postNum[a] < postNum[b]) a = idom[a];
            while (postNum[b] < postNum[a]) b = idom[b];
        }
        return a;
    }

    /** Human readable dump used by tests and debugging. */
    public String dump() {
        StringBuilder sb = new StringBuilder();
        for (BasicBlock b : blocks) {
            sb.append(b).append(b.reachable ? "" : " (unreachable)").append(" ->");
            for (Edge e : b.succs) sb.append(" B").append(e.to.id).append('(').append(kindName(e.kinds)).append(')');
            sb.append('\n');
        }
        return sb.toString();
    }

    public static String kindName(int k) {
        StringBuilder s = new StringBuilder();
        if ((k & K_FALL) != 0) s.append("fall,");
        if ((k & K_GOTO) != 0) s.append("goto,");
        if ((k & K_TRUE) != 0) s.append("true,");
        if ((k & K_FALSE) != 0) s.append("false,");
        if ((k & K_SWITCH) != 0) s.append("switch,");
        if ((k & K_EXC) != 0) s.append("exc,");
        return s.length() == 0 ? "" : s.substring(0, s.length() - 1);
    }
}
