package dev.apkrelab.ir;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Deque;
import java.util.List;

/**
 * 0.53.0 (P0): semi-pruned SSA form of one method (Briggs et al.: phi nodes only for registers that are live across blocks;
 * placement with the iterated dominance frontier, renaming by a dominator-tree walk, done with an explicit stack so a
 * method with thousands of blocks cannot overflow the stack).
 *
 * A {@link Value} is "register r, version k". Version 0 of a register is its value at method entry: the incoming parameter
 * (p-registers) or "undefined" (v-registers that are read before any write). Wide values appear as two Values (both halves).
 *
 * Exception edges: the handler sees the registers as they were BEFORE the throwing instruction (the CFG moved that
 * instruction's definitions into a pseudo block, see {@link Cfg}).
 *
 * Limit: when one (from, to) pair is both a normal and an exception edge (very rare) the normal state is used.
 */
public final class SsaForm {

    public static final class Value {
        public final int reg;
        public final int version;
        public final Insn def;       // defining instruction, or null (phi / method entry)
        public final Phi phi;        // defining phi, or null
        public final boolean entry;  // version 0: parameter or undefined
        public final boolean param;  // entry value of a p-register

        Value(int reg, int version, Insn def, Phi phi, boolean entry, boolean param) {
            this.reg = reg;
            this.version = version;
            this.def = def;
            this.phi = phi;
            this.entry = entry;
            this.param = param;
        }

        @Override
        public String toString() {
            return "r" + reg + "_" + version;
        }
    }

    public static final class Phi {
        public final Cfg.BasicBlock block;
        public final int reg;
        public Value result;
        public final Value[] operands;   // aligned with block.preds (Edge.predIdx)

        Phi(Cfg.BasicBlock block, int reg, int npreds) {
            this.block = block;
            this.reg = reg;
            this.operands = new Value[npreds];
        }
    }

    public final Cfg cfg;
    public final List<Phi>[] phis;        // per block id
    public final Value[][] defs;          // per instruction index, aligned with Insn.defs (null for unreachable code)
    public final Value[][] uses;          // per instruction index, aligned with Insn.uses (null for unreachable code)

    @SuppressWarnings("unchecked")
    private SsaForm(Cfg cfg) {
        this.cfg = cfg;
        int nb = cfg.blocks.size();
        phis = new List[nb];
        for (int i = 0; i < nb; i++) phis[i] = new ArrayList<>();
        int n = cfg.method.insns.size();
        defs = new Value[n][];
        uses = new Value[n][];
    }

    public static SsaForm build(Cfg cfg) {
        SsaForm s = new SsaForm(cfg);
        s.place();
        s.rename();
        return s;
    }

    public static SsaForm build(MethodIr m) {
        return build(Cfg.build(m));
    }

    /**
     * 0.60.0: same result as {@link #build(MethodIr)}, built once per method object. The form is read-only after build, so sharing it between
     * the re-runs of the worklist and between groups (or threads) that hold the same parsed method is safe.
     */
    public static SsaForm buildCached(MethodIr m) {
        java.lang.ref.SoftReference<SsaForm> r = m.ssaRef;
        SsaForm s = r == null ? null : r.get();
        if (s != null) return s;
        s = build(m);
        s.cfg.releaseConstruction();                 // 0.104.2: what only the construction needed (see Cfg.releaseConstruction)
        for (List<Phi> l : s.phis) if (l instanceof ArrayList) ((ArrayList<Phi>) l).trimToSize();
        m.ssaRef = new java.lang.ref.SoftReference<>(s);
        return s;
    }

    public int phiCount() {
        int c = 0;
        for (List<Phi> l : phis) c += l.size();
        return c;
    }

    // ---------- phi placement ----------

    private int regLimit() {
        int mx = cfg.method.registerCount();
        for (Insn in : cfg.method.insns) {
            for (int r : in.defs) if (r + 1 > mx) mx = r + 1;
            for (int r : in.uses) if (r + 1 > mx) mx = r + 1;
        }
        return mx;
    }

    private int regCount;

    private void place() {
        regCount = regLimit();
        int nb = cfg.blocks.size();
        BitSet globals = new BitSet(regCount);
        BitSet[] defBlocks = new BitSet[regCount];
        for (int bi : cfg.rpo) {
            Cfg.BasicBlock b = cfg.blocks.get(bi);
            BitSet killed = new BitSet(regCount);
            if (b.pseudo) {
                for (int r : b.deferredFrom.defs) addDef(defBlocks, r, b.id, nb);
                continue;
            }
            for (int i = b.first; i <= b.last; i++) {
                Insn in = cfg.method.insns.get(i);
                for (int r : in.uses) if (!killed.get(r)) globals.set(r);
                boolean deferred = b.defersLast && i == b.last;
                if (deferred) continue;
                for (int r : in.defs) {
                    killed.set(r);
                    addDef(defBlocks, r, b.id, nb);
                }
            }
        }
        BitSet hasPhi = new BitSet(nb);
        BitSet queued = new BitSet(nb);
        for (int r = globals.nextSetBit(0); r >= 0; r = globals.nextSetBit(r + 1)) {
            if (defBlocks[r] == null) continue;
            hasPhi.clear();
            queued.clear();
            Deque<Integer> work = new ArrayDeque<>();
            for (int b = defBlocks[r].nextSetBit(0); b >= 0; b = defBlocks[r].nextSetBit(b + 1)) {
                work.add(b);
                queued.set(b);
            }
            while (!work.isEmpty()) {
                int b = work.poll();
                for (int d : cfg.df[b]) {
                    if (hasPhi.get(d)) continue;
                    hasPhi.set(d);
                    Cfg.BasicBlock db = cfg.blocks.get(d);
                    phis[d].add(new Phi(db, r, db.preds.size()));
                    if (!queued.get(d)) {
                        queued.set(d);
                        work.add(d);
                    }
                }
            }
        }
    }

    private static void addDef(BitSet[] defBlocks, int r, int block, int nb) {
        if (defBlocks[r] == null) defBlocks[r] = new BitSet(nb);
        defBlocks[r].set(block);
    }

    // ---------- renaming ----------

    private int[] counter;
    private Value[] entryValues;
    private ArrayList<Value>[] stacks;

    private Value top(int r) {
        ArrayList<Value> s = stacks[r];
        if (!s.isEmpty()) return s.get(s.size() - 1);
        Value e = entryValues[r];
        if (e == null) {
            e = new Value(r, 0, null, null, true, r >= cfg.method.firstParam() && r < cfg.method.registerCount());
            entryValues[r] = e;
        }
        return e;
    }

    private Value define(int r, Insn def, Phi phi) {
        Value v = new Value(r, ++counter[r], def, phi, false, false);
        stacks[r].add(v);
        return v;
    }

    @SuppressWarnings("unchecked")
    private void rename() {
        counter = new int[regCount];
        entryValues = new Value[regCount];
        stacks = new ArrayList[regCount];
        for (int i = 0; i < regCount; i++) stacks[i] = new ArrayList<>();
        int nb = cfg.blocks.size();
        int[][] pushed = new int[nb][];
        // frames: {blockId, phase}
        Deque<int[]> work = new ArrayDeque<>();
        work.push(new int[]{cfg.entry.id, 0});
        while (!work.isEmpty()) {
            int[] fr = work.pop();
            Cfg.BasicBlock b = cfg.blocks.get(fr[0]);
            if (fr[1] == 1) { // leaving the block: undo its pushes
                int[] p = pushed[b.id];
                for (int i = p.length - 1; i >= 0; i--) {
                    ArrayList<Value> s = stacks[p[i]];
                    s.remove(s.size() - 1);
                }
                continue;
            }
            List<Integer> push = new ArrayList<>();
            for (Phi ph : phis[b.id]) {
                ph.result = define(ph.reg, null, ph);
                push.add(ph.reg);
            }
            if (b.pseudo) {
                Insn d = b.deferredFrom;
                Value[] dv = new Value[d.defs.length];
                for (int k = 0; k < dv.length; k++) {
                    dv[k] = define(d.defs[k], d, null);
                    push.add(d.defs[k]);
                }
                defs[d.index] = dv;
            } else {
                for (int i = b.first; i <= b.last; i++) {
                    Insn in = cfg.method.insns.get(i);
                    Value[] uv = new Value[in.uses.length];
                    for (int k = 0; k < uv.length; k++) uv[k] = top(in.uses[k]);
                    uses[i] = uv;
                    if (b.defersLast && i == b.last) continue; // defined in the pseudo successor
                    Value[] dv = new Value[in.defs.length];
                    for (int k = 0; k < dv.length; k++) {
                        dv[k] = define(in.defs[k], in, null);
                        push.add(in.defs[k]);
                    }
                    defs[i] = dv;
                }
            }
            for (Cfg.Edge e : b.succs) {
                for (Phi ph : phis[e.to.id]) ph.operands[e.predIdx] = top(ph.reg);
            }
            int[] pr = new int[push.size()];
            for (int i = 0; i < pr.length; i++) pr[i] = push.get(i);
            pushed[b.id] = pr;
            work.push(new int[]{b.id, 1});
            List<Integer> kids = cfg.domChildren[b.id];
            for (int i = kids.size() - 1; i >= 0; i--) work.push(new int[]{kids.get(i), 0});
        }
        // unreachable blocks / empty slots: no values
        for (int i = 0; i < defs.length; i++) {
            if (defs[i] == null) defs[i] = new Value[0];
            if (uses[i] == null) uses[i] = new Value[0];
        }
    }

    /** All values defined by the instruction (empty for unreachable code). */
    public Value[] defsOf(Insn in) {
        return defs[in.index];
    }

    public Value[] usesOf(Insn in) {
        return uses[in.index];
    }

    /** SSA listing for tests and debugging. */
    public String dump() {
        StringBuilder sb = new StringBuilder();
        for (Cfg.BasicBlock b : cfg.blocks) {
            if (!b.reachable) continue;
            sb.append(b).append(":\n");
            for (Phi p : phis[b.id]) {
                sb.append("  ").append(p.result).append(" = phi(");
                for (int i = 0; i < p.operands.length; i++) sb.append(i == 0 ? "" : ", ").append(p.operands[i]);
                sb.append(")\n");
            }
            if (b.pseudo) {
                sb.append("  (result of ").append(b.deferredFrom.op).append(")");
                for (Value v : defs[b.deferredFrom.index]) sb.append(' ').append(v);
                sb.append('\n');
                continue;
            }
            for (int i = b.first; i <= b.last; i++) {
                Insn in = cfg.method.insns.get(i);
                sb.append("  ").append(in.op);
                for (Value v : defs[i]) sb.append(' ').append(v);
                if (uses[i].length > 0) {
                    sb.append(" <-");
                    for (Value v : uses[i]) sb.append(' ').append(v);
                }
                sb.append('\n');
            }
        }
        return sb.toString();
    }
}
