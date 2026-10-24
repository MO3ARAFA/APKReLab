package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 0.53.0 (P0): one method as a flat instruction list plus its labels, try ranges and switch payloads. */
public final class MethodIr {

    /** One .catch / .catchall line, already resolved to instruction indexes ([start, end) is the try range). */
    public static final class Catch {
        public final String type;   // null = catch-all
        public final int start, end, handler;

        Catch(String type, int start, int end, int handler) {
            this.type = type;
            this.start = start;
            this.end = end;
            this.handler = handler;
        }
    }

    public final String owner;      // "Lcom/x/Y;"
    public final String name;
    public final String desc;       // "(Ljava/lang/String;)V"
    public final String flags;      // "public static final" ...
    public final boolean isStatic;
    public final int ins;           // register slots taken by the parameters (incl. this, wide = 2)
    public int locals;              // .locals N  (or .registers N minus ins)
    public final List<Insn> insns = new ArrayList<>();
    public final Map<String, Integer> labels = new HashMap<>();          // label -> index of the next instruction
    public final Map<String, List<String>> payloads = new HashMap<>();   // switch payload label -> case labels (in order)
    public final List<String[]> rawCatches = new ArrayList<>();          // type|null, startLabel, endLabel, handlerLabel (resolved at .end method)
    public final List<Catch> catches = new ArrayList<>();
    /** 0.60.0: SSA form built once per method and reused by every re-analysis and every group (soft, so the GC may drop it under memory pressure). */
    volatile java.lang.ref.SoftReference<SsaForm> ssaRef;
    // 0.66.3: lazy caches (idempotent values, so a benign race between threads is harmless)
    private String sigCache, keyCache;
    private volatile String[] flagTokens;
    public int startOffset;         // char offset of the .method line
    public int startLine;

    MethodIr(String owner, String name, String desc, String flags, boolean isStatic, int ins) {
        this.owner = owner;
        this.name = name;
        this.desc = desc;
        this.flags = flags;
        this.isStatic = isStatic;
        this.ins = ins;
    }

    /** "name(desc)ret" */
    public String sig() {
        String s = sigCache;
        if (s == null) sigCache = s = name + desc;   // 0.66.3: built once (a fresh String every call also lost the cached hashCode)
        return s;
    }

    /** "Lowner;->name(desc)ret" - the same key format the call index and the findings use. */
    public String key() {
        String k = keyCache;
        if (k == null) keyCache = k = owner + "->" + name + desc;
        return k;
    }

    public boolean isAbstract() {
        return hasFlag("abstract");
    }

    public boolean isNative() {
        return hasFlag("native");
    }

    public boolean hasFlag(String f) {
        String[] t = flagTokens;
        if (t == null) flagTokens = t = flags.split(" ");   // 0.66.3: split once; flags is final
        for (String s : t) if (s.equals(f)) return true;
        return false;
    }

    public int registerCount() {
        return locals + ins;
    }

    /** First parameter register (p0) as a plain register number. */
    public int firstParam() {
        return locals;
    }

    /** Smali register name for display: v3, p1. */
    public String regName(int r) {
        return r >= locals ? "p" + (r - locals) : "v" + r;
    }

    /** vN / pN -> register number, or -1 when the token is not a register. */
    public int reg(String tok) {
        if (tok == null || tok.length() < 2) return -1;
        char c = tok.charAt(0);
        if (c != 'v' && c != 'p') return -1;
        int n = 0;
        for (int i = 1; i < tok.length(); i++) {
            char d = tok.charAt(i);
            if (d < '0' || d > '9') return -1;
            n = n * 10 + (d - '0');
            if (n > 65535) return -1;
        }
        return c == 'v' ? n : locals + n;
    }

    /** The same as {@link #reg(String)} for the operand tok[from, to) (no substring). */
    public int reg(String tok, int from, int to) {
        if (to - from < 2) return -1;
        char c = tok.charAt(from);
        if (c != 'v' && c != 'p') return -1;
        int n = 0;
        for (int i = from + 1; i < to; i++) {
            char d = tok.charAt(i);
            if (d < '0' || d > '9') return -1;
            n = n * 10 + (d - '0');
            if (n > 65535) return -1;
        }
        return c == 'v' ? n : locals + n;
    }

    /** Instruction index a label points to, or -1. A label at the very end of the method returns insns.size(). */
    public int labelIndex(String label) {
        Integer i = labels.get(label);
        return i == null ? -1 : i;
    }

    /** The instruction whose source line contains the char offset (same coordinate as Finding.at), or null. */
    public Insn insnAtOffset(int off) {
        int lo = 0, hi = insns.size() - 1, best = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (insns.get(mid).offset <= off) {
                best = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return best < 0 ? null : insns.get(best);
    }

    void resolveCatches() {
        catches.clear();
        for (String[] r : rawCatches) {
            int s = labelIndex(r[1]), e = labelIndex(r[2]), h = labelIndex(r[3]);
            if (s < 0 || e < 0 || h < 0 || h >= insns.size() || s >= insns.size() || e <= s) continue;
            catches.add(new Catch(r[0], s, e, h));
        }
    }

    @Override
    public String toString() {
        return key();
    }
}
