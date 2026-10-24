package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.List;

/**
 * 0.53.0 (P0): baksmali text of ONE class -> {@link ClassIr}. Never throws on odd input: a line it cannot read is skipped,
 * a truncated method is closed at the end of the text. Char offsets and line numbers of every instruction are kept, so a
 * finding's offset can be mapped back to an instruction with {@link MethodIr#insnAtOffset(int)}.
 *
 * What it understands: .class/.super/.implements/.field, .method + .locals/.registers, labels, .catch/.catchall,
 * packed/sparse switch payloads, array-data (skipped), annotations and all other directives (skipped), the register
 * names vN / pN, wide register pairs, invoke(-range) register lists, and move-result fusion into the previous invoke.
 */
public final class SmaliParser {
    private SmaliParser() {
    }

    /** Header + instructions of every method. */
    public static ClassIr parse(String text) {
        return parse(text, true);
    }

    /** bodies=false keeps only the class header and the method signatures (cheap pass for the class hierarchy). */
    public static ClassIr parse(String text, boolean bodies) {
        ClassIr c = new ClassIr();
        if (text == null) return c;
        MethodIr m = null;
        boolean inAnnotation = false;
        String lastLabel = null;
        String payloadKind = null;       // "packed" | "sparse" | "array"
        String payloadLabel = null;
        List<String> payloadTargets = null;
        int[] sc = new int[2 * MAX_OPS];     // operand ranges of one instruction, reused
        int pos = 0, n = text.length(), lineNo = 0;
        while (pos < n) {
            int e = text.indexOf('\n', pos);
            if (e < 0) e = n;
            lineNo++;
            int s = pos;
            while (s < e && isWs(text.charAt(s))) s++;
            int f = e;
            while (f > s && isWs(text.charAt(f - 1))) f--;
            int lineStart = s;
            pos = e + 1;
            if (f <= s) continue;
            // 0.103.0: a line that cannot change anything (a comment, a directive the parser ignores, any body line of a header-only pass) gets no String at all
            if (m != null && payloadKind == null && !inAnnotation && ignorable(text, s, f, bodies)) continue;
            String line = text.substring(s, f);

            if (m == null) {
                if (line.startsWith(".method ")) {
                    m = newMethod(c.type, line, lineStart, lineNo);
                    lastLabel = null;
                    inAnnotation = false;
                    payloadKind = null;
                } else if (line.startsWith(".class ")) {
                    String[] t = line.substring(7).trim().split(" ");
                    c.type = t[t.length - 1];
                    StringBuilder fl = new StringBuilder();
                    for (int i = 0; i < t.length - 1; i++) fl.append(i == 0 ? "" : " ").append(t[i]);
                    c.flags = fl.toString();
                } else if (line.startsWith(".super ")) {
                    c.superType = line.substring(7).trim();
                } else if (line.startsWith(".implements ")) {
                    c.interfaces.add(line.substring(12).trim());
                } else if (line.startsWith(".field ")) {
                    String d = line.substring(7);
                    int eq = d.indexOf(" = ");
                    if (eq >= 0) d = d.substring(0, eq);
                    int sp = d.lastIndexOf(' ');
                    c.fields.add(sp < 0 ? d : d.substring(sp + 1));
                }
                continue;
            }

            // ---- inside a method ----
            if (line.startsWith(".end method")) {
                m.resolveCatches();
                c.methods.add(m);
                m = null;
                continue;
            }
            if (!bodies) continue;
            if (payloadKind != null) {
                if (line.startsWith(".end packed-switch") || line.startsWith(".end sparse-switch") || line.startsWith(".end array-data")) {
                    if (!payloadKind.equals("array") && payloadLabel != null) m.payloads.put(payloadLabel, payloadTargets);
                    payloadKind = null;
                } else if (!payloadKind.equals("array")) {
                    int i = line.lastIndexOf(':');
                    if (i >= 0) payloadTargets.add(line.substring(i).trim());
                }
                continue;
            }
            if (inAnnotation) {
                if (line.startsWith(".end annotation")) inAnnotation = false;
                continue;
            }
            char c0 = line.charAt(0);
            if (c0 == '#') continue;
            if (c0 == ':') {
                lastLabel = line;
                m.labels.put(line, m.insns.size());
                continue;
            }
            if (c0 == '.') {
                int sp = line.indexOf(' ');
                String head = sp < 0 ? line : line.substring(0, sp);
                switch (head) {
                    case ".locals":
                        m.locals = intOr(line.substring(head.length()).trim(), 0);
                        break;
                    case ".registers":
                        m.locals = Math.max(0, intOr(line.substring(head.length()).trim(), 0) - m.ins);
                        break;
                    case ".annotation":
                        inAnnotation = true;
                        break;
                    case ".packed-switch":
                        payloadKind = "packed";
                        payloadLabel = lastLabel;
                        payloadTargets = new ArrayList<>();
                        break;
                    case ".sparse-switch":
                        payloadKind = "sparse";
                        payloadLabel = lastLabel;
                        payloadTargets = new ArrayList<>();
                        break;
                    case ".array-data":
                        payloadKind = "array";
                        break;
                    case ".catch":
                        addCatch(m, line, false);
                        break;
                    case ".catchall":
                        addCatch(m, line, true);
                        break;
                    default:
                        break; // .line .local .param .prologue .end ... : no instruction
                }
                continue;
            }
            Insn in = parseInsn(m, line, lineStart, lineNo, sc);
            if (in == null) continue;
            if (in.kind == Insn.Kind.MOVE_RESULT && !m.insns.isEmpty()) {
                Insn prev = m.insns.get(m.insns.size() - 1);
                if ((prev.kind == Insn.Kind.INVOKE || prev.kind == Insn.Kind.FILLED_ARRAY) && !prev.hasResult) {
                    prev.hasResult = true;
                    prev.defs = in.defs;
                    continue; // fused: no instruction of its own (a :try_end label in between is harmless)
                }
            }
            m.insns.add(in);
        }
        if (m != null) { // truncated text: keep what we have
            m.resolveCatches();
            c.methods.add(m);
        }
        return c;
    }

    // ---------- header helpers ----------

    private static MethodIr newMethod(String owner, String line, int off, int lineNo) {
        String body = line.substring(".method ".length()).trim();
        int sp = body.lastIndexOf(' ');
        String sig = sp < 0 ? body : body.substring(sp + 1);
        String flags = sp < 0 ? "" : body.substring(0, sp);
        int open = sig.indexOf('(');
        String name = open < 0 ? sig : sig.substring(0, open);
        String desc = open < 0 ? "()V" : sig.substring(open);
        boolean isStatic = false;
        for (String t : flags.split(" ")) if (t.equals("static")) isStatic = true;
        MethodIr m = new MethodIr(owner, name, desc, flags, isStatic, (isStatic ? 0 : 1) + slotCount(desc));
        m.startOffset = off;
        m.startLine = lineNo;
        return m;
    }

    /** Register slots taken by the parameters of a descriptor like "(IJLjava/lang/String;[I)V" = 1 + 2 + 1 + 1. */
    static int slotCount(String desc) {
        int open = desc.indexOf('('), close = desc.indexOf(')');
        if (open < 0 || close < open) return 0;
        int i = open + 1, n = 0;
        while (i < close) {
            char ch = desc.charAt(i);
            if (ch == '[') {
                while (i < close && desc.charAt(i) == '[') i++;
                if (i < close && desc.charAt(i) == 'L') {
                    int semi = desc.indexOf(';', i);
                    if (semi < 0) break;
                    i = semi;
                }
                i++;
                n++;
            } else if (ch == 'L') {
                int semi = desc.indexOf(';', i);
                if (semi < 0) break;
                i = semi + 1;
                n++;
            } else if (ch == 'J' || ch == 'D') {
                i++;
                n += 2;
            } else {
                i++;
                n++;
            }
        }
        return n;
    }

    private static void addCatch(MethodIr m, String line, boolean all) {
        int ob = line.indexOf('{'), cb = line.indexOf('}');
        if (ob < 0 || cb < ob) return;
        String[] r = line.substring(ob + 1, cb).split("\\.\\.");
        if (r.length != 2) return;
        String type = all ? null : line.substring(".catch".length(), ob).trim();
        m.rawCatches.add(new String[]{type, r[0].trim(), r[1].trim(), line.substring(cb + 1).trim()});
    }

    private static int intOr(String s, int d) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException ex) {
            return d;
        }
    }

    private static boolean isWs(char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r';
    }

    // ---------- 0.103.0: lines and operands without throw-away Strings ----------

    private static boolean startsAt(String t, int s, int f, String p) {
        return f - s >= p.length() && t.startsWith(p, s);
    }

    /** Directives whose handling in {@link #parse} reads the line (the ignorable ones are every other '.' line). */
    private static final String[] NEEDED_HEADS = {".locals", ".registers", ".annotation", ".packed-switch", ".sparse-switch", ".array-data", ".catch", ".catchall"};

    /**
     * True when the line [s, f) of a method body is dropped by {@link #parse} without any effect: a '#' comment, a '.' directive whose head (up to the first space) is not one
     * the parser handles, and, when only the signatures are wanted, everything except ".end method". Mirrors the order of the checks in parse() exactly.
     */
    private static boolean ignorable(String t, int s, int f, boolean bodies) {
        if (startsAt(t, s, f, ".end method")) return false;
        if (!bodies) return true;
        char c = t.charAt(s);
        if (c == '#') return true;
        if (c != '.') return false;
        int sp = t.indexOf(' ', s);
        int he = sp < 0 || sp >= f ? f : sp;
        for (String h : NEEDED_HEADS) if (he - s == h.length() && t.startsWith(h, s)) return false;
        return true;
    }

    /** An opcode string shared by every instruction that uses it, with its Kind (looked up by characters: no String is made for an opcode already seen). */
    private static final class Op {
        final String s; final Insn.Kind k;
        Op(String s, Insn.Kind k) { this.s = s; this.k = k; }
    }

    /** Open-addressing table filled on first sight. Racy on purpose and safe: an Op is immutable (final fields), a lost write only means the Op is made again. */
    private static final Op[] OPS = new Op[1024];
    private static volatile int opCount;

    private static Op op(String t, int from, int to) {
        int len = to - from, h = 0;
        for (int i = from; i < to; i++) h = h * 31 + t.charAt(i);
        int slot = (h ^ (h >>> 10)) & 1023;
        for (int probe = 0; probe < 8; probe++, slot = (slot + 1) & 1023) {
            Op o = OPS[slot];
            if (o == null) {
                String str = t.substring(from, to);
                Op made = new Op(str, Insn.kindOf(str));
                if (len <= 40 && opCount < 600) { OPS[slot] = made; opCount++; }
                return made;
            }
            if (o.s.length() == len && t.regionMatches(from, o.s, 0, len)) return o;
        }
        String str = t.substring(from, to);
        return new Op(str, Insn.kindOf(str));
    }

    /** Immutable one-register arrays shared by all instructions (nothing in the engine writes into Insn.defs / Insn.uses). */
    private static final int[][] ONE = new int[256][];
    static { for (int i = 0; i < ONE.length; i++) ONE[i] = new int[]{i}; }

    private static int[] one(int x) { return x < ONE.length ? ONE[x] : new int[]{x}; }

    private static final int MAX_OPS = 32;

    /** Splits [from, to) of line at top-level commas (not inside quotes or braces) into trimmed ranges sc[2i], sc[2i+1]; returns the count (capped at MAX_OPS). Same rules as the old splitOperands. */
    private static int split(String s, int from, int to, int[] sc) {
        if (to <= from) return 0;
        int n = 0, depth = 0, start = from;
        boolean str = false;
        for (int i = from; i < to; i++) {
            char ch = s.charAt(i);
            if (str) {
                if (ch == '\\') i++;
                else if (ch == '"') str = false;
            } else if (ch == '"') {
                str = true;
            } else if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
            } else if (ch == ',' && depth == 0) {
                if (n < MAX_OPS) trimInto(s, start, i, sc, n);
                n++;
                start = i + 1;
            }
        }
        if (n < MAX_OPS) trimInto(s, start, to, sc, n);
        return Math.min(n + 1, MAX_OPS);
    }

    private static void trimInto(String s, int a, int b, int[] sc, int n) {
        while (a < b && s.charAt(a) <= ' ') a++;
        while (b > a && s.charAt(b - 1) <= ' ') b--;
        sc[2 * n] = a;
        sc[2 * n + 1] = b;
    }

    private static String str(String line, int[] sc, int i) {
        return line.substring(sc[2 * i], sc[2 * i + 1]);
    }

    /** Register at operand [i], or none; the same rules as MethodIr.reg on the trimmed operand. */
    private static int[] r(MethodIr m, String line, int[] sc, int n, int i, boolean wide) {
        if (i >= n) return Insn.NO_REGS;
        int x = m.reg(line, sc[2 * i], sc[2 * i + 1]);
        if (x < 0) return Insn.NO_REGS;
        return wide ? new int[]{x, x + 1} : one(x);
    }

    static Insn parseInsn(MethodIr m, String line, int offset, int lineNo, int[] sc) {
        int len = line.length();
        int sp = line.indexOf(' ');
        Op o = op(line, 0, sp < 0 ? len : sp);
        String op = o.s;
        Insn.Kind k = o.k;
        // the operand text: after the opcode, trimmed (what the old code called "rest")
        int rs = sp < 0 ? len : sp + 1, re = len;
        while (rs < re && line.charAt(rs) <= ' ') rs++;
        while (re > rs && line.charAt(re - 1) <= ' ') re--;
        Insn in = new Insn(m.insns.size(), op, k, offset, lineNo, line);
        boolean w = op.contains("-wide");
        // an invoke / filled-new-array keeps its operands inside the braces: no split needed (the old code split them and never used the result)
        int n = (k == Insn.Kind.INVOKE || k == Insn.Kind.FILLED_ARRAY || k == Insn.Kind.NOP || k == Insn.Kind.OTHER) ? 0 : split(line, rs, re, sc);
        switch (k) {
            case CONST:
                in.defs = r(m, line, sc, n, 0, op.startsWith("const-wide"));
                if (n > 1) in.ref = str(line, sc, 1);
                break;
            case MOVE:
                in.defs = r(m, line, sc, n, 0, w);
                in.uses = r(m, line, sc, n, 1, w);
                break;
            case MOVE_RESULT:
                in.defs = r(m, line, sc, n, 0, w);
                break;
            case MOVE_EXCEPTION:
                in.defs = r(m, line, sc, n, 0, false);
                break;
            case RETURN:
                in.uses = r(m, line, sc, n, 0, w);
                break;
            case GOTO:
                if (n > 0) in.labels = new String[]{str(line, sc, 0)};
                break;
            case IF:
                if (op.endsWith("z")) {
                    in.uses = r(m, line, sc, n, 0, false);
                    if (n > 1) in.labels = new String[]{str(line, sc, 1)};
                } else {
                    in.uses = cat(r(m, line, sc, n, 0, false), r(m, line, sc, n, 1, false));
                    if (n > 2) in.labels = new String[]{str(line, sc, 2)};
                }
                break;
            case SWITCH:
            case FILL_ARRAY_DATA:
                in.uses = r(m, line, sc, n, 0, false);
                if (n > 1) in.labels = new String[]{str(line, sc, 1)};
                break;
            case THROW:
            case MONITOR:
                in.uses = r(m, line, sc, n, 0, false);
                break;
            case INVOKE:
            case FILLED_ARRAY: {
                int ob = line.indexOf('{', rs), cb = line.indexOf('}', rs);
                if (ob < 0 || ob >= re) ob = -1;
                if (cb < 0 || cb >= re) cb = -1;
                if (ob < 0 || cb < ob) break;
                in.uses = regList(m, line, ob + 1, cb);
                int a = cb + 1, b = re;
                while (a < b && line.charAt(a) <= ' ') a++;
                if (a < b && line.charAt(a) == ',') {
                    a++;
                    while (a < b && line.charAt(a) <= ' ') a++;
                }
                int comma = line.indexOf(',', a);
                int end = comma < 0 || comma >= b ? b : comma;
                while (end > a && line.charAt(end - 1) <= ' ') end--;
                in.ref = line.substring(a, end);
                break;
            }
            case FIELD_GET:
                if (op.startsWith("sget")) {
                    in.defs = r(m, line, sc, n, 0, w);
                    if (n > 1) in.ref = str(line, sc, 1);
                } else {
                    in.defs = r(m, line, sc, n, 0, w);
                    in.uses = r(m, line, sc, n, 1, false);
                    if (n > 2) in.ref = str(line, sc, 2);
                }
                break;
            case FIELD_PUT:
                if (op.startsWith("sput")) {
                    in.uses = r(m, line, sc, n, 0, w);
                    if (n > 1) in.ref = str(line, sc, 1);
                } else {
                    in.uses = cat(r(m, line, sc, n, 0, w), r(m, line, sc, n, 1, false));
                    if (n > 2) in.ref = str(line, sc, 2);
                }
                break;
            case ARRAY_GET:
                in.defs = r(m, line, sc, n, 0, w);
                in.uses = cat(r(m, line, sc, n, 1, false), r(m, line, sc, n, 2, false));
                break;
            case ARRAY_PUT:
                in.uses = cat(r(m, line, sc, n, 0, w), r(m, line, sc, n, 1, false), r(m, line, sc, n, 2, false));
                break;
            case NEW_INSTANCE:
                in.defs = r(m, line, sc, n, 0, false);
                if (n > 1) in.ref = str(line, sc, 1);
                break;
            case NEW_ARRAY:
                in.defs = r(m, line, sc, n, 0, false);
                in.uses = r(m, line, sc, n, 1, false);
                if (n > 2) in.ref = str(line, sc, 2);
                break;
            case CHECK_CAST:
                in.defs = r(m, line, sc, n, 0, false);
                in.uses = r(m, line, sc, n, 0, false);
                if (n > 1) in.ref = str(line, sc, 1);
                break;
            case INSTANCE_OF:
                in.defs = r(m, line, sc, n, 0, false);
                in.uses = r(m, line, sc, n, 1, false);
                if (n > 2) in.ref = str(line, sc, 2);
                break;
            case ARRAY_LENGTH:
                in.defs = r(m, line, sc, n, 0, false);
                in.uses = r(m, line, sc, n, 1, false);
                break;
            case CMP: {
                boolean cw = Insn.wideType(Insn.typeOf(op));
                in.defs = r(m, line, sc, n, 0, false);
                in.uses = cat(r(m, line, sc, n, 1, cw), r(m, line, sc, n, 2, cw));
                break;
            }
            case UNOP: {
                int to = op.indexOf("-to-");
                if (to >= 0) {
                    String from = op.substring(0, to);
                    String dst = op.substring(to + 4);
                    in.defs = r(m, line, sc, n, 0, Insn.wideType(dst));
                    in.uses = r(m, line, sc, n, 1, Insn.wideType(from));
                } else {
                    boolean uw = Insn.wideType(Insn.typeOf(op));
                    in.defs = r(m, line, sc, n, 0, uw);
                    in.uses = r(m, line, sc, n, 1, uw);
                }
                break;
            }
            case BINOP: {
                boolean bw = Insn.wideType(Insn.typeOf(op));
                String b = Insn.base(op);
                boolean shift = b.equals("shl") || b.equals("shr") || b.equals("ushr");
                int sl = op.indexOf('/');
                String suffix = sl < 0 ? "" : op.substring(sl + 1);
                if (suffix.equals("2addr")) {
                    in.defs = r(m, line, sc, n, 0, bw);
                    in.uses = cat(r(m, line, sc, n, 0, bw), r(m, line, sc, n, 1, bw && !shift));
                } else if (suffix.startsWith("lit")) {
                    in.defs = r(m, line, sc, n, 0, bw);
                    in.uses = r(m, line, sc, n, 1, bw);
                    if (n > 2) in.ref = str(line, sc, 2);
                } else {
                    in.defs = r(m, line, sc, n, 0, bw);
                    in.uses = cat(r(m, line, sc, n, 1, bw), r(m, line, sc, n, 2, bw && !shift));
                }
                break;
            }
            default:
                break; // NOP, OTHER
        }
        return in;
    }

    private static int[] cat(int[]... parts) {
        int n = 0;
        for (int[] p : parts) n += p.length;
        if (n == 0) return Insn.NO_REGS;
        int[] out = new int[n];
        int k = 0;
        for (int[] p : parts) {
            System.arraycopy(p, 0, out, k, p.length);
            k += p.length;
        }
        return out;
    }

    /** The registers of "v0, v1, p2" or "v0 .. v5" in line[from, to). Lists are read in place; a range falls back to the String code (rare, and its split() rules stay exactly as before). */
    private static int[] regList(MethodIr m, String line, int from, int to) {
        int a = from, b = to;
        while (a < b && line.charAt(a) <= ' ') a++;
        while (b > a && line.charAt(b - 1) <= ' ') b--;
        if (a >= b) return Insn.NO_REGS;
        int dots = line.indexOf("..", a);
        if (dots >= 0 && dots < b) return regListText(m, line.substring(a, b));
        int cnt = 1;
        for (int i = a; i < b; i++) if (line.charAt(i) == ',') cnt++;
        int[] tmp = new int[cnt];
        int got = 0, st = a;
        for (int i = a; i <= b; i++) {
            if (i == b || line.charAt(i) == ',') {
                int x = st, y = i;
                while (x < y && line.charAt(x) <= ' ') x++;
                while (y > x && line.charAt(y - 1) <= ' ') y--;
                int v = m.reg(line, x, y);
                if (v >= 0) tmp[got++] = v;
                st = i + 1;
            }
        }
        if (got == 0) return Insn.NO_REGS;
        if (got == 1) return one(tmp[0]);
        if (got == tmp.length) return tmp;
        int[] out = new int[got];
        System.arraycopy(tmp, 0, out, 0, got);
        return out;
    }

    /** "v0, v1, p2" or "v0 .. v5" -> register numbers (the original String implementation, used for ranges). */
    private static int[] regListText(MethodIr m, String inner) {
        inner = inner.trim();
        if (inner.isEmpty()) return Insn.NO_REGS;
        if (inner.contains("..")) {
            String[] e = inner.split("\\.\\.");
            if (e.length != 2) return Insn.NO_REGS;
            int lo = m.reg(e[0].trim()), hi = m.reg(e[1].trim());
            if (lo < 0 || hi < lo || hi - lo > 255) return Insn.NO_REGS;
            int[] out = new int[hi - lo + 1];
            for (int i = 0; i < out.length; i++) out[i] = lo + i;
            return out;
        }
        String[] t = inner.split(",");
        int[] tmp = new int[t.length];
        int n = 0;
        for (String x : t) {
            int v = m.reg(x.trim());
            if (v >= 0) tmp[n++] = v;
        }
        if (n == tmp.length) return tmp;
        int[] out = new int[n];
        System.arraycopy(tmp, 0, out, 0, n);
        return out;
    }
}
