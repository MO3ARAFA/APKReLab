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
            Insn in = parseInsn(m, line, lineStart, lineNo);
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

    // ---------- instructions ----------

    static Insn parseInsn(MethodIr m, String line, int offset, int lineNo) {
        int sp = line.indexOf(' ');
        String op = sp < 0 ? line : line.substring(0, sp);
        String rest = sp < 0 ? "" : line.substring(sp + 1).trim();
        Insn.Kind k = Insn.kindOf(op);
        Insn in = new Insn(m.insns.size(), op, k, offset, lineNo, line);
        List<String> a = splitOperands(rest);
        boolean w = op.contains("-wide");
        switch (k) {
            case CONST:
                in.defs = r(m, a, 0, op.startsWith("const-wide"));
                if (a.size() > 1) in.ref = a.get(1);
                break;
            case MOVE:
                in.defs = r(m, a, 0, w);
                in.uses = r(m, a, 1, w);
                break;
            case MOVE_RESULT:
                in.defs = r(m, a, 0, w);
                break;
            case MOVE_EXCEPTION:
                in.defs = r(m, a, 0, false);
                break;
            case RETURN:
                in.uses = r(m, a, 0, w);
                break;
            case GOTO:
                if (a.size() > 0) in.labels = new String[]{a.get(0)};
                break;
            case IF:
                if (op.endsWith("z")) {
                    in.uses = r(m, a, 0, false);
                    if (a.size() > 1) in.labels = new String[]{a.get(1)};
                } else {
                    in.uses = cat(r(m, a, 0, false), r(m, a, 1, false));
                    if (a.size() > 2) in.labels = new String[]{a.get(2)};
                }
                break;
            case SWITCH:
            case FILL_ARRAY_DATA:
                in.uses = r(m, a, 0, false);
                if (a.size() > 1) in.labels = new String[]{a.get(1)};
                break;
            case THROW:
            case MONITOR:
                in.uses = r(m, a, 0, false);
                break;
            case INVOKE:
            case FILLED_ARRAY: {
                int ob = rest.indexOf('{'), cb = rest.indexOf('}');
                if (ob < 0 || cb < ob) break;
                in.uses = regList(m, rest.substring(ob + 1, cb));
                String after = rest.substring(cb + 1).trim();
                if (after.startsWith(",")) after = after.substring(1).trim();
                int comma = after.indexOf(',');
                in.ref = comma < 0 ? after : after.substring(0, comma).trim();
                break;
            }
            case FIELD_GET:
                if (op.startsWith("sget")) {
                    in.defs = r(m, a, 0, w);
                    if (a.size() > 1) in.ref = a.get(1);
                } else {
                    in.defs = r(m, a, 0, w);
                    in.uses = r(m, a, 1, false);
                    if (a.size() > 2) in.ref = a.get(2);
                }
                break;
            case FIELD_PUT:
                if (op.startsWith("sput")) {
                    in.uses = r(m, a, 0, w);
                    if (a.size() > 1) in.ref = a.get(1);
                } else {
                    in.uses = cat(r(m, a, 0, w), r(m, a, 1, false));
                    if (a.size() > 2) in.ref = a.get(2);
                }
                break;
            case ARRAY_GET:
                in.defs = r(m, a, 0, w);
                in.uses = cat(r(m, a, 1, false), r(m, a, 2, false));
                break;
            case ARRAY_PUT:
                in.uses = cat(r(m, a, 0, w), r(m, a, 1, false), r(m, a, 2, false));
                break;
            case NEW_INSTANCE:
                in.defs = r(m, a, 0, false);
                if (a.size() > 1) in.ref = a.get(1);
                break;
            case NEW_ARRAY:
                in.defs = r(m, a, 0, false);
                in.uses = r(m, a, 1, false);
                if (a.size() > 2) in.ref = a.get(2);
                break;
            case CHECK_CAST:
                in.defs = r(m, a, 0, false);
                in.uses = r(m, a, 0, false);
                if (a.size() > 1) in.ref = a.get(1);
                break;
            case INSTANCE_OF:
                in.defs = r(m, a, 0, false);
                in.uses = r(m, a, 1, false);
                if (a.size() > 2) in.ref = a.get(2);
                break;
            case ARRAY_LENGTH:
                in.defs = r(m, a, 0, false);
                in.uses = r(m, a, 1, false);
                break;
            case CMP: {
                boolean cw = Insn.wideType(Insn.typeOf(op));
                in.defs = r(m, a, 0, false);
                in.uses = cat(r(m, a, 1, cw), r(m, a, 2, cw));
                break;
            }
            case UNOP: {
                int to = op.indexOf("-to-");
                if (to >= 0) {
                    String from = op.substring(0, to);
                    String dst = op.substring(to + 4);
                    in.defs = r(m, a, 0, Insn.wideType(dst));
                    in.uses = r(m, a, 1, Insn.wideType(from));
                } else {
                    boolean uw = Insn.wideType(Insn.typeOf(op));
                    in.defs = r(m, a, 0, uw);
                    in.uses = r(m, a, 1, uw);
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
                    in.defs = r(m, a, 0, bw);
                    in.uses = cat(r(m, a, 0, bw), r(m, a, 1, bw && !shift));
                } else if (suffix.startsWith("lit")) {
                    in.defs = r(m, a, 0, bw);
                    in.uses = r(m, a, 1, bw);
                    if (a.size() > 2) in.ref = a.get(2);
                } else {
                    in.defs = r(m, a, 0, bw);
                    in.uses = cat(r(m, a, 1, bw), r(m, a, 2, bw && !shift));
                }
                break;
            }
            default:
                break; // NOP, OTHER
        }
        return in;
    }

    private static int[] r(MethodIr m, List<String> a, int i, boolean wide) {
        if (i >= a.size()) return Insn.NO_REGS;
        int x = m.reg(a.get(i));
        if (x < 0) return Insn.NO_REGS;
        return wide ? new int[]{x, x + 1} : new int[]{x};
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

    /** "v0, v1, p2" or "v0 .. v5" -> register numbers. */
    private static int[] regList(MethodIr m, String inner) {
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

    /** Splits "v0, \"a, b\", {v1, v2}, Lx;->m()V" at top-level commas (not inside quotes or braces). */
    static List<String> splitOperands(String s) {
        List<String> out = new ArrayList<>();
        if (s.isEmpty()) return out;
        int depth = 0, start = 0;
        boolean str = false;
        for (int i = 0; i < s.length(); i++) {
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
                out.add(s.substring(start, i).trim());
                start = i + 1;
            }
        }
        out.add(s.substring(start).trim());
        return out;
    }
}
