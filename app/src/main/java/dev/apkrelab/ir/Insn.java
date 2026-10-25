package dev.apkrelab.ir;

/**
 * 0.53.0 (P0): one Smali instruction in the IR. Registers are plain ints: vN = N, pN = locals + N (see {@link MethodIr#reg}).
 * Wide values (long / double) list BOTH halves in {@link #defs} / {@link #uses}, so every analysis can treat a register as one slot.
 * An invoke (or filled-new-array) that is followed by move-result* is FUSED with it: the move-result's register is in {@link #defs}.
 * Fields are public for speed; treat them as read-only after parsing.
 */
public final class Insn {
    public enum Kind {
        NOP, CONST, MOVE, MOVE_RESULT, MOVE_EXCEPTION, RETURN, GOTO, IF, SWITCH, THROW, INVOKE,
        FIELD_GET, FIELD_PUT, ARRAY_GET, ARRAY_PUT, NEW_INSTANCE, NEW_ARRAY, FILLED_ARRAY, FILL_ARRAY_DATA,
        CHECK_CAST, INSTANCE_OF, ARRAY_LENGTH, BINOP, UNOP, CMP, MONITOR, OTHER
    }

    static final int[] NO_REGS = new int[0];
    static final String[] NO_LABELS = new String[0];

    public final int index;      // position in MethodIr.insns
    public final String op;      // opcode as written, e.g. "invoke-virtual/range"
    public final Kind kind;
    public final int offset;     // char offset of the line inside the class text (same coordinate as Finding.at)
    public final int line;       // 1-based line number inside the class text
    private String head;         // the trimmed source line; after compact(), only the part before ref when the line ends with it (see text())
    private boolean refTail;     // text() = head + ref
    public int[] defs = NO_REGS;
    public int[] uses = NO_REGS;
    public String ref = "";      // method / field / type reference, or the literal of a const (strings keep their quotes)
    public String[] labels = NO_LABELS; // goto / if target, switch: the payload label, fill-array-data: payload label
    public boolean hasResult;    // invoke / filled-new-array fused with a following move-result*

    Insn(int index, String op, Kind kind, int offset, int line, String text) {
        this.index = index;
        this.op = op;
        this.kind = kind;
        this.offset = offset;
        this.line = line;
        this.head = text;
    }

    /** The trimmed source line, exactly as written. */
    public String text() {
        return refTail ? head + ref : head;
    }

    /**
     * 0.104.3: every instruction kept its whole source line plus a second copy of its reference, about 80 bytes per instruction, the biggest share of a group's live heap.
     * The line always ends with the reference (measured on 1.06 M instructions of two real apps: no exception), and the parts repeat across a whole app (5 times for the
     * line before the reference, 4.5 times for the reference): both go through the shared table of {@link Canon}, so equal parts are mostly one object.
     * Called by {@link SmaliParser} once the instruction is complete; {@link #text()} still returns the line exactly.
     */
    void compact() {
        if (!ref.isEmpty() && head.endsWith(ref)) {
            head = Canon.of(head.substring(0, head.length() - ref.length()));
            refTail = true;
        } else {
            head = Canon.of(head);
        }
        ref = Canon.of(ref);
        for (int i = 0; i < labels.length; i++) labels[i] = Canon.of(labels[i]);
    }

    // ---------- invoke helpers ----------

    public boolean isInvoke() {
        return kind == Kind.INVOKE;
    }

    /** virtual, super, direct, static, interface, polymorphic, custom ("" when not an invoke). */
    public String invokeKind() {
        if (kind != Kind.INVOKE) return "";
        // 1.0.0: the known kinds without a substring (asked for every call site on every pass)
        if (op.startsWith("invoke-virtual")) return "virtual";
        if (op.startsWith("invoke-static")) return "static";
        if (op.startsWith("invoke-direct")) return "direct";
        if (op.startsWith("invoke-interface")) return "interface";
        if (op.startsWith("invoke-super")) return "super";
        String s = op.substring("invoke-".length());
        int sl = s.indexOf('/');
        return sl < 0 ? s : s.substring(0, sl);
    }

    /** "Lowner;" of the invoked method, or "" when the reference is not a normal method reference. */
    public String targetOwner() {
        int i = ref.indexOf("->");
        return (kind == Kind.INVOKE && i > 0) ? ref.substring(0, i) : "";
    }

    /** "name(desc)ret" of the invoked method, or "". */
    public String targetSig() {
        int i = ref.indexOf("->");
        return (kind == Kind.INVOKE && i > 0) ? ref.substring(i + 2) : "";
    }

    /** Method name only ("<init>", "getString", ...). */
    public String targetName() {
        String s = targetSig();
        int p = s.indexOf('(');
        return p < 0 ? s : s.substring(0, p);
    }

    // ---------- semantics ----------

    /** Can this instruction raise an exception that a surrounding try block could catch? */
    public boolean canThrow() {
        switch (kind) {
            case INVOKE: case FIELD_GET: case FIELD_PUT: case ARRAY_GET: case ARRAY_PUT: case NEW_INSTANCE:
            case NEW_ARRAY: case FILLED_ARRAY: case FILL_ARRAY_DATA: case CHECK_CAST: case ARRAY_LENGTH:
            case MONITOR: case THROW:
                return true;
            case CONST:
                return op.equals("const-class") || op.startsWith("const-method");
            case BINOP: {
                String b = base(op);
                if (!(b.equals("div") || b.equals("rem"))) return false;
                String t = typeOf(op);
                return t.equals("int") || t.equals("long");
            }
            default:
                return false;
        }
    }

    /** True when control never continues to the next instruction. */
    public boolean endsFlow() {
        return kind == Kind.GOTO || kind == Kind.RETURN || kind == Kind.THROW;
    }

    @Override
    public String toString() {
        return index + ": " + text();
    }

    // ---------- opcode tables ----------

    static String base(String op) {
        int d = op.indexOf('-');
        return d < 0 ? op : op.substring(0, d);
    }

    /** "int" of "add-int/2addr", "long" of "neg-long"; "" when the op has no type part. */
    static String typeOf(String op) {
        int d = op.indexOf('-');
        if (d < 0) return "";
        String r = op.substring(d + 1);
        int sl = r.indexOf('/');
        return sl < 0 ? r : r.substring(0, sl);
    }

    static boolean wideType(String t) {
        return t.equals("long") || t.equals("double");
    }

    static Kind kindOf(String op) {
        if (op.equals("nop")) return Kind.NOP;
        if (op.startsWith("move-result")) return Kind.MOVE_RESULT;
        if (op.equals("move-exception")) return Kind.MOVE_EXCEPTION;
        if (op.startsWith("move")) return Kind.MOVE;
        if (op.startsWith("return")) return Kind.RETURN;
        if (op.startsWith("const")) return Kind.CONST;
        if (op.startsWith("monitor-")) return Kind.MONITOR;
        if (op.equals("check-cast")) return Kind.CHECK_CAST;
        if (op.equals("instance-of")) return Kind.INSTANCE_OF;
        if (op.equals("array-length")) return Kind.ARRAY_LENGTH;
        if (op.equals("new-instance")) return Kind.NEW_INSTANCE;
        if (op.equals("new-array")) return Kind.NEW_ARRAY;
        if (op.startsWith("filled-new-array")) return Kind.FILLED_ARRAY;
        if (op.equals("fill-array-data")) return Kind.FILL_ARRAY_DATA;
        if (op.equals("throw")) return Kind.THROW;
        if (op.startsWith("goto")) return Kind.GOTO;
        if (op.equals("packed-switch") || op.equals("sparse-switch")) return Kind.SWITCH;
        if (op.startsWith("cmp")) return Kind.CMP;
        if (op.startsWith("if-")) return Kind.IF;
        if (op.startsWith("aget")) return Kind.ARRAY_GET;
        if (op.startsWith("aput")) return Kind.ARRAY_PUT;
        if (op.startsWith("iget") || op.startsWith("sget")) return Kind.FIELD_GET;
        if (op.startsWith("iput") || op.startsWith("sput")) return Kind.FIELD_PUT;
        if (op.startsWith("invoke-")) return Kind.INVOKE;
        if (op.contains("-to-")) return Kind.UNOP;
        switch (base(op)) {
            case "neg": case "not":
                return Kind.UNOP;
            case "add": case "sub": case "mul": case "div": case "rem": case "and": case "or": case "xor":
            case "shl": case "shr": case "ushr": case "rsub":
                return Kind.BINOP;
            default:
                return Kind.OTHER;
        }
    }
}
