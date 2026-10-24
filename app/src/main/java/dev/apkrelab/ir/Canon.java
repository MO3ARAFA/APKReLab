package dev.apkrelab.ir;

/**
 * 0.104.3: one shared copy of the strings that repeat across a whole app (an instruction's line up to its reference, the reference, a label). A fixed table of the last string
 * seen per hash slot, no lock: two threads racing on a slot only lose a little sharing (a reference write is atomic, and a String is immutable). Equal strings in, an equal
 * string out: callers see exactly the text they gave. Lossy on purpose: a slot holds one string, so the table never grows (at most SLOTS strings stay reachable through it,
 * an estimated 4-6 MB, not measured), unlike String.intern, which measured 2.6 times slower parsing on the JVM (a global lock).
 */
final class Canon {
    private static final int BITS = 16, SLOTS = 1 << BITS;
    private static final String[] TABLE = new String[SLOTS];

    private Canon() {
    }

    static String of(String s) {
        int h = s.hashCode();
        int i = (h ^ (h >>> BITS)) & (SLOTS - 1);
        String c = TABLE[i];
        if (c != null && c.equals(s)) return c;
        TABLE[i] = s;
        return s;
    }
}
