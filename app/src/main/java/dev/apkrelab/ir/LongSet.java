package dev.apkrelab.ir;

/**
 * 0.101.0: a set of longs in one open-addressing array (8 bytes per slot, no boxing, no node objects). The call graph keeps one entry per candidate edge; a HashSet of
 * strings or of small sets per (caller, callee) pair kept hundreds of bytes per edge alive and drove the garbage collector (43% of the run time at a 1 GB heap).
 */
final class LongSet {
    private long[] table = new long[64];
    private int size;
    private boolean hasZero;

    /** @return true when {@code k} was not in the set yet. */
    boolean add(long k) {
        if (k == 0) {
            if (hasZero) return false;
            hasZero = true;
            return true;
        }
        if ((size + 1) * 2 > table.length) grow();
        int mask = table.length - 1;
        int i = mix(k) & mask;
        while (table[i] != 0) {
            if (table[i] == k) return false;
            i = (i + 1) & mask;
        }
        table[i] = k;
        size++;
        return true;
    }

    int size() { return size + (hasZero ? 1 : 0); }

    private void grow() {
        long[] old = table;
        table = new long[old.length * 2];
        int mask = table.length - 1;
        for (long k : old) {
            if (k == 0) continue;
            int i = mix(k) & mask;
            while (table[i] != 0) i = (i + 1) & mask;
            table[i] = k;
        }
    }

    private static int mix(long k) {
        k ^= k >>> 33;
        k *= 0xff51afd7ed558ccdL;
        k ^= k >>> 33;
        return (int) k;
    }
}
