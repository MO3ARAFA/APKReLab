package dev.apkrelab.ir;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/** 0.101.0: the compact set that replaced the string edge keys of the call graph must behave exactly like a HashSet. */
public class LongSetTest {
    @Test
    public void behavesLikeAHashSetOnRandomKeysIncludingZeroAndNegatives() {
        Random r = new Random(7);
        LongSet a = new LongSet();
        Set<Long> b = new HashSet<>();
        for (int i = 0; i < 200_000; i++) {
            long k = (i % 997 == 0) ? 0L : (i % 1009 == 0) ? -r.nextInt(50) : (long) r.nextInt(60_000) << (i % 3 == 0 ? 42 : 0);
            Assert.assertEquals("key " + k + " at " + i, b.add(k), a.add(k));
        }
        Assert.assertEquals(b.size(), a.size());
    }

    @Test
    public void growsAndKeepsEveryKey() {
        LongSet a = new LongSet();
        for (long k = 1; k <= 100_000; k++) Assert.assertTrue(a.add(k * 31));
        for (long k = 1; k <= 100_000; k++) Assert.assertFalse(a.add(k * 31));
        Assert.assertEquals(100_000, a.size());
    }
}
