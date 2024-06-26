package org.bouncycastle.math.raw;

public abstract class Bits {

    public static int bitPermuteStep(final int x, final int m, final int s) {
        final int t = (x ^ x >>> s) & m;
        return  t ^ t <<  s ^ x;
    }

    public static long bitPermuteStep(final long x, final long m, final int s) {
        final long t = (x ^ x >>> s) & m;
        return   t ^ t <<  s ^ x;
    }

    public static int bitPermuteStepSimple(final int x, final int m, final int s) {
        return (x & m) << s | x >>> s & m;
    }

    public static long bitPermuteStepSimple(final long x, final long m, final int s) {
        return (x & m) << s | x >>> s & m;
    }
}
