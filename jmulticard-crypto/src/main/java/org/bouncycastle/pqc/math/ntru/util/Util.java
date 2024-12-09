package org.bouncycastle.pqc.math.ntru.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.pqc.math.ntru.euclid.IntEuclidean;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
import org.bouncycastle.util.Integers;

public class Util
{
    private static volatile boolean IS_64_BITNESS_KNOWN;
    private static volatile boolean IS_64_BIT_JVM;

    /**
     * Calculates the inverse of n mod modulus
     * @param n Number.
     * @param modulus Modulus.
     * @return Inverted value.
     */
    public static int invert(int n, final int modulus)
    {
        n %= modulus;
        if (n < 0)
        {
            n += modulus;
        }
        return IntEuclidean.calculate(n, modulus).x;
    }

    /**
     * Calculates a^b mod modulus
     * @param a First number.
     * @param b Second number.
     * @param modulus Modulus.
     * @return result.
     */
    public static int pow(final int a, final int b, final int modulus)
    {
        int p = 1;
        for (int i = 0; i < b; i++)
        {
            p = p * a % modulus;
        }
        return p;
    }

    /**
     * Calculates a^b mod modulus
     * @param a First number.
     * @param b Second number.
     * @param modulus Modulus.
     * @return result.
     */
    public static long pow(final long a, final int b, final long modulus)
    {
        long p = 1;
        for (int i = 0; i < b; i++)
        {
            p = p * a % modulus;
        }
        return p;
    }

    /**
     * Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     *
     * @param N Number
     * @param numOnes Positives
     * @param numNegOnes Negatives
     * @param sparse     whether to create a {@link SparseTernaryPolynomial} or {@link DenseTernaryPolynomial}
     * @param random Secure random.
     * @return a ternary polynomial
     */
    public static TernaryPolynomial generateRandomTernary(final int N, final int numOnes, final int numNegOnes, final boolean sparse, final SecureRandom random)
    {
        if (sparse)
        {
            return SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
        }
        else
        {
            return DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
        }
    }

    /**
     * Generates an array containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     *
     * @param N Number
     * @param numOnes Positives
     * @param numNegOnes Negatives
     * @param random Secure random.
     * @return an array of integers
     */
    public static int[] generateRandomTernary(final int N, final int numOnes, final int numNegOnes, final SecureRandom random)
    {
        final Integer one = Integers.valueOf(1);
        final Integer minusOne = Integers.valueOf(-1);
        final Integer zero = Integers.valueOf(0);

        final List list = new ArrayList();
        for (int i = 0; i < numOnes; i++)
        {
            list.add(one);
        }
        for (int i = 0; i < numNegOnes; i++)
        {
            list.add(minusOne);
        }
        while (list.size() < N)
        {
            list.add(zero);
        }

        Collections.shuffle(list, random);

        final int[] arr = new int[N];
        for (int i = 0; i < N; i++)
        {
            arr[i] = ((Integer)list.get(i)).intValue();
        }
        return arr;
    }

    /**
     * Takes an educated guess as to whether 64 bits are supported by the JVM.
     *
     * @return <code>true</code> if 64-bit support detected, <code>false</code> otherwise
     */
    public static boolean is64BitJVM()
    {
        if (!IS_64_BITNESS_KNOWN)
        {
            final String arch = System.getProperty("os.arch");
            final String sunModel = System.getProperty("sun.arch.data.model");
            IS_64_BIT_JVM = "amd64".equals(arch) || "x86_64".equals(arch) || "ppc64".equals(arch) || "64".equals(sunModel);
            IS_64_BITNESS_KNOWN = true;
        }
        return IS_64_BIT_JVM;
    }

    /**
     * Reads a given number of bytes from an <code>InputStream</code>.
     * If there are not enough bytes in the stream, an <code>IOException</code>
     * is thrown.
     *
     * @param is InputStream.
     * @param length Number of bytes.
     * @return an array of length <code>length</code>
     * @throws IOException If IO error occurs.
     */
    public static byte[] readFullLength(final InputStream is, final int length)
        throws IOException
    {
        final byte[] arr = new byte[length];
        if (is.read(arr) != arr.length)
        {
            throw new IOException("Not enough bytes to read.");
        }
        return arr;
    }
}