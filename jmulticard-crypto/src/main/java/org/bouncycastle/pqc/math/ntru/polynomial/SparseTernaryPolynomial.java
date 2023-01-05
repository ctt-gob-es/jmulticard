package org.bouncycastle.pqc.math.ntru.polynomial;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.pqc.math.ntru.util.ArrayEncoder;
import org.bouncycastle.pqc.math.ntru.util.Util;
import org.bouncycastle.util.Arrays;

/**
 * A <code>TernaryPolynomial</code> with a "low" number of nonzero coefficients.
 */
public class SparseTernaryPolynomial
    implements TernaryPolynomial
{
    /**
     * Number of bits to use for each coefficient. Determines the upper bound for <code>N</code>.
     */
    private static final int BITS_PER_INDEX = 11;

    private final int N;
    private int[] ones;
    private int[] negOnes;

    /**
     * Constructs a new polynomial.
     *
     * @param N       total number of coefficients including zeros
     * @param ones    indices of coefficients equal to 1
     * @param negOnes indices of coefficients equal to -1
     */
    SparseTernaryPolynomial(final int N, final int[] ones, final int[] negOnes)
    {
        this.N = N;
        this.ones = ones;
        this.negOnes = negOnes;
    }

    /**
     * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     *
     * @param intPoly the original polynomial
     */
    public SparseTernaryPolynomial(final IntegerPolynomial intPoly)
    {
        this(intPoly.coeffs);
    }

    /**
     * Constructs a new <code>SparseTernaryPolynomial</code> with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    public SparseTernaryPolynomial(final int[] coeffs)
    {
        N = coeffs.length;
        ones = new int[N];
        negOnes = new int[N];
        int onesIdx = 0;
        int negOnesIdx = 0;
        for (int i = 0; i < N; i++)
        {
            final int c = coeffs[i];
            switch (c)
            {
            case 1:
                ones[onesIdx++] = i;
                break;
            case -1:
                negOnes[negOnesIdx++] = i;
                break;
            case 0:
                break;
            default:
                throw new IllegalArgumentException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
        ones = Arrays.copyOf(ones, onesIdx);
        negOnes = Arrays.copyOf(negOnes, negOnesIdx);
    }

    /**
     * Decodes a byte array encoded with {@link #toBinary()} to a ploynomial.
     *
     * @param is         an input stream containing an encoded polynomial
     * @param N          number of coefficients including zeros
     * @param numOnes    number of coefficients equal to 1
     * @param numNegOnes number of coefficients equal to -1
     * @return the decoded polynomial
     * @throws IOException
     */
    public static SparseTernaryPolynomial fromBinary(final InputStream is, final int N, final int numOnes, final int numNegOnes)
        throws IOException
    {
        final int maxIndex = 1 << BITS_PER_INDEX;
        final int bitsPerIndex = 32 - Integer.numberOfLeadingZeros(maxIndex - 1);

        final int data1Len = (numOnes * bitsPerIndex + 7) / 8;
        final byte[] data1 = Util.readFullLength(is, data1Len);
        final int[] ones = ArrayEncoder.decodeModQ(data1, numOnes, maxIndex);

        final int data2Len = (numNegOnes * bitsPerIndex + 7) / 8;
        final byte[] data2 = Util.readFullLength(is, data2Len);
        final int[] negOnes = ArrayEncoder.decodeModQ(data2, numNegOnes, maxIndex);

        return new SparseTernaryPolynomial(N, ones, negOnes);
    }

    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     *
     * @param N          number of coefficients
     * @param numOnes    number of 1's
     * @param numNegOnes number of -1's
     */
    public static SparseTernaryPolynomial generateRandom(final int N, final int numOnes, final int numNegOnes, final SecureRandom random)
    {
        final int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes, random);
        return new SparseTernaryPolynomial(coeffs);
    }

    @Override
	public IntegerPolynomial mult(final IntegerPolynomial poly2)
    {
        final int[] b = poly2.coeffs;
        if (b.length != N)
        {
            throw new IllegalArgumentException("Number of coefficients must be the same");
        }

        final int[] c = new int[N];
        for (final int i : ones) {
            int j = N - 1 - i;
            for (int k = N - 1; k >= 0; k--)
            {
                c[k] += b[j];
                j--;
                if (j < 0)
                {
                    j = N - 1;
                }
            }
        }

        for (final int i : negOnes) {
            int j = N - 1 - i;
            for (int k = N - 1; k >= 0; k--)
            {
                c[k] -= b[j];
                j--;
                if (j < 0)
                {
                    j = N - 1;
                }
            }
        }

        return new IntegerPolynomial(c);
    }

    @Override
	public IntegerPolynomial mult(final IntegerPolynomial poly2, final int modulus)
    {
        final IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    @Override
	public BigIntPolynomial mult(final BigIntPolynomial poly2)
    {
        final BigInteger[] b = poly2.coeffs;
        if (b.length != N)
        {
            throw new IllegalArgumentException("Number of coefficients must be the same");
        }

        final BigInteger[] c = new BigInteger[N];
        for (int i = 0; i < N; i++)
        {
            c[i] = BigInteger.ZERO;
        }

        for (final int i : ones) {
            int j = N - 1 - i;
            for (int k = N - 1; k >= 0; k--)
            {
                c[k] = c[k].add(b[j]);
                j--;
                if (j < 0)
                {
                    j = N - 1;
                }
            }
        }

        for (final int i : negOnes) {
            int j = N - 1 - i;
            for (int k = N - 1; k >= 0; k--)
            {
                c[k] = c[k].subtract(b[j]);
                j--;
                if (j < 0)
                {
                    j = N - 1;
                }
            }
        }

        return new BigIntPolynomial(c);
    }

    @Override
	public int[] getOnes()
    {
        return ones;
    }

    @Override
	public int[] getNegOnes()
    {
        return negOnes;
    }

    /**
     * Encodes the polynomial to a byte array writing <code>BITS_PER_INDEX</code> bits for each coefficient.
     *
     * @return the encoded polynomial
     */
    public byte[] toBinary()
    {
        final int maxIndex = 1 << BITS_PER_INDEX;
        final byte[] bin1 = ArrayEncoder.encodeModQ(ones, maxIndex);
        final byte[] bin2 = ArrayEncoder.encodeModQ(negOnes, maxIndex);

        final byte[] bin = Arrays.copyOf(bin1, bin1.length + bin2.length);
        System.arraycopy(bin2, 0, bin, bin1.length, bin2.length);
        return bin;
    }

    @Override
	public IntegerPolynomial toIntegerPolynomial()
    {
        final int[] coeffs = new int[N];
        for (final int one : ones) {
            final int i = one;
            coeffs[i] = 1;
        }
        for (final int negOne : negOnes) {
            final int i = negOne;
            coeffs[i] = -1;
        }
        return new IntegerPolynomial(coeffs);
    }

    @Override
	public int size()
    {
        return N;
    }

    @Override
	public void clear()
    {
        java.util.Arrays.fill(ones, 0);
        java.util.Arrays.fill(negOnes, 0);
    }

    @Override
	public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + Arrays.hashCode(negOnes);
        return prime * result + Arrays.hashCode(ones);
    }

    @Override
	public boolean equals(final Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if ((obj == null) || (getClass() != obj.getClass()))
        {
            return false;
        }
        final SparseTernaryPolynomial other = (SparseTernaryPolynomial)obj;
        if (N != other.N)
        {
            return false;
        }
        if (!Arrays.areEqual(negOnes, other.negOnes))
        {
            return false;
        }
        if (!Arrays.areEqual(ones, other.ones))
        {
            return false;
        }
        return true;
    }
}
