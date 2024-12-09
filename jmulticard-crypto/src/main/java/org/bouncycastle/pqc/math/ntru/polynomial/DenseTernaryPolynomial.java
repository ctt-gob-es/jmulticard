package org.bouncycastle.pqc.math.ntru.polynomial;

import java.security.SecureRandom;

import org.bouncycastle.pqc.math.ntru.util.Util;
import org.bouncycastle.util.Arrays;

/**
 * A <code>TernaryPolynomial</code> with a "high" number of nonzero coefficients.
 */
public class DenseTernaryPolynomial
    extends IntegerPolynomial
    implements TernaryPolynomial
{

    /**
     * Constructs a new <code>DenseTernaryPolynomial</code> with <code>N</code> coefficients.
     *
     * @param N the number of coefficients
     */
    DenseTernaryPolynomial(final int N)
    {
        super(N);
        checkTernarity();
    }

    /**
     * Constructs a <code>DenseTernaryPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     *
     * @param intPoly the original polynomial
     */
    public DenseTernaryPolynomial(final IntegerPolynomial intPoly)
    {
        this(intPoly.coeffs);
    }

    /**
     * Constructs a new <code>DenseTernaryPolynomial</code> with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    public DenseTernaryPolynomial(final int[] coeffs)
    {
        super(coeffs);
        checkTernarity();
    }

    private void checkTernarity()
    {
        for (int i = 0; i != this.coeffs.length; i++)
        {
            final int c = this.coeffs[i];
            if (c < -1 || c > 1)
            {
                throw new IllegalStateException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
    }

    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     *
     * @param N          number of coefficients
     * @param numOnes    number of 1's
     * @param numNegOnes number of -1's
     * @param random Secure random.
     * @return Random value.
     */
    public static DenseTernaryPolynomial generateRandom(final int N, final int numOnes, final int numNegOnes, final SecureRandom random)
    {
        final int[] coeffs = Util.generateRandomTernary(N, numOnes, numNegOnes, random);
        return new DenseTernaryPolynomial(coeffs);
    }

    /**
     * Generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
     *
     * @param N number of coefficients
     * @param random Secure random.
     * @param random Secure random.
     * @return Random value.
     */
    public static DenseTernaryPolynomial generateRandom(final int N, final SecureRandom random)
    {
        final DenseTernaryPolynomial poly = new DenseTernaryPolynomial(N);
        for (int i = 0; i < N; i++)
        {
            poly.coeffs[i] = random.nextInt(3) - 1;
        }
        return poly;
    }

    @Override
	public IntegerPolynomial mult(final IntegerPolynomial poly2, final int modulus)
    {
        // even on 32-bit systems, LongPolynomial5 multiplies faster than IntegerPolynomial
        if (modulus == 2048)
        {
            final IntegerPolynomial poly2Pos = (IntegerPolynomial)poly2.clone();
            poly2Pos.modPositive(2048);
            final LongPolynomial5 poly5 = new LongPolynomial5(poly2Pos);
            return poly5.mult(this).toIntegerPolynomial();
        }
        else
        {
            return super.mult(poly2, modulus);
        }
    }

    @Override
	public int[] getOnes()
    {
        final int N = this.coeffs.length;
        final int[] ones = new int[N];
        int onesIdx = 0;
        for (int i = 0; i < N; i++)
        {
            final int c = this.coeffs[i];
            if (c == 1)
            {
                ones[onesIdx++] = i;
            }
        }
        return Arrays.copyOf(ones, onesIdx);
    }

    @Override
	public int[] getNegOnes()
    {
        final int N = this.coeffs.length;
        final int[] negOnes = new int[N];
        int negOnesIdx = 0;
        for (int i = 0; i < N; i++)
        {
            final int c = this.coeffs[i];
            if (c == -1)
            {
                negOnes[negOnesIdx++] = i;
            }
        }
        return Arrays.copyOf(negOnes, negOnesIdx);
    }

    @Override
	public int size()
    {
        return this.coeffs.length;
    }
}
