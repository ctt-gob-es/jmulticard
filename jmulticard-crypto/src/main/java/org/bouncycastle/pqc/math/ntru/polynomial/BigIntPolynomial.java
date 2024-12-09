package org.bouncycastle.pqc.math.ntru.polynomial;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Arrays;

/**
 * A polynomial with {@link BigInteger} coefficients.<br>
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class BigIntPolynomial
{
    private final static double LOG_10_2 = Math.log10(2);

    BigInteger[] coeffs;

    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     *
     * @param N the number of coefficients
     */
    BigIntPolynomial(final int N)
    {
        this.coeffs = new BigInteger[N];
        for (int i = 0; i < N; i++)
        {
            this.coeffs[i] = Constants.BIGINT_ZERO;
        }
    }

    /**
     * Constructs a new polynomial with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    BigIntPolynomial(final BigInteger[] coeffs)
    {
        this.coeffs = coeffs;
    }

    /**
     * Constructs a <code>BigIntPolynomial</code> from a <code>IntegerPolynomial</code>. The two polynomials are
     * independent of each other.
     *
     * @param p the original polynomial
     */
    public BigIntPolynomial(final IntegerPolynomial p)
    {
        this.coeffs = new BigInteger[p.coeffs.length];
        for (int i = 0; i < this.coeffs.length; i++)
        {
            this.coeffs[i] = BigInteger.valueOf(p.coeffs[i]);
        }
    }

    /**
     * Generates a random polynomial with <code>numOnes</code> coefficients equal to 1,
     * <code>numNegOnes</code> coefficients equal to -1, and the rest equal to 0.
     *
     * @param N          number of coefficients
     * @param numOnes    number of 1's
     * @param numNegOnes number of -1's
     * @return a random polynomial.
     */
    static BigIntPolynomial generateRandomSmall(final int N, final int numOnes, final int numNegOnes)
    {
        final List coeffs = new ArrayList();
        for (int i = 0; i < numOnes; i++)
        {
            coeffs.add(Constants.BIGINT_ONE);
        }
        for (int i = 0; i < numNegOnes; i++)
        {
            coeffs.add(BigInteger.valueOf(-1));
        }
        while (coeffs.size() < N)
        {
            coeffs.add(Constants.BIGINT_ZERO);
        }
        Collections.shuffle(coeffs, CryptoServicesRegistrar.getSecureRandom());

        final BigIntPolynomial poly = new BigIntPolynomial(N);
        for (int i = 0; i < coeffs.size(); i++)
        {
            poly.coeffs[i] = (BigInteger)coeffs.get(i);
        }
        return poly;
    }

    /**
     * Multiplies the polynomial by another, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br>
     * Both polynomials must have the same number of coefficients.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public BigIntPolynomial mult(final BigIntPolynomial poly2)
    {
        final int N = this.coeffs.length;
        if (poly2.coeffs.length != N)
        {
            throw new IllegalArgumentException("Number of coefficients must be the same");
        }

        final BigIntPolynomial c = multRecursive(poly2);

        if (c.coeffs.length > N)
        {
            for (int k = N; k < c.coeffs.length; k++)
            {
                c.coeffs[k - N] = c.coeffs[k - N].add(c.coeffs[k]);
            }
            c.coeffs = Arrays.copyOf(c.coeffs, N);
        }
        return c;
    }

    /**
     * Karazuba multiplication
     */
    private BigIntPolynomial multRecursive(final BigIntPolynomial poly2)
    {
        final BigInteger[] a = this.coeffs;
        final BigInteger[] b = poly2.coeffs;

        final int n = poly2.coeffs.length;
        if (n <= 1)
        {
            final BigInteger[] c = Arrays.clone(this.coeffs);
            for (int i = 0; i < this.coeffs.length; i++)
            {
                c[i] = c[i].multiply(poly2.coeffs[0]);
            }
            return new BigIntPolynomial(c);
        }
        else
        {
            final int n1 = n / 2;

            final BigIntPolynomial a1 = new BigIntPolynomial(Arrays.copyOf(a, n1));
            final BigIntPolynomial a2 = new BigIntPolynomial(Arrays.copyOfRange(a, n1, n));
            final BigIntPolynomial b1 = new BigIntPolynomial(Arrays.copyOf(b, n1));
            final BigIntPolynomial b2 = new BigIntPolynomial(Arrays.copyOfRange(b, n1, n));

            final BigIntPolynomial A = (BigIntPolynomial)a1.clone();
            A.add(a2);
            final BigIntPolynomial B = (BigIntPolynomial)b1.clone();
            B.add(b2);

            final BigIntPolynomial c1 = a1.multRecursive(b1);
            final BigIntPolynomial c2 = a2.multRecursive(b2);
            final BigIntPolynomial c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);

            final BigIntPolynomial c = new BigIntPolynomial(2 * n - 1);
            for (int i = 0; i < c1.coeffs.length; i++)
            {
                c.coeffs[i] = c1.coeffs[i];
            }
            for (int i = 0; i < c3.coeffs.length; i++)
            {
                c.coeffs[n1 + i] = c.coeffs[n1 + i].add(c3.coeffs[i]);
            }
            for (int i = 0; i < c2.coeffs.length; i++)
            {
                c.coeffs[2 * n1 + i] = c.coeffs[2 * n1 + i].add(c2.coeffs[i]);
            }
            return c;
        }
    }

    /**
     * Adds another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     *
     * @param b another polynomial
     */
    void add(final BigIntPolynomial b, final BigInteger modulus)
    {
        add(b);
        mod(modulus);
    }

    /**
     * Adds another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void add(final BigIntPolynomial b)
    {
        if (b.coeffs.length > this.coeffs.length)
        {
            final int N = this.coeffs.length;
            this.coeffs = Arrays.copyOf(this.coeffs, b.coeffs.length);
            for (int i = N; i < this.coeffs.length; i++)
            {
                this.coeffs[i] = Constants.BIGINT_ZERO;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            this.coeffs[i] = this.coeffs[i].add(b.coeffs[i]);
        }
    }

    /**
     * Subtracts another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void sub(final BigIntPolynomial b)
    {
        if (b.coeffs.length > this.coeffs.length)
        {
            final int N = this.coeffs.length;
            this.coeffs = Arrays.copyOf(this.coeffs, b.coeffs.length);
            for (int i = N; i < this.coeffs.length; i++)
            {
                this.coeffs[i] = Constants.BIGINT_ZERO;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            this.coeffs[i] = this.coeffs[i].subtract(b.coeffs[i]);
        }
    }

    /**
     * Multiplies each coefficient by a <code>BigInteger</code>. Does not return
     * a new polynomial but modifies this polynomial.
     *
     * @param factor Multiplicator factor.
     */
    public void mult(final BigInteger factor)
    {
        for (int i = 0; i < this.coeffs.length; i++)
        {
            this.coeffs[i] = this.coeffs[i].multiply(factor);
        }
    }

    /**
     * Multiplies each coefficient by a <code>int</code>. Does not return a new
     * polynomial but modifies this polynomial.
     *
     * @param factor Multiplicator factor.
     */
    void mult(final int factor)
    {
        mult(BigInteger.valueOf(factor));
    }

    /**
     * Divides each coefficient by a <code>BigInteger</code> and rounds the result to the nearest whole number.<br>
     * Does not return a new polynomial but modifies this polynomial.
     *
     * @param divisor the number to divide by
     */
    public void div(final BigInteger divisor)
    {
        final BigInteger d = divisor.add(Constants.BIGINT_ONE).divide(BigInteger.valueOf(2));
        for (int i = 0; i < this.coeffs.length; i++)
        {
            this.coeffs[i] = this.coeffs[i].compareTo(Constants.BIGINT_ZERO) > 0 ? this.coeffs[i].add(d) : this.coeffs[i].add(d.negate());
            this.coeffs[i] = this.coeffs[i].divide(divisor);
        }
    }

    /**
     * Divides each coefficient by a <code>BigDecimal</code> and rounds the result to <code>decimalPlaces</code> places.
     *
     * @param divisor       the number to divide by
     * @param decimalPlaces the number of fractional digits to round the result to
     * @return a new <code>BigDecimalPolynomial</code>
     */
    public BigDecimalPolynomial div(final BigDecimal divisor, final int decimalPlaces)
    {
        final BigInteger max = maxCoeffAbs();
        final int coeffLength = (int)(max.bitLength() * LOG_10_2) + 1;
        // factor = 1/divisor
        final BigDecimal factor = Constants.BIGDEC_ONE.divide(divisor, coeffLength + decimalPlaces + 1, BigDecimal.ROUND_HALF_EVEN);

        // multiply each coefficient by factor
        final BigDecimalPolynomial p = new BigDecimalPolynomial(this.coeffs.length);
        for (int i = 0; i < this.coeffs.length; i++)
        // multiply, then truncate after decimalPlaces so subsequent operations aren't slowed down
        {
            p.coeffs[i] = new BigDecimal(this.coeffs[i]).multiply(factor).setScale(decimalPlaces, BigDecimal.ROUND_HALF_EVEN);
        }

        return p;
    }

    /**
     * Returns the base10 length of the largest coefficient.
     *
     * @return length of the longest coefficient
     */
    public int getMaxCoeffLength()
    {
        return (int)(maxCoeffAbs().bitLength() * LOG_10_2) + 1;
    }

    private BigInteger maxCoeffAbs()
    {
        BigInteger max = this.coeffs[0].abs();
        for (int i = 1; i < this.coeffs.length; i++)
        {
            final BigInteger coeff = this.coeffs[i].abs();
            if (coeff.compareTo(max) > 0)
            {
                max = coeff;
            }
        }
        return max;
    }

    /**
     * Takes each coefficient modulo a number.
     *
     * @param modulus The modulus.
     */
    public void mod(final BigInteger modulus)
    {
        for (int i = 0; i < this.coeffs.length; i++)
        {
            this.coeffs[i] = this.coeffs[i].mod(modulus);
        }
    }

    /**
     * Returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
     *
     * @return the sum of all coefficients
     */
    BigInteger sumCoeffs()
    {
        BigInteger sum = Constants.BIGINT_ZERO;
        for (int i = 0; i < this.coeffs.length; i++)
        {
            sum = sum.add(this.coeffs[i]);
        }
        return sum;
    }

    /**
     * Makes a copy of the polynomial that is independent of the original.
     */
    @Override
	public Object clone()
    {
        return new BigIntPolynomial(this.coeffs.clone());
    }

    @Override
	public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(this.coeffs);
        return result;
    }

    @Override
	public boolean equals(final Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (getClass() != obj.getClass())
        {
            return false;
        }
        final BigIntPolynomial other = (BigIntPolynomial)obj;
        if (!Arrays.areEqual(this.coeffs, other.coeffs))
        {
            return false;
        }
        return true;
    }

    public BigInteger[] getCoeffs()
    {
        return Arrays.clone(this.coeffs);
    }
}
