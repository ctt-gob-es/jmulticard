package org.bouncycastle.pqc.math.ntru.polynomial;

import org.bouncycastle.util.Arrays;

/**
 * A polynomial class that combines five coefficients into one <code>long</code> value for
 * faster multiplication by a ternary polynomial.<br>
 * Coefficients can be between 0 and 2047 and are stored in bits 0..11, 12..23, ..., 48..59 of a <code>long</code> number.
 */
public class LongPolynomial5
{
    private final long[] coeffs;   // groups of 5 coefficients
    private final int numCoeffs;

    /**
     * Constructs a <code>LongPolynomial5</code> from a <code>IntegerPolynomial</code>. The two polynomials are independent of each other.
     *
     * @param p the original polynomial. Coefficients must be between 0 and 2047.
     */
    public LongPolynomial5(final IntegerPolynomial p)
    {
        this.numCoeffs = p.coeffs.length;

        this.coeffs = new long[(this.numCoeffs + 4) / 5];
        int cIdx = 0;
        int shift = 0;
        for (int i = 0; i < this.numCoeffs; i++)
        {
            this.coeffs[cIdx] |= (long)p.coeffs[i] << shift;
            shift += 12;
            if (shift >= 60)
            {
                shift = 0;
                cIdx++;
            }
        }
    }

    private LongPolynomial5(final long[] coeffs, final int numCoeffs)
    {
        this.coeffs = coeffs;
        this.numCoeffs = numCoeffs;
    }

    /**
     * Multiplies the polynomial with a <code>TernaryPolynomial</code>, taking the indices mod N and the values mod 2048.
     * @param poly2 Factor.
     * @return Result.
     */
    public LongPolynomial5 mult(final TernaryPolynomial poly2)
    {
        final long[][] prod = new long[5][this.coeffs.length + (poly2.size() + 4) / 5 - 1];   // intermediate results, the subarrays are shifted by 0,...,4 coefficients

        // multiply ones
        final int[] ones = poly2.getOnes();
        for (int idx = 0; idx != ones.length; idx++)
        {
            final int pIdx = ones[idx];
            int cIdx = pIdx / 5;
            final int m = pIdx - cIdx * 5;   // m = pIdx % 5
            for (int i = 0; i < this.coeffs.length; i++)
            {
                prod[m][cIdx] = prod[m][cIdx] + this.coeffs[i] & 0x7FF7FF7FF7FF7FFL;
                cIdx++;
            }
        }

        // multiply negative ones
        final int[] negOnes = poly2.getNegOnes();
        for (int idx = 0; idx != negOnes.length; idx++)
        {
            final int pIdx = negOnes[idx];
            int cIdx = pIdx / 5;
            final int m = pIdx - cIdx * 5;   // m = pIdx % 5
            for (int i = 0; i < this.coeffs.length; i++)
            {
                prod[m][cIdx] = 0x800800800800800L + prod[m][cIdx] - this.coeffs[i] & 0x7FF7FF7FF7FF7FFL;
                cIdx++;
            }
        }

        // combine shifted coefficients (5 arrays) into a single array of length prod[*].length+1
        final long[] cCoeffs = Arrays.copyOf(prod[0], prod[0].length + 1);
        for (int m = 1; m <= 4; m++)
        {
            final int shift = m * 12;
            final int shift60 = 60 - shift;
            final long mask = (1L << shift60) - 1;
            final int pLen = prod[m].length;
            for (int i = 0; i < pLen; i++)
            {
                long upper, lower;
                upper = prod[m][i] >> shift60;
                lower = prod[m][i] & mask;

                cCoeffs[i] = cCoeffs[i] + (lower << shift) & 0x7FF7FF7FF7FF7FFL;
                final int nextIdx = i + 1;
                cCoeffs[nextIdx] = cCoeffs[nextIdx] + upper & 0x7FF7FF7FF7FF7FFL;
            }
        }

        // reduce indices of cCoeffs modulo numCoeffs
        final int shift = 12 * (this.numCoeffs % 5);
        for (int cIdx = this.coeffs.length - 1; cIdx < cCoeffs.length; cIdx++)
        {
            long iCoeff;   // coefficient to shift into the [0..numCoeffs-1] range
            int newIdx;
            if (cIdx == this.coeffs.length - 1)
            {
                iCoeff = this.numCoeffs == 5 ? 0 : cCoeffs[cIdx] >> shift;
                newIdx = 0;
            }
            else
            {
                iCoeff = cCoeffs[cIdx];
                newIdx = cIdx * 5 - this.numCoeffs;
            }

            final int base = newIdx / 5;
            final int m = newIdx - base * 5;   // m = newIdx % 5
            final long lower = iCoeff << 12 * m;
            final long upper = iCoeff >> 12 * (5 - m);
            cCoeffs[base] = cCoeffs[base] + lower & 0x7FF7FF7FF7FF7FFL;
            final int base1 = base + 1;
            if (base1 < this.coeffs.length)
            {
                cCoeffs[base1] = cCoeffs[base1] + upper & 0x7FF7FF7FF7FF7FFL;
            }
        }

        return new LongPolynomial5(cCoeffs, this.numCoeffs);
    }

    public IntegerPolynomial toIntegerPolynomial()
    {
        final int[] intCoeffs = new int[this.numCoeffs];
        int cIdx = 0;
        int shift = 0;
        for (int i = 0; i < this.numCoeffs; i++)
        {
            intCoeffs[i] = (int)(this.coeffs[cIdx] >> shift & 2047);
            shift += 12;
            if (shift >= 60)
            {
                shift = 0;
                cIdx++;
            }
        }
        return new IntegerPolynomial(intCoeffs);
    }
}
