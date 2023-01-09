package org.bouncycastle.pqc.math.ntru.polynomial;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

/**
 * A polynomial of the form <code>f1*f2+f3</code>, where
 * <code>f1,f2,f3</code> are very sparsely populated ternary polynomials.
 */
public class ProductFormPolynomial
    implements Polynomial
{
    private final SparseTernaryPolynomial f1, f2, f3;

    public ProductFormPolynomial(final SparseTernaryPolynomial f1, final SparseTernaryPolynomial f2, final SparseTernaryPolynomial f3)
    {
        this.f1 = f1;
        this.f2 = f2;
        this.f3 = f3;
    }

    public static ProductFormPolynomial generateRandom(final int N, final int df1, final int df2, final int df3Ones, final int df3NegOnes, final SecureRandom random)
    {
        final SparseTernaryPolynomial f1 = SparseTernaryPolynomial.generateRandom(N, df1, df1, random);
        final SparseTernaryPolynomial f2 = SparseTernaryPolynomial.generateRandom(N, df2, df2, random);
        final SparseTernaryPolynomial f3 = SparseTernaryPolynomial.generateRandom(N, df3Ones, df3NegOnes, random);
        return new ProductFormPolynomial(f1, f2, f3);
    }

    public static ProductFormPolynomial fromBinary(final byte[] data, final int N, final int df1, final int df2, final int df3Ones, final int df3NegOnes)
        throws IOException
    {
        return fromBinary(new ByteArrayInputStream(data), N, df1, df2, df3Ones, df3NegOnes);
    }

    public static ProductFormPolynomial fromBinary(final InputStream is, final int N, final int df1, final int df2, final int df3Ones, final int df3NegOnes)
        throws IOException
    {
        SparseTernaryPolynomial f1;

        f1 = SparseTernaryPolynomial.fromBinary(is, N, df1, df1);
        final SparseTernaryPolynomial f2 = SparseTernaryPolynomial.fromBinary(is, N, df2, df2);
        final SparseTernaryPolynomial f3 = SparseTernaryPolynomial.fromBinary(is, N, df3Ones, df3NegOnes);
        return new ProductFormPolynomial(f1, f2, f3);
    }

    public byte[] toBinary()
    {
        final byte[] f1Bin = f1.toBinary();
        final byte[] f2Bin = f2.toBinary();
        final byte[] f3Bin = f3.toBinary();

        final byte[] all = Arrays.copyOf(f1Bin, f1Bin.length + f2Bin.length + f3Bin.length);
        System.arraycopy(f2Bin, 0, all, f1Bin.length, f2Bin.length);
        System.arraycopy(f3Bin, 0, all, f1Bin.length + f2Bin.length, f3Bin.length);
        return all;
    }

    @Override
	public IntegerPolynomial mult(final IntegerPolynomial b)
    {
        IntegerPolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    @Override
	public BigIntPolynomial mult(final BigIntPolynomial b)
    {
        BigIntPolynomial c = f1.mult(b);
        c = f2.mult(c);
        c.add(f3.mult(b));
        return c;
    }

    @Override
	public IntegerPolynomial toIntegerPolynomial()
    {
        final IntegerPolynomial i = f1.mult(f2.toIntegerPolynomial());
        i.add(f3.toIntegerPolynomial());
        return i;
    }

    @Override
	public IntegerPolynomial mult(final IntegerPolynomial poly2, final int modulus)
    {
        final IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    @Override
	public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + (f1 == null ? 0 : f1.hashCode());
        result = prime * result + (f2 == null ? 0 : f2.hashCode());
        return prime * result + (f3 == null ? 0 : f3.hashCode());
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
        final ProductFormPolynomial other = (ProductFormPolynomial)obj;
        if (f1 == null)
        {
            if (other.f1 != null)
            {
                return false;
            }
        }
        else if (!f1.equals(other.f1))
        {
            return false;
        }
        if (f2 == null)
        {
            if (other.f2 != null)
            {
                return false;
            }
        }
        else if (!f2.equals(other.f2))
        {
            return false;
        }
        if (f3 == null)
        {
            if (other.f3 != null)
            {
                return false;
            }
        }
        else if (!f3.equals(other.f3))
        {
            return false;
        }
        return true;
    }
}
