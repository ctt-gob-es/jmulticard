package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

public class McElieceParameters
    implements CipherParameters
{

    /**
     * The default extension degree
     */
    public static final int DEFAULT_M = 11;

    /**
     * The default error correcting capability.
     */
    public static final int DEFAULT_T = 50;

    /**
     * extension degree of the finite field GF(2^m)
     */
    private int m;

    /**
     * error correction capability of the code
     */
    private int t;

    /**
     * length of the code
     */
    private int n;

    /**
     * the field polynomial
     */
    private int fieldPoly;

    private final Digest digest;

    /**
     * Constructor. Set the default parameters: extension degree.
     */
    public McElieceParameters()
    {
        this(DEFAULT_M, DEFAULT_T);
    }

    public McElieceParameters(final Digest digest)
    {
        this(DEFAULT_M, DEFAULT_T, digest);
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceParameters(final int keysize)
    {
        this(keysize, null);
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @param digest CCA2 mode digest
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceParameters(final int keysize, final Digest digest)
    {
        if (keysize < 1)
        {
            throw new IllegalArgumentException("key size must be positive");
        }
        this.m = 0;
        this.n = 1;
        while (this.n < keysize)
        {
            this.n <<= 1;
            this.m++;
        }
        this.t = this.n >>> 1;
        this.t /= this.m;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.m);
        this.digest = digest;
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceParameters(final int m, final int t)
    {
        this(m, t, null);
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code.
     * @param digest Digest
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceParameters(final int m, final int t, final Digest digest)
    {
        if (m < 1)
        {
            throw new IllegalArgumentException("m must be positive");
        }
        if (m > 32)
        {
            throw new IllegalArgumentException("m is too large");
        }
        this.m = m;
        this.n = 1 << m;
        if (t < 0)
        {
            throw new IllegalArgumentException("t must be positive");
        }
        if (t > this.n)
        {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        this.t = t;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
        this.digest = digest;
    }

    /**
     * Constructor.
     *
     * @param m    degree of the finite field GF(2^m)
     * @param t    error correction capability of the code
     * @param poly the field polynomial
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
     * <tt>poly</tt> is not an irreducible field polynomial.
     */
    public McElieceParameters(final int m, final int t, final int poly)
    {
        this(m, t, poly, null);
    }

    /**
     * Constructor.
     *
     * @param m    degree of the finite field GF(2^m)
     * @param t    error correction capability of the code
     * @param poly the field polynomial
     * @param digest CCA2 mode digest
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
     * <tt>poly</tt> is not an irreducible field polynomial.
     */
    public McElieceParameters(final int m, final int t, final int poly, final Digest digest)
    {
        this.m = m;
        if (m < 1)
        {
            throw new IllegalArgumentException("m must be positive");
        }
        if (m > 32)
        {
            throw new IllegalArgumentException(" m is too large");
        }
        this.n = 1 << m;
        this.t = t;
        if (t < 0)
        {
            throw new IllegalArgumentException("t must be positive");
        }
        if (t > this.n)
        {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        if (PolynomialRingGF2.degree(poly) == m
            && PolynomialRingGF2.isIrreducible(poly))
        {
            this.fieldPoly = poly;
        }
        else
        {
            throw new IllegalArgumentException(
                "polynomial is not a field polynomial for GF(2^m)");
        }
        this.digest = digest;
    }

    /**
     * @return the extension degree of the finite field GF(2^m)
     */
    public int getM()
    {
        return this.m;
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return this.n;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT()
    {
        return this.t;
    }

    /**
     * @return the field polynomial
     */
    public int getFieldPoly()
    {
        return this.fieldPoly;
    }
}
