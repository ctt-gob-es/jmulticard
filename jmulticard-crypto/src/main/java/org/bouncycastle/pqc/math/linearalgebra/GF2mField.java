package org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

/**
 * This class describes operations with elements from the finite field F =
 * GF(2^m). ( GF(2^m)= GF(2)[A] where A is a root of irreducible polynomial with
 * degree m, each field element B has a polynomial basis representation, i.e. it
 * is represented by a different binary polynomial of degree less than m, B =
 * poly(A) ) All operations are defined only for field with 1&lt; m &lt;32. For the
 * representation of field elements the map f: F-&gt;Z, poly(A)-&gt;poly(2) is used,
 * where integers have the binary representation. For example: A^7+A^3+A+1 -&gt;
 * (00...0010001011)=139 Also for elements type Integer is used.
 *
 * @see PolynomialRingGF2
 */
public class GF2mField
{

    /*
      * degree - degree of the field polynomial - the field polynomial ring -
      * polynomial ring over the finite field GF(2)
      */

    private int degree = 0;

    private final int polynomial;

    /**
     * create a finite field GF(2^m)
     *
     * @param degree the degree of the field
     */
    public GF2mField(final int degree)
    {
        if (degree >= 32)
        {
            throw new IllegalArgumentException(
                " Error: the degree of field is too large ");
        }
        if (degree < 1)
        {
            throw new IllegalArgumentException(
                " Error: the degree of field is non-positive ");
        }
        this.degree = degree;
        this.polynomial = PolynomialRingGF2.getIrreduciblePolynomial(degree);
    }

    /**
     * create a finite field GF(2^m) with the fixed field polynomial
     *
     * @param degree the degree of the field
     * @param poly   the field polynomial
     */
    public GF2mField(final int degree, final int poly)
    {
        if (degree != PolynomialRingGF2.degree(poly))
        {
            throw new IllegalArgumentException(
                " Error: the degree is not correct");
        }
        if (!PolynomialRingGF2.isIrreducible(poly))
        {
            throw new IllegalArgumentException(
                " Error: given polynomial is reducible");
        }
        this.degree = degree;
        this.polynomial = poly;

    }

    public GF2mField(final byte[] enc)
    {
        if (enc.length != 4)
        {
            throw new IllegalArgumentException(
                "byte array is not an encoded finite field");
        }
        this.polynomial = LittleEndianConversions.OS2IP(enc);
        if (!PolynomialRingGF2.isIrreducible(this.polynomial))
        {
            throw new IllegalArgumentException(
                "byte array is not an encoded finite field");
        }

        this.degree = PolynomialRingGF2.degree(this.polynomial);
    }

    public GF2mField(final GF2mField field)
    {
        this.degree = field.degree;
        this.polynomial = field.polynomial;
    }

    /**
     * return degree of the field
     *
     * @return degree of the field
     */
    public int getDegree()
    {
        return this.degree;
    }

    /**
     * return the field polynomial
     *
     * @return the field polynomial
     */
    public int getPolynomial()
    {
        return this.polynomial;
    }

    /**
     * return the encoded form of this field
     *
     * @return the field in byte array form
     */
    public byte[] getEncoded()
    {
        return LittleEndianConversions.I2OSP(this.polynomial);
    }

    /**
     * Return sum of two elements
     *
     * @param a First param.
     * @param b Seconf param.
     * @return a+b
     */
    public int add(final int a, final int b)
    {
        return a ^ b;
    }

    /**
     * Return product of two elements
     *
     * @param a First param.
     * @param b Seconf param.
     * @return a*b
     */
    public int mult(final int a, final int b)
    {
        return PolynomialRingGF2.modMultiply(a, b, this.polynomial);
    }

    /**
     * compute exponentiation a^k
     *
     * @param a a field element a
     * @param k k degree
     * @return a^k
     */
    public int exp(int a, int k)
    {
        if (k == 0)
        {
            return 1;
        }
        if (a == 0)
        {
            return 0;
        }
        if (a == 1)
        {
            return 1;
        }
        int result = 1;
        if (k < 0)
        {
            a = inverse(a);
            k = -k;
        }
        while (k != 0)
        {
            if ((k & 1) == 1)
            {
                result = mult(result, a);
            }
            a = mult(a, a);
            k >>>= 1;
        }
        return result;
    }

    /**
     * compute the multiplicative inverse of a
     *
     * @param a a field element a
     * @return a<sup>-1</sup>
     */
    public int inverse(final int a)
    {
        final int d = (1 << this.degree) - 2;

        return exp(a, d);
    }

    /**
     * compute the square root of an integer
     *
     * @param a a field element a
     * @return a<sup>1/2</sup>
     */
    public int sqRoot(int a)
    {
        for (int i = 1; i < this.degree; i++)
        {
            a = mult(a, a);
        }
        return a;
    }

    /**
     * create a random field element using PRNG sr
     *
     * @param sr SecureRandom
     * @return a random element
     */
    public int getRandomElement(final SecureRandom sr)
    {
        final int result = RandUtils.nextInt(sr, 1 << this.degree);
        return result;
    }

    /**
     * create a random non-zero field element
     *
     * @return a random element
     */
    public int getRandomNonZeroElement()
    {
        return getRandomNonZeroElement(CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * create a random non-zero field element using PRNG sr
     *
     * @param sr SecureRandom
     * @return a random non-zero element
     */
    public int getRandomNonZeroElement(final SecureRandom sr)
    {
        final int controltime = 1 << 20;
        int count = 0;
        int result = RandUtils.nextInt(sr, 1 << this.degree);
        while (result == 0 && count < controltime)
        {
            result = RandUtils.nextInt(sr, 1 << this.degree);
            count++;
        }
        if (count == controltime)
        {
            result = 1;
        }
        return result;
    }

    /**
     * @param e Encoded element.
     * @return true if e is encoded element of this field and false otherwise
     */
    public boolean isElementOfThisField(final int e)
    {
        // e is encoded element of this field iff 0<= e < |2^m|
        if (this.degree == 31)
        {
            return e >= 0;
        }
        return e >= 0 && e < 1 << this.degree;
    }

    /*
      * help method for visual control
      */
    public String elementToStr(int a)
    {
        String s = "";
        for (int i = 0; i < this.degree; i++)
        {
            if (((byte)a & 0x01) == 0)
            {
                s = "0" + s;
            }
            else
            {
                s = "1" + s;
            }
            a >>>= 1;
        }
        return s;
    }

    /**
     * checks if given object is equal to this field.
     * <p>
     * The method returns false whenever the given object is not GF2m.
     *
     * @param other object
     * @return true or false
     */
    @Override
	public boolean equals(final Object other)
    {
        if (other == null || !(other instanceof GF2mField))
        {
            return false;
        }

        final GF2mField otherField = (GF2mField)other;

        if (this.degree == otherField.degree
            && this.polynomial == otherField.polynomial)
        {
            return true;
        }

        return false;
    }

    @Override
	public int hashCode()
    {
        return this.polynomial;
    }

    /**
     * Returns a human readable form of this field.
     *
     * @return a human readable form of this field.
     */
    @Override
	public String toString()
    {
        final String str = "Finite Field GF(2^" + this.degree + ") = " + "GF(2)[X]/<"
            + polyToString(this.polynomial) + "> ";
        return str;
    }

    private static String polyToString(int p)
    {
        String str = "";
        if (p == 0)
        {
            str = "0";
        }
        else
        {
            byte b = (byte)(p & 0x01);
            if (b == 1)
            {
                str = "1";
            }
            p >>>= 1;
            int i = 1;
            while (p != 0)
            {
                b = (byte)(p & 0x01);
                if (b == 1)
                {
                    str = str + "+x^" + i;
                }
                p >>>= 1;
                i++;
            }
        }
        return str;
    }

}
