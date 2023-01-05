package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SecP256R1FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));

    protected int[] x;

    public SecP256R1FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP256R1FieldElement");
        }

        this.x = SecP256R1Field.fromBigInteger(x);
    }

    public SecP256R1FieldElement()
    {
        x = Nat256.create();
    }

    protected SecP256R1FieldElement(final int[] x)
    {
        this.x = x;
    }

    @Override
	public boolean isZero()
    {
        return Nat256.isZero(x);
    }

    @Override
	public boolean isOne()
    {
        return Nat256.isOne(x);
    }

    @Override
	public boolean testBitZero()
    {
        return Nat256.getBit(x, 0) == 1;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat256.toBigInteger(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecP256R1Field";
    }

    @Override
	public int getFieldSize()
    {
        return Q.bitLength();
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final int[] z = Nat256.create();
        SecP256R1Field.add(x, ((SecP256R1FieldElement)b).x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final int[] z = Nat256.create();
        SecP256R1Field.addOne(x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement subtract(final ECFieldElement b)
    {
        final int[] z = Nat256.create();
        SecP256R1Field.subtract(x, ((SecP256R1FieldElement)b).x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement multiply(final ECFieldElement b)
    {
        final int[] z = Nat256.create();
        SecP256R1Field.multiply(x, ((SecP256R1FieldElement)b).x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement divide(final ECFieldElement b)
    {
//        return multiply(b.invert());
        final int[] z = Nat256.create();
        SecP256R1Field.inv(((SecP256R1FieldElement)b).x, z);
        SecP256R1Field.multiply(z, x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement negate()
    {
        final int[] z = Nat256.create();
        SecP256R1Field.negate(x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement square()
    {
        final int[] z = Nat256.create();
        SecP256R1Field.square(x, z);
        return new SecP256R1FieldElement(z);
    }

    @Override
	public ECFieldElement invert()
    {
//        return new SecP256R1FieldElement(toBigInteger().modInverse(Q));
        final int[] z = Nat256.create();
        SecP256R1Field.inv(x, z);
        return new SecP256R1FieldElement(z);
    }

    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    @Override
	public ECFieldElement sqrt()
    {
        // Raise this element to the exponent 2^254 - 2^222 + 2^190 + 2^94

        final int[] x1 = x;
        if (Nat256.isZero(x1) || Nat256.isOne(x1))
        {
            return this;
        }

        final int[] tt0 = Nat256.createExt();
        final int[] t1 = Nat256.create();
        final int[] t2 = Nat256.create();

        SecP256R1Field.square(x1, t1, tt0);
        SecP256R1Field.multiply(t1, x1, t1, tt0);

        SecP256R1Field.squareN(t1, 2, t2, tt0);
        SecP256R1Field.multiply(t2, t1, t2, tt0);

        SecP256R1Field.squareN(t2, 4, t1, tt0);
        SecP256R1Field.multiply(t1, t2, t1, tt0);

        SecP256R1Field.squareN(t1, 8, t2, tt0);
        SecP256R1Field.multiply(t2, t1, t2, tt0);

        SecP256R1Field.squareN(t2, 16, t1, tt0);
        SecP256R1Field.multiply(t1, t2, t1, tt0);

        SecP256R1Field.squareN(t1, 32, t1, tt0);
        SecP256R1Field.multiply(t1, x1, t1, tt0);

        SecP256R1Field.squareN(t1, 96, t1, tt0);
        SecP256R1Field.multiply(t1, x1, t1, tt0);

        SecP256R1Field.squareN(t1, 94, t1, tt0);
        SecP256R1Field.square(t1, t2, tt0);

        return Nat256.eq(x1, t2) ? new SecP256R1FieldElement(t1) : null;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP256R1FieldElement))
        {
            return false;
        }

        final SecP256R1FieldElement o = (SecP256R1FieldElement)other;
        return Nat256.eq(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 8);
    }
}
