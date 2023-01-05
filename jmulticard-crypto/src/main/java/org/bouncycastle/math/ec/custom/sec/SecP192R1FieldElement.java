package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SecP192R1FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"));

    protected int[] x;

    public SecP192R1FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP192R1FieldElement");
        }

        this.x = SecP192R1Field.fromBigInteger(x);
    }

    public SecP192R1FieldElement()
    {
        x = Nat192.create();
    }

    protected SecP192R1FieldElement(final int[] x)
    {
        this.x = x;
    }

    @Override
	public boolean isZero()
    {
        return Nat192.isZero(x);
    }

    @Override
	public boolean isOne()
    {
        return Nat192.isOne(x);
    }

    @Override
	public boolean testBitZero()
    {
        return Nat192.getBit(x, 0) == 1;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat192.toBigInteger(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecP192R1Field";
    }

    @Override
	public int getFieldSize()
    {
        return Q.bitLength();
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final int[] z = Nat192.create();
        SecP192R1Field.add(x, ((SecP192R1FieldElement)b).x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final int[] z = Nat192.create();
        SecP192R1Field.addOne(x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement subtract(final ECFieldElement b)
    {
        final int[] z = Nat192.create();
        SecP192R1Field.subtract(x, ((SecP192R1FieldElement)b).x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement multiply(final ECFieldElement b)
    {
        final int[] z = Nat192.create();
        SecP192R1Field.multiply(x, ((SecP192R1FieldElement)b).x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement divide(final ECFieldElement b)
    {
//        return multiply(b.invert());
        final int[] z = Nat192.create();
        SecP192R1Field.inv(((SecP192R1FieldElement)b).x, z);
        SecP192R1Field.multiply(z, x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement negate()
    {
        final int[] z = Nat192.create();
        SecP192R1Field.negate(x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement square()
    {
        final int[] z = Nat192.create();
        SecP192R1Field.square(x, z);
        return new SecP192R1FieldElement(z);
    }

    @Override
	public ECFieldElement invert()
    {
//        return new SecP192R1FieldElement(toBigInteger().modInverse(Q));
        final int[] z = Nat192.create();
        SecP192R1Field.inv(x, z);
        return new SecP192R1FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    @Override
	public ECFieldElement sqrt()
    {
        // Raise this element to the exponent 2^190 - 2^62

        final int[] x1 = x;
        if (Nat192.isZero(x1) || Nat192.isOne(x1))
        {
            return this;
        }

        final int[] t1 = Nat192.create();
        final int[] t2 = Nat192.create();

        SecP192R1Field.square(x1, t1);
        SecP192R1Field.multiply(t1, x1, t1);

        SecP192R1Field.squareN(t1, 2, t2);
        SecP192R1Field.multiply(t2, t1, t2);

        SecP192R1Field.squareN(t2, 4, t1);
        SecP192R1Field.multiply(t1, t2, t1);

        SecP192R1Field.squareN(t1, 8, t2);
        SecP192R1Field.multiply(t2, t1, t2);

        SecP192R1Field.squareN(t2, 16, t1);
        SecP192R1Field.multiply(t1, t2, t1);

        SecP192R1Field.squareN(t1, 32, t2);
        SecP192R1Field.multiply(t2, t1, t2);

        SecP192R1Field.squareN(t2, 64, t1);
        SecP192R1Field.multiply(t1, t2, t1);

        SecP192R1Field.squareN(t1, 62, t1);
        SecP192R1Field.square(t1, t2);

        return Nat192.eq(x1, t2) ? new SecP192R1FieldElement(t1) : null;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP192R1FieldElement))
        {
            return false;
        }

        final SecP192R1FieldElement o = (SecP192R1FieldElement)other;
        return Nat192.eq(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 6);
    }
}
