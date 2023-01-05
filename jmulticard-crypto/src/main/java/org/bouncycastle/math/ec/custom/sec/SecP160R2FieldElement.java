package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SecP160R2FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73"));

    protected int[] x;

    public SecP160R2FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP160R2FieldElement");
        }

        this.x = SecP160R2Field.fromBigInteger(x);
    }

    public SecP160R2FieldElement()
    {
        x = Nat160.create();
    }

    protected SecP160R2FieldElement(final int[] x)
    {
        this.x = x;
    }

    @Override
	public boolean isZero()
    {
        return Nat160.isZero(x);
    }

    @Override
	public boolean isOne()
    {
        return Nat160.isOne(x);
    }

    @Override
	public boolean testBitZero()
    {
        return Nat160.getBit(x, 0) == 1;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat160.toBigInteger(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecP160R2Field";
    }

    @Override
	public int getFieldSize()
    {
        return Q.bitLength();
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final int[] z = Nat160.create();
        SecP160R2Field.add(x, ((SecP160R2FieldElement)b).x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final int[] z = Nat160.create();
        SecP160R2Field.addOne(x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement subtract(final ECFieldElement b)
    {
        final int[] z = Nat160.create();
        SecP160R2Field.subtract(x, ((SecP160R2FieldElement)b).x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement multiply(final ECFieldElement b)
    {
        final int[] z = Nat160.create();
        SecP160R2Field.multiply(x, ((SecP160R2FieldElement)b).x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement divide(final ECFieldElement b)
    {
//        return multiply(b.invert());
        final int[] z = Nat160.create();
        SecP160R2Field.inv(((SecP160R2FieldElement)b).x, z);
        SecP160R2Field.multiply(z, x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement negate()
    {
        final int[] z = Nat160.create();
        SecP160R2Field.negate(x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement square()
    {
        final int[] z = Nat160.create();
        SecP160R2Field.square(x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override
	public ECFieldElement invert()
    {
//        return new SecP160R2FieldElement(toBigInteger().modInverse(Q));
        final int[] z = Nat160.create();
        SecP160R2Field.inv(x, z);
        return new SecP160R2FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    @Override
	public ECFieldElement sqrt()
    {
        /*
         * Raise this element to the exponent 2^158 - 2^30 - 2^12 - 2^10 - 2^7 - 2^6 - 2^5 - 2^1 - 2^0
         *
         * Breaking up the exponent's binary representation into "repunits", we get: { 127 1s } { 1
         * 0s } { 17 1s } { 1 0s } { 1 1s } { 1 0s } { 2 1s } { 3 0s } { 3 1s } { 1 0s } { 1 1s }
         *
         * Therefore we need an addition chain containing 1, 2, 3, 17, 127 (the lengths of the repunits)
         * We use: [1], [2], [3], 4, 7, 14, [17], 31, 62, 124, [127]
         */

        final int[] x1 = x;
        if (Nat160.isZero(x1) || Nat160.isOne(x1))
        {
            return this;
        }

        final int[] x2 = Nat160.create();
        SecP160R2Field.square(x1, x2);
        SecP160R2Field.multiply(x2, x1, x2);
        final int[] x3 = Nat160.create();
        SecP160R2Field.square(x2, x3);
        SecP160R2Field.multiply(x3, x1, x3);
        final int[] x4 = Nat160.create();
        SecP160R2Field.square(x3, x4);
        SecP160R2Field.multiply(x4, x1, x4);
        final int[] x7 = Nat160.create();
        SecP160R2Field.squareN(x4, 3, x7);
        SecP160R2Field.multiply(x7, x3, x7);
        final int[] x14 = x4;
        SecP160R2Field.squareN(x7, 7, x14);
        SecP160R2Field.multiply(x14, x7, x14);
        final int[] x17 = x7;
        SecP160R2Field.squareN(x14, 3, x17);
        SecP160R2Field.multiply(x17, x3, x17);
        final int[] x31 = Nat160.create();
        SecP160R2Field.squareN(x17, 14, x31);
        SecP160R2Field.multiply(x31, x14, x31);
        final int[] x62 = x14;
        SecP160R2Field.squareN(x31, 31, x62);
        SecP160R2Field.multiply(x62, x31, x62);
        final int[] x124 = x31;
        SecP160R2Field.squareN(x62, 62, x124);
        SecP160R2Field.multiply(x124, x62, x124);
        final int[] x127 = x62;
        SecP160R2Field.squareN(x124, 3, x127);
        SecP160R2Field.multiply(x127, x3, x127);

        final int[] t1 = x127;
        SecP160R2Field.squareN(t1, 18, t1);
        SecP160R2Field.multiply(t1, x17, t1);
        SecP160R2Field.squareN(t1, 2, t1);
        SecP160R2Field.multiply(t1, x1, t1);
        SecP160R2Field.squareN(t1, 3, t1);
        SecP160R2Field.multiply(t1, x2, t1);
        SecP160R2Field.squareN(t1, 6, t1);
        SecP160R2Field.multiply(t1, x3, t1);
        SecP160R2Field.squareN(t1, 2, t1);
        SecP160R2Field.multiply(t1, x1, t1);

        final int[] t2 = x2;
        SecP160R2Field.square(t1, t2);

        return Nat160.eq(x1, t2) ? new SecP160R2FieldElement(t1) : null;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP160R2FieldElement))
        {
            return false;
        }

        final SecP160R2FieldElement o = (SecP160R2FieldElement)other;
        return Nat160.eq(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 5);
    }
}
