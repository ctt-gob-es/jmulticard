package org.bouncycastle.math.ec.custom.gm;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SM2P256V1FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"));

    protected int[] x;

    public SM2P256V1FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SM2P256V1FieldElement");
        }

        this.x = SM2P256V1Field.fromBigInteger(x);
    }

    public SM2P256V1FieldElement()
    {
        x = Nat256.create();
    }

    protected SM2P256V1FieldElement(final int[] x)
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
        return "SM2P256V1Field";
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
        SM2P256V1Field.add(x, ((SM2P256V1FieldElement)b).x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final int[] z = Nat256.create();
        SM2P256V1Field.addOne(x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement subtract(final ECFieldElement b)
    {
        final int[] z = Nat256.create();
        SM2P256V1Field.subtract(x, ((SM2P256V1FieldElement)b).x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement multiply(final ECFieldElement b)
    {
        final int[] z = Nat256.create();
        SM2P256V1Field.multiply(x, ((SM2P256V1FieldElement)b).x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement divide(final ECFieldElement b)
    {
//        return multiply(b.invert());
        final int[] z = Nat256.create();
        SM2P256V1Field.inv(((SM2P256V1FieldElement)b).x, z);
        SM2P256V1Field.multiply(z, x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement negate()
    {
        final int[] z = Nat256.create();
        SM2P256V1Field.negate(x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement square()
    {
        final int[] z = Nat256.create();
        SM2P256V1Field.square(x, z);
        return new SM2P256V1FieldElement(z);
    }

    @Override
	public ECFieldElement invert()
    {
//        return new SM2P256V1FieldElement(toBigInteger().modInverse(Q));
        final int[] z = Nat256.create();
        SM2P256V1Field.inv(x, z);
        return new SM2P256V1FieldElement(z);
    }

    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    @Override
	public ECFieldElement sqrt()
    {
        /*
         * Raise this element to the exponent 2^254 - 2^222 - 2^94 + 2^62
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 31 1s } { 1 0s } { 128 1s } { 31 0s } { 1 1s } { 62 0s }
         *
         * We use an addition chain for the beginning: [1], 2, 3, 6, 12, [24], 30, [31]
         */

        final int[] x1 = x;
        if (Nat256.isZero(x1) || Nat256.isOne(x1))
        {
            return this;
        }

        final int[] x2 = Nat256.create();
        SM2P256V1Field.square(x1, x2);
        SM2P256V1Field.multiply(x2, x1, x2);
        final int[] x4 = Nat256.create();
        SM2P256V1Field.squareN(x2, 2, x4);
        SM2P256V1Field.multiply(x4, x2, x4);
        final int[] x6 = Nat256.create();
        SM2P256V1Field.squareN(x4, 2, x6);
        SM2P256V1Field.multiply(x6, x2, x6);
        final int[] x12 = x2;
        SM2P256V1Field.squareN(x6, 6, x12);
        SM2P256V1Field.multiply(x12, x6, x12);
        final int[] x24 = Nat256.create();
        SM2P256V1Field.squareN(x12, 12, x24);
        SM2P256V1Field.multiply(x24, x12, x24);
        final int[] x30 = x12;
        SM2P256V1Field.squareN(x24, 6, x30);
        SM2P256V1Field.multiply(x30, x6, x30);
        final int[] x31 = x6;
        SM2P256V1Field.square(x30, x31);
        SM2P256V1Field.multiply(x31, x1, x31);

        final int[] t1 = x24;
        SM2P256V1Field.squareN(x31, 31, t1);

        final int[] x62 = x30;
        SM2P256V1Field.multiply(t1, x31, x62);

        SM2P256V1Field.squareN(t1, 32, t1);
        SM2P256V1Field.multiply(t1, x62, t1);
        SM2P256V1Field.squareN(t1, 62, t1);
        SM2P256V1Field.multiply(t1, x62, t1);
        SM2P256V1Field.squareN(t1, 4, t1);
        SM2P256V1Field.multiply(t1, x4, t1);
        SM2P256V1Field.squareN(t1, 32, t1);
        SM2P256V1Field.multiply(t1, x1, t1);
        SM2P256V1Field.squareN(t1, 62, t1);

        final int[] t2 = x4;
        SM2P256V1Field.square(t1, t2);

        return Nat256.eq(x1, t2) ? new SM2P256V1FieldElement(t1) : null;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SM2P256V1FieldElement))
        {
            return false;
        }

        final SM2P256V1FieldElement o = (SM2P256V1FieldElement)other;
        return Nat256.eq(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 8);
    }
}
