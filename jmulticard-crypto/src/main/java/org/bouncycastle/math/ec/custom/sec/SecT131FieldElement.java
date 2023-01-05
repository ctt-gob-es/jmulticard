package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Arrays;

public class SecT131FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT131FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 131)
        {
            throw new IllegalArgumentException("x value invalid for SecT131FieldElement");
        }

        this.x = SecT131Field.fromBigInteger(x);
    }

    public SecT131FieldElement()
    {
        x = Nat192.create64();
    }

    protected SecT131FieldElement(final long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    @Override
	public boolean isOne()
    {
        return Nat192.isOne64(x);
    }

    @Override
	public boolean isZero()
    {
        return Nat192.isZero64(x);
    }

    @Override
	public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat192.toBigInteger64(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecT131Field";
    }

    @Override
	public int getFieldSize()
    {
        return 131;
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final long[] z = Nat192.create64();
        SecT131Field.add(x, ((SecT131FieldElement)b).x, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final long[] z = Nat192.create64();
        SecT131Field.addOne(x, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement subtract(final ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    @Override
	public ECFieldElement multiply(final ECFieldElement b)
    {
        final long[] z = Nat192.create64();
        SecT131Field.multiply(x, ((SecT131FieldElement)b).x, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement multiplyMinusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    @Override
	public ECFieldElement multiplyPlusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x, bx = ((SecT131FieldElement)b).x;
        final long[] xx = ((SecT131FieldElement)x).x, yx = ((SecT131FieldElement)y).x;

        final long[] tt = Nat.create64(5);
        SecT131Field.multiplyAddToExt(ax, bx, tt);
        SecT131Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat192.create64();
        SecT131Field.reduce(tt, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement divide(final ECFieldElement b)
    {
        return multiply(b.invert());
    }

    @Override
	public ECFieldElement negate()
    {
        return this;
    }

    @Override
	public ECFieldElement square()
    {
        final long[] z = Nat192.create64();
        SecT131Field.square(x, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement squareMinusProduct(final ECFieldElement x, final ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    @Override
	public ECFieldElement squarePlusProduct(final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x;
        final long[] xx = ((SecT131FieldElement)x).x, yx = ((SecT131FieldElement)y).x;

        final long[] tt = Nat.create64(5);
        SecT131Field.squareAddToExt(ax, tt);
        SecT131Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat192.create64();
        SecT131Field.reduce(tt, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement squarePow(final int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        final long[] z = Nat192.create64();
        SecT131Field.squareN(x, pow, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement halfTrace()
    {
        final long[] z = Nat192.create64();
        SecT131Field.halfTrace(x, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public boolean hasFastTrace()
    {
        return true;
    }

    @Override
	public int trace()
    {
        return SecT131Field.trace(x);
    }

    @Override
	public ECFieldElement invert()
    {
        final long[] z = Nat192.create64();
        SecT131Field.invert(x, z);
        return new SecT131FieldElement(z);
    }

    @Override
	public ECFieldElement sqrt()
    {
        final long[] z = Nat192.create64();
        SecT131Field.sqrt(x, z);
        return new SecT131FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 131;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 3;
    }

    public int getK3()
    {
        return 8;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT131FieldElement))
        {
            return false;
        }

        final SecT131FieldElement o = (SecT131FieldElement)other;
        return Nat192.eq64(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return 131832 ^ Arrays.hashCode(x, 0, 3);
    }
}
