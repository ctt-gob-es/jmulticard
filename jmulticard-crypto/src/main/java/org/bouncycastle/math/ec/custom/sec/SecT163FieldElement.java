package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Arrays;

public class SecT163FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT163FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 163)
        {
            throw new IllegalArgumentException("x value invalid for SecT163FieldElement");
        }

        this.x = SecT163Field.fromBigInteger(x);
    }

    public SecT163FieldElement()
    {
        x = Nat192.create64();
    }

    protected SecT163FieldElement(final long[] x)
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
        return "SecT163Field";
    }

    @Override
	public int getFieldSize()
    {
        return 163;
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final long[] z = Nat192.create64();
        SecT163Field.add(x, ((SecT163FieldElement)b).x, z);
        return new SecT163FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final long[] z = Nat192.create64();
        SecT163Field.addOne(x, z);
        return new SecT163FieldElement(z);
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
        SecT163Field.multiply(x, ((SecT163FieldElement)b).x, z);
        return new SecT163FieldElement(z);
    }

    @Override
	public ECFieldElement multiplyMinusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    @Override
	public ECFieldElement multiplyPlusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x, bx = ((SecT163FieldElement)b).x;
        final long[] xx = ((SecT163FieldElement)x).x, yx = ((SecT163FieldElement)y).x;

        final long[] tt = Nat192.createExt64();
        SecT163Field.multiplyAddToExt(ax, bx, tt);
        SecT163Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat192.create64();
        SecT163Field.reduce(tt, z);
        return new SecT163FieldElement(z);
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
        SecT163Field.square(x, z);
        return new SecT163FieldElement(z);
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
        final long[] xx = ((SecT163FieldElement)x).x, yx = ((SecT163FieldElement)y).x;

        final long[] tt = Nat192.createExt64();
        SecT163Field.squareAddToExt(ax, tt);
        SecT163Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat192.create64();
        SecT163Field.reduce(tt, z);
        return new SecT163FieldElement(z);
    }

    @Override
	public ECFieldElement squarePow(final int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        final long[] z = Nat192.create64();
        SecT163Field.squareN(x, pow, z);
        return new SecT163FieldElement(z);
    }

    @Override
	public ECFieldElement halfTrace()
    {
        final long[] z = Nat192.create64();
        SecT163Field.halfTrace(x, z);
        return new SecT163FieldElement(z);
    }

    @Override
	public boolean hasFastTrace()
    {
        return true;
    }

    @Override
	public int trace()
    {
        return SecT163Field.trace(x);
    }

    @Override
	public ECFieldElement invert()
    {
        final long[] z = Nat192.create64();
        SecT163Field.invert(x, z);
        return new SecT163FieldElement(z);
    }

    @Override
	public ECFieldElement sqrt()
    {
        final long[] z = Nat192.create64();
        SecT163Field.sqrt(x, z);
        return new SecT163FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 163;
    }

    public int getK1()
    {
        return 3;
    }

    public int getK2()
    {
        return 6;
    }

    public int getK3()
    {
        return 7;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT163FieldElement))
        {
            return false;
        }

        final SecT163FieldElement o = (SecT163FieldElement)other;
        return Nat192.eq64(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return 163763 ^ Arrays.hashCode(x, 0, 3);
    }
}
