package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat320;
import org.bouncycastle.util.Arrays;

public class SecT283FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT283FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 283)
        {
            throw new IllegalArgumentException("x value invalid for SecT283FieldElement");
        }

        this.x = SecT283Field.fromBigInteger(x);
    }

    public SecT283FieldElement()
    {
        x = Nat320.create64();
    }

    protected SecT283FieldElement(final long[] x)
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
        return Nat320.isOne64(x);
    }

    @Override
	public boolean isZero()
    {
        return Nat320.isZero64(x);
    }

    @Override
	public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat320.toBigInteger64(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecT283Field";
    }

    @Override
	public int getFieldSize()
    {
        return 283;
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final long[] z = Nat320.create64();
        SecT283Field.add(x, ((SecT283FieldElement)b).x, z);
        return new SecT283FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final long[] z = Nat320.create64();
        SecT283Field.addOne(x, z);
        return new SecT283FieldElement(z);
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
        final long[] z = Nat320.create64();
        SecT283Field.multiply(x, ((SecT283FieldElement)b).x, z);
        return new SecT283FieldElement(z);
    }

    @Override
	public ECFieldElement multiplyMinusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    @Override
	public ECFieldElement multiplyPlusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x, bx = ((SecT283FieldElement)b).x;
        final long[] xx = ((SecT283FieldElement)x).x, yx = ((SecT283FieldElement)y).x;

        final long[] tt = Nat.create64(9);
        SecT283Field.multiplyAddToExt(ax, bx, tt);
        SecT283Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat320.create64();
        SecT283Field.reduce(tt, z);
        return new SecT283FieldElement(z);
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
        final long[] z = Nat320.create64();
        SecT283Field.square(x, z);
        return new SecT283FieldElement(z);
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
        final long[] xx = ((SecT283FieldElement)x).x, yx = ((SecT283FieldElement)y).x;

        final long[] tt = Nat.create64(9);
        SecT283Field.squareAddToExt(ax, tt);
        SecT283Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat320.create64();
        SecT283Field.reduce(tt, z);
        return new SecT283FieldElement(z);
    }

    @Override
	public ECFieldElement squarePow(final int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        final long[] z = Nat320.create64();
        SecT283Field.squareN(x, pow, z);
        return new SecT283FieldElement(z);
    }

    @Override
	public ECFieldElement halfTrace()
    {
        final long[] z = Nat320.create64();
        SecT283Field.halfTrace(x, z);
        return new SecT283FieldElement(z);
    }

    @Override
	public boolean hasFastTrace()
    {
        return true;
    }

    @Override
	public int trace()
    {
        return SecT283Field.trace(x);
    }

    @Override
	public ECFieldElement invert()
    {
        final long[] z = Nat320.create64();
        SecT283Field.invert(x, z);
        return new SecT283FieldElement(z);
    }

    @Override
	public ECFieldElement sqrt()
    {
        final long[] z = Nat320.create64();
        SecT283Field.sqrt(x, z);
        return new SecT283FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 283;
    }

    public int getK1()
    {
        return 5;
    }

    public int getK2()
    {
        return 7;
    }

    public int getK3()
    {
        return 12;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT283FieldElement))
        {
            return false;
        }

        final SecT283FieldElement o = (SecT283FieldElement)other;
        return Nat320.eq64(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return 2831275 ^ Arrays.hashCode(x, 0, 5);
    }
}
