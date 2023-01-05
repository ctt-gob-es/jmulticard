package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat576;
import org.bouncycastle.util.Arrays;

public class SecT571FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT571FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 571)
        {
            throw new IllegalArgumentException("x value invalid for SecT571FieldElement");
        }

        this.x = SecT571Field.fromBigInteger(x);
    }

    public SecT571FieldElement()
    {
        x = Nat576.create64();
    }

    protected SecT571FieldElement(final long[] x)
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
        return Nat576.isOne64(x);
    }

    @Override
	public boolean isZero()
    {
        return Nat576.isZero64(x);
    }

    @Override
	public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat576.toBigInteger64(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecT571Field";
    }

    @Override
	public int getFieldSize()
    {
        return 571;
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final long[] z = Nat576.create64();
        SecT571Field.add(x, ((SecT571FieldElement)b).x, z);
        return new SecT571FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final long[] z = Nat576.create64();
        SecT571Field.addOne(x, z);
        return new SecT571FieldElement(z);
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
        final long[] z = Nat576.create64();
        SecT571Field.multiply(x, ((SecT571FieldElement)b).x, z);
        return new SecT571FieldElement(z);
    }

    @Override
	public ECFieldElement multiplyMinusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    @Override
	public ECFieldElement multiplyPlusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x, bx = ((SecT571FieldElement)b).x;
        final long[] xx = ((SecT571FieldElement)x).x, yx = ((SecT571FieldElement)y).x;

        final long[] tt = Nat576.createExt64();
        SecT571Field.multiplyAddToExt(ax, bx, tt);
        SecT571Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat576.create64();
        SecT571Field.reduce(tt, z);
        return new SecT571FieldElement(z);
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
        final long[] z = Nat576.create64();
        SecT571Field.square(x, z);
        return new SecT571FieldElement(z);
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
        final long[] xx = ((SecT571FieldElement)x).x, yx = ((SecT571FieldElement)y).x;

        final long[] tt = Nat576.createExt64();
        SecT571Field.squareAddToExt(ax, tt);
        SecT571Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat576.create64();
        SecT571Field.reduce(tt, z);
        return new SecT571FieldElement(z);
    }

    @Override
	public ECFieldElement squarePow(final int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        final long[] z = Nat576.create64();
        SecT571Field.squareN(x, pow, z);
        return new SecT571FieldElement(z);
    }

    @Override
	public ECFieldElement halfTrace()
    {
        final long[] z = Nat576.create64();
        SecT571Field.halfTrace(x, z);
        return new SecT571FieldElement(z);
    }

    @Override
	public boolean hasFastTrace()
    {
        return true;
    }

    @Override
	public int trace()
    {
        return SecT571Field.trace(x);
    }

    @Override
	public ECFieldElement invert()
    {
        final long[] z = Nat576.create64();
        SecT571Field.invert(x, z);
        return new SecT571FieldElement(z);
    }

    @Override
	public ECFieldElement sqrt()
    {
        final long[] z = Nat576.create64();
        SecT571Field.sqrt(x, z);
        return new SecT571FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 571;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 5;
    }

    public int getK3()
    {
        return 10;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT571FieldElement))
        {
            return false;
        }

        final SecT571FieldElement o = (SecT571FieldElement)other;
        return Nat576.eq64(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return 5711052 ^ Arrays.hashCode(x, 0, 9);
    }
}
