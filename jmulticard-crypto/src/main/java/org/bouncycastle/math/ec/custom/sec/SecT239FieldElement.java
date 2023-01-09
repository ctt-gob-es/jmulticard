package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

public class SecT239FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT239FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 239)
        {
            throw new IllegalArgumentException("x value invalid for SecT239FieldElement");
        }

        this.x = SecT239Field.fromBigInteger(x);
    }

    public SecT239FieldElement()
    {
        x = Nat256.create64();
    }

    protected SecT239FieldElement(final long[] x)
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
        return Nat256.isOne64(x);
    }

    @Override
	public boolean isZero()
    {
        return Nat256.isZero64(x);
    }

    @Override
	public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat256.toBigInteger64(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecT239Field";
    }

    @Override
	public int getFieldSize()
    {
        return 239;
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final long[] z = Nat256.create64();
        SecT239Field.add(x, ((SecT239FieldElement)b).x, z);
        return new SecT239FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final long[] z = Nat256.create64();
        SecT239Field.addOne(x, z);
        return new SecT239FieldElement(z);
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
        final long[] z = Nat256.create64();
        SecT239Field.multiply(x, ((SecT239FieldElement)b).x, z);
        return new SecT239FieldElement(z);
    }

    @Override
	public ECFieldElement multiplyMinusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    @Override
	public ECFieldElement multiplyPlusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x, bx = ((SecT239FieldElement)b).x;
        final long[] xx = ((SecT239FieldElement)x).x, yx = ((SecT239FieldElement)y).x;

        final long[] tt = Nat256.createExt64();
        SecT239Field.multiplyAddToExt(ax, bx, tt);
        SecT239Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat256.create64();
        SecT239Field.reduce(tt, z);
        return new SecT239FieldElement(z);
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
        final long[] z = Nat256.create64();
        SecT239Field.square(x, z);
        return new SecT239FieldElement(z);
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
        final long[] xx = ((SecT239FieldElement)x).x, yx = ((SecT239FieldElement)y).x;

        final long[] tt = Nat256.createExt64();
        SecT239Field.squareAddToExt(ax, tt);
        SecT239Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat256.create64();
        SecT239Field.reduce(tt, z);
        return new SecT239FieldElement(z);
    }

    @Override
	public ECFieldElement squarePow(final int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        final long[] z = Nat256.create64();
        SecT239Field.squareN(x, pow, z);
        return new SecT239FieldElement(z);
    }

    @Override
	public ECFieldElement halfTrace()
    {
        final long[] z = Nat256.create64();
        SecT239Field.halfTrace(x, z);
        return new SecT239FieldElement(z);
    }

    @Override
	public boolean hasFastTrace()
    {
        return true;
    }

    @Override
	public int trace()
    {
        return SecT239Field.trace(x);
    }

    @Override
	public ECFieldElement invert()
    {
        final long[] z = Nat256.create64();
        SecT239Field.invert(x, z);
        return new SecT239FieldElement(z);
    }

    @Override
	public ECFieldElement sqrt()
    {
        final long[] z = Nat256.create64();
        SecT239Field.sqrt(x, z);
        return new SecT239FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.TPB;
    }

    public int getM()
    {
        return 239;
    }

    public int getK1()
    {
        return 158;
    }

    public int getK2()
    {
        return 0;
    }

    public int getK3()
    {
        return 0;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT239FieldElement))
        {
            return false;
        }

        final SecT239FieldElement o = (SecT239FieldElement)other;
        return Nat256.eq64(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return 23900158 ^ Arrays.hashCode(x, 0, 4);
    }
}
