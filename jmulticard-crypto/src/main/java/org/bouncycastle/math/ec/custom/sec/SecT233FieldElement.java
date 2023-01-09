package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

public class SecT233FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT233FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 233)
        {
            throw new IllegalArgumentException("x value invalid for SecT233FieldElement");
        }

        this.x = SecT233Field.fromBigInteger(x);
    }

    public SecT233FieldElement()
    {
        x = Nat256.create64();
    }

    protected SecT233FieldElement(final long[] x)
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
        return "SecT233Field";
    }

    @Override
	public int getFieldSize()
    {
        return 233;
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final long[] z = Nat256.create64();
        SecT233Field.add(x, ((SecT233FieldElement)b).x, z);
        return new SecT233FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final long[] z = Nat256.create64();
        SecT233Field.addOne(x, z);
        return new SecT233FieldElement(z);
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
        SecT233Field.multiply(x, ((SecT233FieldElement)b).x, z);
        return new SecT233FieldElement(z);
    }

    @Override
	public ECFieldElement multiplyMinusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    @Override
	public ECFieldElement multiplyPlusProduct(final ECFieldElement b, final ECFieldElement x, final ECFieldElement y)
    {
        final long[] ax = this.x, bx = ((SecT233FieldElement)b).x;
        final long[] xx = ((SecT233FieldElement)x).x, yx = ((SecT233FieldElement)y).x;

        final long[] tt = Nat256.createExt64();
        SecT233Field.multiplyAddToExt(ax, bx, tt);
        SecT233Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat256.create64();
        SecT233Field.reduce(tt, z);
        return new SecT233FieldElement(z);
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
        SecT233Field.square(x, z);
        return new SecT233FieldElement(z);
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
        final long[] xx = ((SecT233FieldElement)x).x, yx = ((SecT233FieldElement)y).x;

        final long[] tt = Nat256.createExt64();
        SecT233Field.squareAddToExt(ax, tt);
        SecT233Field.multiplyAddToExt(xx, yx, tt);

        final long[] z = Nat256.create64();
        SecT233Field.reduce(tt, z);
        return new SecT233FieldElement(z);
    }

    @Override
	public ECFieldElement squarePow(final int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        final long[] z = Nat256.create64();
        SecT233Field.squareN(x, pow, z);
        return new SecT233FieldElement(z);
    }

    @Override
	public ECFieldElement halfTrace()
    {
        final long[] z = Nat256.create64();
        SecT233Field.halfTrace(x, z);
        return new SecT233FieldElement(z);
    }

    @Override
	public boolean hasFastTrace()
    {
        return true;
    }

    @Override
	public int trace()
    {
        return SecT233Field.trace(x);
    }

    @Override
	public ECFieldElement invert()
    {
        final long[] z = Nat256.create64();
        SecT233Field.invert(x, z);
        return new SecT233FieldElement(z);
    }

    @Override
	public ECFieldElement sqrt()
    {
        final long[] z = Nat256.create64();
        SecT233Field.sqrt(x, z);
        return new SecT233FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.TPB;
    }

    public int getM()
    {
        return 233;
    }

    public int getK1()
    {
        return 74;
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

        if (!(other instanceof SecT233FieldElement))
        {
            return false;
        }

        final SecT233FieldElement o = (SecT233FieldElement)other;
        return Nat256.eq64(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return 2330074 ^ Arrays.hashCode(x, 0, 4);
    }
}
