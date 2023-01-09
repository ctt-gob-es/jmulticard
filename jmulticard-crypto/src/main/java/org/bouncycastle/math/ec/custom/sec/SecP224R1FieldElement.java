package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat224;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SecP224R1FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"));

    protected int[] x;

    public SecP224R1FieldElement(final BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP224R1FieldElement");
        }

        this.x = SecP224R1Field.fromBigInteger(x);
    }

    public SecP224R1FieldElement()
    {
        x = Nat224.create();
    }

    protected SecP224R1FieldElement(final int[] x)
    {
        this.x = x;
    }

    @Override
	public boolean isZero()
    {
        return Nat224.isZero(x);
    }

    @Override
	public boolean isOne()
    {
        return Nat224.isOne(x);
    }

    @Override
	public boolean testBitZero()
    {
        return Nat224.getBit(x, 0) == 1;
    }

    @Override
	public BigInteger toBigInteger()
    {
        return Nat224.toBigInteger(x);
    }

    @Override
	public String getFieldName()
    {
        return "SecP224R1Field";
    }

    @Override
	public int getFieldSize()
    {
        return Q.bitLength();
    }

    @Override
	public ECFieldElement add(final ECFieldElement b)
    {
        final int[] z = Nat224.create();
        SecP224R1Field.add(x, ((SecP224R1FieldElement)b).x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement addOne()
    {
        final int[] z = Nat224.create();
        SecP224R1Field.addOne(x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement subtract(final ECFieldElement b)
    {
        final int[] z = Nat224.create();
        SecP224R1Field.subtract(x, ((SecP224R1FieldElement)b).x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement multiply(final ECFieldElement b)
    {
        final int[] z = Nat224.create();
        SecP224R1Field.multiply(x, ((SecP224R1FieldElement)b).x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement divide(final ECFieldElement b)
    {
//        return multiply(b.invert());
        final int[] z = Nat224.create();
        SecP224R1Field.inv(((SecP224R1FieldElement)b).x, z);
        SecP224R1Field.multiply(z, x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement negate()
    {
        final int[] z = Nat224.create();
        SecP224R1Field.negate(x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement square()
    {
        final int[] z = Nat224.create();
        SecP224R1Field.square(x, z);
        return new SecP224R1FieldElement(z);
    }

    @Override
	public ECFieldElement invert()
    {
//        return new SecP224R1FieldElement(toBigInteger().modInverse(Q));
        final int[] z = Nat224.create();
        SecP224R1Field.inv(x, z);
        return new SecP224R1FieldElement(z);
    }

    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    @Override
	public ECFieldElement sqrt()
    {
        final int[] c = x;
        if (Nat224.isZero(c) || Nat224.isOne(c))
        {
            return this;
        }

        final int[] nc = Nat224.create();
        SecP224R1Field.negate(c, nc);

        final int[] r = Mod.random(SecP224R1Field.P);
        final int[] t = Nat224.create();

        if (!isSquare(c))
        {
            return null;
        }

        while (!trySqrt(nc, r, t))
        {
            SecP224R1Field.addOne(r, r);
        }

        SecP224R1Field.square(t, r);

        return Nat224.eq(c, r) ? new SecP224R1FieldElement(t) : null;
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP224R1FieldElement))
        {
            return false;
        }

        final SecP224R1FieldElement o = (SecP224R1FieldElement)other;
        return Nat224.eq(x, o.x);
    }

    @Override
	public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 7);
    }

    private static boolean isSquare(final int[] x)
    {
        final int[] t1 = Nat224.create();
        final int[] t2 = Nat224.create();
        Nat224.copy(x, t1);

        for (int i = 0; i < 7; ++i)
        {
            Nat224.copy(t1, t2);
            SecP224R1Field.squareN(t1, 1 << i, t1);
            SecP224R1Field.multiply(t1, t2, t1);
        }

        SecP224R1Field.squareN(t1, 95, t1);
        return Nat224.isOne(t1);
    }

    private static void RM(final int[] nc, final int[] d0, final int[] e0, final int[] d1, final int[] e1, final int[] f1, final int[] t)
    {
        SecP224R1Field.multiply(e1, e0, t);
        SecP224R1Field.multiply(t, nc, t);
        SecP224R1Field.multiply(d1, d0, f1);
        SecP224R1Field.add(f1, t, f1);
        SecP224R1Field.multiply(d1, e0, t);
        Nat224.copy(f1, d1);
        SecP224R1Field.multiply(e1, d0, e1);
        SecP224R1Field.add(e1, t, e1);
        SecP224R1Field.square(e1, f1);
        SecP224R1Field.multiply(f1, nc, f1);
    }

    private static void RP(final int[] nc, final int[] d1, final int[] e1, final int[] f1, final int[] t)
    {
        Nat224.copy(nc, f1);

        final int[] d0 = Nat224.create();
        final int[] e0 = Nat224.create();

        for (int i = 0; i < 7; ++i)
        {
            Nat224.copy(d1, d0);
            Nat224.copy(e1, e0);

            int j = 1 << i;
            while (--j >= 0)
            {
                RS(d1, e1, f1, t);
            }

            RM(nc, d0, e0, d1, e1, f1, t);
        }
    }

    private static void RS(final int[] d, final int[] e, final int[] f, final int[] t)
    {
        SecP224R1Field.multiply(e, d, e);
        SecP224R1Field.twice(e, e);
        SecP224R1Field.square(d, t);
        SecP224R1Field.add(f, t, d);
        SecP224R1Field.multiply(f, t, f);
        final int c = Nat.shiftUpBits(7, f, 2, 0);
        SecP224R1Field.reduce32(c, f);
    }

    private static boolean trySqrt(final int[] nc, final int[] r, final int[] t)
    {
        final int[] d1 = Nat224.create();
        Nat224.copy(r, d1);
        final int[] e1 = Nat224.create();
        e1[0] = 1;
        final int[] f1 = Nat224.create();
        RP(nc, d1, e1, f1, t);

        final int[] d0 = Nat224.create();
        final int[] e0 = Nat224.create();

        for (int k = 1; k < 96; ++k)
        {
            Nat224.copy(d1, d0);
            Nat224.copy(e1, e0);

            RS(d1, e1, f1, t);

            if (Nat224.isZero(d1))
            {
                SecP224R1Field.inv(e0, t);
                SecP224R1Field.multiply(t, d0, t);
                return true;
            }
        }

        return false;
    }
}
