package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat;

public class SecP521R1Point extends ECPoint.AbstractFp
{
    SecP521R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        super(curve, x, y);
    }

    SecP521R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    @Override
	protected ECPoint detach()
    {
        return new SecP521R1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override
	public ECPoint add(final ECPoint b)
    {
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return this;
        }
        if (this == b)
        {
            return twice();
        }

        final ECCurve curve = this.getCurve();

        final SecP521R1FieldElement X1 = (SecP521R1FieldElement)x, Y1 = (SecP521R1FieldElement)y;
        final SecP521R1FieldElement X2 = (SecP521R1FieldElement)b.getXCoord(), Y2 = (SecP521R1FieldElement)b.getYCoord();

        final SecP521R1FieldElement Z1 = (SecP521R1FieldElement)zs[0];
        final SecP521R1FieldElement Z2 = (SecP521R1FieldElement)b.getZCoord(0);

        final int[] tt0 = Nat.create(33);
        final int[] t1 = Nat.create(17);
        final int[] t2 = Nat.create(17);
        final int[] t3 = Nat.create(17);
        final int[] t4 = Nat.create(17);

        final boolean Z1IsOne = Z1.isOne();
        int[] U2, S2;
        if (Z1IsOne)
        {
            U2 = X2.x;
            S2 = Y2.x;
        }
        else
        {
            S2 = t3;
            SecP521R1Field.square(Z1.x, S2, tt0);

            U2 = t2;
            SecP521R1Field.multiply(S2, X2.x, U2, tt0);

            SecP521R1Field.multiply(S2, Z1.x, S2, tt0);
            SecP521R1Field.multiply(S2, Y2.x, S2, tt0);
        }

        final boolean Z2IsOne = Z2.isOne();
        int[] U1, S1;
        if (Z2IsOne)
        {
            U1 = X1.x;
            S1 = Y1.x;
        }
        else
        {
            S1 = t4;
            SecP521R1Field.square(Z2.x, S1, tt0);

            U1 = t1;
            SecP521R1Field.multiply(S1, X1.x, U1, tt0);

            SecP521R1Field.multiply(S1, Z2.x, S1, tt0);
            SecP521R1Field.multiply(S1, Y1.x, S1, tt0);
        }

        final int[] H = Nat.create(17);
        SecP521R1Field.subtract(U1, U2, H);

        final int[] R = t2;
        SecP521R1Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat.isZero(17, H))
        {
            if (Nat.isZero(17, R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        final int[] HSquared = t3;
        SecP521R1Field.square(H, HSquared, tt0);

        final int[] G = Nat.create(17);
        SecP521R1Field.multiply(HSquared, H, G, tt0);

        final int[] V = t3;
        SecP521R1Field.multiply(HSquared, U1, V, tt0);

        SecP521R1Field.multiply(S1, G, t1, tt0);

        final SecP521R1FieldElement X3 = new SecP521R1FieldElement(t4);
        SecP521R1Field.square(R, X3.x, tt0);
        SecP521R1Field.add(X3.x, G, X3.x);
        SecP521R1Field.subtract(X3.x, V, X3.x);
        SecP521R1Field.subtract(X3.x, V, X3.x);

        final SecP521R1FieldElement Y3 = new SecP521R1FieldElement(G);
        SecP521R1Field.subtract(V, X3.x, Y3.x);
        SecP521R1Field.multiply(Y3.x, R, t2, tt0);
        SecP521R1Field.subtract(t2, t1, Y3.x);

        final SecP521R1FieldElement Z3 = new SecP521R1FieldElement(H);
        if (!Z1IsOne)
        {
            SecP521R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
        }
        if (!Z2IsOne)
        {
            SecP521R1Field.multiply(Z3.x, Z2.x, Z3.x, tt0);
        }

        final ECFieldElement[] zs = { Z3 };

        return new SecP521R1Point(curve, X3, Y3, zs);
    }

    @Override
	public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECCurve curve = this.getCurve();

        final SecP521R1FieldElement Y1 = (SecP521R1FieldElement)y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        final SecP521R1FieldElement X1 = (SecP521R1FieldElement)x, Z1 = (SecP521R1FieldElement)zs[0];

        final int[] tt0 = Nat.create(33);
        final int[] t1 = Nat.create(17);
        final int[] t2 = Nat.create(17);

        final int[] Y1Squared = Nat.create(17);
        SecP521R1Field.square(Y1.x, Y1Squared, tt0);

        final int[] T = Nat.create(17);
        SecP521R1Field.square(Y1Squared, T, tt0);

        final boolean Z1IsOne = Z1.isOne();

        int[] Z1Squared = Z1.x;
        if (!Z1IsOne)
        {
            Z1Squared = t2;
            SecP521R1Field.square(Z1.x, Z1Squared, tt0);
        }

        SecP521R1Field.subtract(X1.x, Z1Squared, t1);

        final int[] M = t2;
        SecP521R1Field.add(X1.x, Z1Squared, M);
        SecP521R1Field.multiply(M, t1, M, tt0);
        Nat.addBothTo(17, M, M, M);
        SecP521R1Field.reduce23(M);

        final int[] S = Y1Squared;
        SecP521R1Field.multiply(Y1Squared, X1.x, S, tt0);
        Nat.shiftUpBits(17, S, 2, 0);
        SecP521R1Field.reduce23(S);

        Nat.shiftUpBits(17, T, 3, 0, t1);
        SecP521R1Field.reduce23(t1);

        final SecP521R1FieldElement X3 = new SecP521R1FieldElement(T);
        SecP521R1Field.square(M, X3.x, tt0);
        SecP521R1Field.subtract(X3.x, S, X3.x);
        SecP521R1Field.subtract(X3.x, S, X3.x);

        final SecP521R1FieldElement Y3 = new SecP521R1FieldElement(S);
        SecP521R1Field.subtract(S, X3.x, Y3.x);
        SecP521R1Field.multiply(Y3.x, M, Y3.x, tt0);
        SecP521R1Field.subtract(Y3.x, t1, Y3.x);

        final SecP521R1FieldElement Z3 = new SecP521R1FieldElement(M);
        SecP521R1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne)
        {
            SecP521R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
        }

        return new SecP521R1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 });
    }

    @Override
	public ECPoint twicePlus(final ECPoint b)
    {
        if (this == b)
        {
            return threeTimes();
        }
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return twice();
        }

        final ECFieldElement Y1 = y;
        if (Y1.isZero())
        {
            return b;
        }

        return twice().add(b);
    }

    @Override
	public ECPoint threeTimes()
    {
        if (this.isInfinity() || y.isZero())
        {
            return this;
        }

        // NOTE: Be careful about recursions between twicePlus and threeTimes
        return twice().add(this);
    }

    protected ECFieldElement two(final ECFieldElement x)
    {
        return x.add(x);
    }

    protected ECFieldElement three(final ECFieldElement x)
    {
        return two(x).add(x);
    }

    protected ECFieldElement four(final ECFieldElement x)
    {
        return two(two(x));
    }

    protected ECFieldElement eight(final ECFieldElement x)
    {
        return four(two(x));
    }

    protected ECFieldElement doubleProductFromSquares(final ECFieldElement a, final ECFieldElement b,
        final ECFieldElement aSquared, final ECFieldElement bSquared)
    {
        /*
         * NOTE: If squaring in the field is faster than multiplication, then this is a quicker
         * way to calculate 2.A.B, if A^2 and B^2 are already known.
         */
        return a.add(b).square().subtract(aSquared).subtract(bSquared);
    }

    @Override
	public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        return new SecP521R1Point(curve, x, y.negate(), zs);
    }
}
