package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat224;

public class SecP224R1Point extends ECPoint.AbstractFp
{
    SecP224R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        super(curve, x, y);
    }

    SecP224R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    @Override
	protected ECPoint detach()
    {
        return new SecP224R1Point(null, getAffineXCoord(), getAffineYCoord());
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

        final SecP224R1FieldElement X1 = (SecP224R1FieldElement)x, Y1 = (SecP224R1FieldElement)y;
        final SecP224R1FieldElement X2 = (SecP224R1FieldElement)b.getXCoord(), Y2 = (SecP224R1FieldElement)b.getYCoord();

        final SecP224R1FieldElement Z1 = (SecP224R1FieldElement)zs[0];
        final SecP224R1FieldElement Z2 = (SecP224R1FieldElement)b.getZCoord(0);

        int c;
        final int[] tt1 = Nat224.createExt();
        final int[] t2 = Nat224.create();
        final int[] t3 = Nat224.create();
        final int[] t4 = Nat224.create();

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
            SecP224R1Field.square(Z1.x, S2);

            U2 = t2;
            SecP224R1Field.multiply(S2, X2.x, U2);

            SecP224R1Field.multiply(S2, Z1.x, S2);
            SecP224R1Field.multiply(S2, Y2.x, S2);
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
            SecP224R1Field.square(Z2.x, S1);

            U1 = tt1;
            SecP224R1Field.multiply(S1, X1.x, U1);

            SecP224R1Field.multiply(S1, Z2.x, S1);
            SecP224R1Field.multiply(S1, Y1.x, S1);
        }

        final int[] H = Nat224.create();
        SecP224R1Field.subtract(U1, U2, H);

        final int[] R = t2;
        SecP224R1Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat224.isZero(H))
        {
            if (Nat224.isZero(R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        final int[] HSquared = t3;
        SecP224R1Field.square(H, HSquared);

        final int[] G = Nat224.create();
        SecP224R1Field.multiply(HSquared, H, G);

        final int[] V = t3;
        SecP224R1Field.multiply(HSquared, U1, V);

        SecP224R1Field.negate(G, G);
        Nat224.mul(S1, G, tt1);

        c = Nat224.addBothTo(V, V, G);
        SecP224R1Field.reduce32(c, G);

        final SecP224R1FieldElement X3 = new SecP224R1FieldElement(t4);
        SecP224R1Field.square(R, X3.x);
        SecP224R1Field.subtract(X3.x, G, X3.x);

        final SecP224R1FieldElement Y3 = new SecP224R1FieldElement(G);
        SecP224R1Field.subtract(V, X3.x, Y3.x);
        SecP224R1Field.multiplyAddToExt(Y3.x, R, tt1);
        SecP224R1Field.reduce(tt1, Y3.x);

        final SecP224R1FieldElement Z3 = new SecP224R1FieldElement(H);
        if (!Z1IsOne)
        {
            SecP224R1Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        if (!Z2IsOne)
        {
            SecP224R1Field.multiply(Z3.x, Z2.x, Z3.x);
        }

        final ECFieldElement[] zs = { Z3 };

        return new SecP224R1Point(curve, X3, Y3, zs);
    }

    @Override
	public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECCurve curve = this.getCurve();

        final SecP224R1FieldElement Y1 = (SecP224R1FieldElement)y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        final SecP224R1FieldElement X1 = (SecP224R1FieldElement)x, Z1 = (SecP224R1FieldElement)zs[0];

        int c;
        final int[] t1 = Nat224.create();
        final int[] t2 = Nat224.create();

        final int[] Y1Squared = Nat224.create();
        SecP224R1Field.square(Y1.x, Y1Squared);

        final int[] T = Nat224.create();
        SecP224R1Field.square(Y1Squared, T);

        final boolean Z1IsOne = Z1.isOne();

        int[] Z1Squared = Z1.x;
        if (!Z1IsOne)
        {
            Z1Squared = t2;
            SecP224R1Field.square(Z1.x, Z1Squared);
        }

        SecP224R1Field.subtract(X1.x, Z1Squared, t1);

        final int[] M = t2;
        SecP224R1Field.add(X1.x, Z1Squared, M);
        SecP224R1Field.multiply(M, t1, M);
        c = Nat224.addBothTo(M, M, M);
        SecP224R1Field.reduce32(c, M);

        final int[] S = Y1Squared;
        SecP224R1Field.multiply(Y1Squared, X1.x, S);
        c = Nat.shiftUpBits(7, S, 2, 0);
        SecP224R1Field.reduce32(c, S);

        c = Nat.shiftUpBits(7, T, 3, 0, t1);
        SecP224R1Field.reduce32(c, t1);

        final SecP224R1FieldElement X3 = new SecP224R1FieldElement(T);
        SecP224R1Field.square(M, X3.x);
        SecP224R1Field.subtract(X3.x, S, X3.x);
        SecP224R1Field.subtract(X3.x, S, X3.x);

        final SecP224R1FieldElement Y3 = new SecP224R1FieldElement(S);
        SecP224R1Field.subtract(S, X3.x, Y3.x);
        SecP224R1Field.multiply(Y3.x, M, Y3.x);
        SecP224R1Field.subtract(Y3.x, t1, Y3.x);

        final SecP224R1FieldElement Z3 = new SecP224R1FieldElement(M);
        SecP224R1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne)
        {
            SecP224R1Field.multiply(Z3.x, Z1.x, Z3.x);
        }

        return new SecP224R1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 });
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

    @Override
	public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        return new SecP224R1Point(curve, x, y.negate(), zs);
    }
}
