package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat384;

public class SecP384R1Point extends ECPoint.AbstractFp
{
    SecP384R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        super(curve, x, y);
    }

    SecP384R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    @Override
	protected ECPoint detach()
    {
        return new SecP384R1Point(null, getAffineXCoord(), getAffineYCoord());
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

        final SecP384R1FieldElement X1 = (SecP384R1FieldElement)x, Y1 = (SecP384R1FieldElement)y;
        final SecP384R1FieldElement X2 = (SecP384R1FieldElement)b.getXCoord(), Y2 = (SecP384R1FieldElement)b.getYCoord();

        final SecP384R1FieldElement Z1 = (SecP384R1FieldElement)zs[0];
        final SecP384R1FieldElement Z2 = (SecP384R1FieldElement)b.getZCoord(0);

        int c;
        final int[] tt0 = Nat.create(24);
        final int[] tt1 = Nat.create(24);
        final int[] tt2 = Nat.create(24);
        final int[] t3 = Nat.create(12);
        final int[] t4 = Nat.create(12);

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
            SecP384R1Field.square(Z1.x, S2, tt0);

            U2 = tt2;
            SecP384R1Field.multiply(S2, X2.x, U2, tt0);

            SecP384R1Field.multiply(S2, Z1.x, S2, tt0);
            SecP384R1Field.multiply(S2, Y2.x, S2, tt0);
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
            SecP384R1Field.square(Z2.x, S1, tt0);

            U1 = tt1;
            SecP384R1Field.multiply(S1, X1.x, U1, tt0);

            SecP384R1Field.multiply(S1, Z2.x, S1, tt0);
            SecP384R1Field.multiply(S1, Y1.x, S1, tt0);
        }

        final int[] H = Nat.create(12);
        SecP384R1Field.subtract(U1, U2, H);

        final int[] R = Nat.create(12);
        SecP384R1Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat.isZero(12, H))
        {
            if (Nat.isZero(12, R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        final int[] HSquared = t3;
        SecP384R1Field.square(H, HSquared, tt0);

        final int[] G = Nat.create(12);
        SecP384R1Field.multiply(HSquared, H, G, tt0);

        final int[] V = t3;
        SecP384R1Field.multiply(HSquared, U1, V, tt0);

        SecP384R1Field.negate(G, G);
        Nat384.mul(S1, G, tt1);

        c = Nat.addBothTo(12, V, V, G);
        SecP384R1Field.reduce32(c, G);

        final SecP384R1FieldElement X3 = new SecP384R1FieldElement(t4);
        SecP384R1Field.square(R, X3.x, tt0);
        SecP384R1Field.subtract(X3.x, G, X3.x);

        final SecP384R1FieldElement Y3 = new SecP384R1FieldElement(G);
        SecP384R1Field.subtract(V, X3.x, Y3.x);
        Nat384.mul(Y3.x, R, tt2);
        SecP384R1Field.addExt(tt1, tt2, tt1);
        SecP384R1Field.reduce(tt1, Y3.x);

        final SecP384R1FieldElement Z3 = new SecP384R1FieldElement(H);
        if (!Z1IsOne)
        {
            SecP384R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
        }
        if (!Z2IsOne)
        {
            SecP384R1Field.multiply(Z3.x, Z2.x, Z3.x, tt0);
        }

        final ECFieldElement[] zs = { Z3 };

        return new SecP384R1Point(curve, X3, Y3, zs);
    }

    @Override
	public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECCurve curve = this.getCurve();

        final SecP384R1FieldElement Y1 = (SecP384R1FieldElement)y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        final SecP384R1FieldElement X1 = (SecP384R1FieldElement)x, Z1 = (SecP384R1FieldElement)zs[0];

        int c;
        final int[] tt0 = Nat.create(24);
        final int[] t1 = Nat.create(12);
        final int[] t2 = Nat.create(12);

        final int[] Y1Squared = Nat.create(12);
        SecP384R1Field.square(Y1.x, Y1Squared, tt0);

        final int[] T = Nat.create(12);
        SecP384R1Field.square(Y1Squared, T, tt0);

        final boolean Z1IsOne = Z1.isOne();

        int[] Z1Squared = Z1.x;
        if (!Z1IsOne)
        {
            Z1Squared = t2;
            SecP384R1Field.square(Z1.x, Z1Squared, tt0);
        }

        SecP384R1Field.subtract(X1.x, Z1Squared, t1);

        final int[] M = t2;
        SecP384R1Field.add(X1.x, Z1Squared, M);
        SecP384R1Field.multiply(M, t1, M, tt0);
        c = Nat.addBothTo(12, M, M, M);
        SecP384R1Field.reduce32(c, M);

        final int[] S = Y1Squared;
        SecP384R1Field.multiply(Y1Squared, X1.x, S, tt0);
        c = Nat.shiftUpBits(12, S, 2, 0);
        SecP384R1Field.reduce32(c, S);

        c = Nat.shiftUpBits(12, T, 3, 0, t1);
        SecP384R1Field.reduce32(c, t1);

        final SecP384R1FieldElement X3 = new SecP384R1FieldElement(T);
        SecP384R1Field.square(M, X3.x, tt0);
        SecP384R1Field.subtract(X3.x, S, X3.x);
        SecP384R1Field.subtract(X3.x, S, X3.x);

        final SecP384R1FieldElement Y3 = new SecP384R1FieldElement(S);
        SecP384R1Field.subtract(S, X3.x, Y3.x);
        SecP384R1Field.multiply(Y3.x, M, Y3.x, tt0);
        SecP384R1Field.subtract(Y3.x, t1, Y3.x);

        final SecP384R1FieldElement Z3 = new SecP384R1FieldElement(M);
        SecP384R1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne)
        {
            SecP384R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
        }

        return new SecP384R1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 });
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

        return new SecP384R1Point(curve, x, y.negate(), zs);
    }
}
