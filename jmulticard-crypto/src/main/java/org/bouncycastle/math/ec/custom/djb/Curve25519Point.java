package org.bouncycastle.math.ec.custom.djb;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;

public class Curve25519Point extends ECPoint.AbstractFp
{
    Curve25519Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        super(curve, x, y);
    }

    Curve25519Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    @Override
	protected ECPoint detach()
    {
        return new Curve25519Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override
	public ECFieldElement getZCoord(final int index)
    {
        if (index == 1)
        {
            return getJacobianModifiedW();
        }

        return super.getZCoord(index);
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

        final Curve25519FieldElement X1 = (Curve25519FieldElement)x, Y1 = (Curve25519FieldElement)y,
            Z1 = (Curve25519FieldElement)zs[0];
        final Curve25519FieldElement X2 = (Curve25519FieldElement)b.getXCoord(), Y2 = (Curve25519FieldElement)b.getYCoord(),
            Z2 = (Curve25519FieldElement)b.getZCoord(0);

        int c;
        final int[] tt1 = Nat256.createExt();
        final int[] t2 = Nat256.create();
        final int[] t3 = Nat256.create();
        final int[] t4 = Nat256.create();

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
            Curve25519Field.square(Z1.x, S2);

            U2 = t2;
            Curve25519Field.multiply(S2, X2.x, U2);

            Curve25519Field.multiply(S2, Z1.x, S2);
            Curve25519Field.multiply(S2, Y2.x, S2);
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
            Curve25519Field.square(Z2.x, S1);

            U1 = tt1;
            Curve25519Field.multiply(S1, X1.x, U1);

            Curve25519Field.multiply(S1, Z2.x, S1);
            Curve25519Field.multiply(S1, Y1.x, S1);
        }

        final int[] H = Nat256.create();
        Curve25519Field.subtract(U1, U2, H);

        final int[] R = t2;
        Curve25519Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat256.isZero(H))
        {
            if (Nat256.isZero(R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        final int[] HSquared = Nat256.create();
        Curve25519Field.square(H, HSquared);

        final int[] G = Nat256.create();
        Curve25519Field.multiply(HSquared, H, G);

        final int[] V = t3;
        Curve25519Field.multiply(HSquared, U1, V);

        Curve25519Field.negate(G, G);
        Nat256.mul(S1, G, tt1);

        c = Nat256.addBothTo(V, V, G);
        Curve25519Field.reduce27(c, G);

        final Curve25519FieldElement X3 = new Curve25519FieldElement(t4);
        Curve25519Field.square(R, X3.x);
        Curve25519Field.subtract(X3.x, G, X3.x);

        final Curve25519FieldElement Y3 = new Curve25519FieldElement(G);
        Curve25519Field.subtract(V, X3.x, Y3.x);
        Curve25519Field.multiplyAddToExt(Y3.x, R, tt1);
        Curve25519Field.reduce(tt1, Y3.x);

        final Curve25519FieldElement Z3 = new Curve25519FieldElement(H);
        if (!Z1IsOne)
        {
            Curve25519Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        if (!Z2IsOne)
        {
            Curve25519Field.multiply(Z3.x, Z2.x, Z3.x);
        }

        final int[] Z3Squared = Z1IsOne && Z2IsOne ? HSquared : null;

        // TODO If the result will only be used in a subsequent addition, we don't need W3
        final Curve25519FieldElement W3 = calculateJacobianModifiedW(Z3, Z3Squared);

        final ECFieldElement[] zs = { Z3, W3 };

        return new Curve25519Point(curve, X3, Y3, zs);
    }

    @Override
	public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECCurve curve = this.getCurve();

        final ECFieldElement Y1 = y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        return twiceJacobianModified(true);
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

        return twiceJacobianModified(false).add(b);
    }

    @Override
	public ECPoint threeTimes()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECFieldElement Y1 = y;
        if (Y1.isZero())
        {
            return this;
        }

        return twiceJacobianModified(false).add(this);
    }

    @Override
	public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        return new Curve25519Point(this.getCurve(), x, y.negate(), zs);
    }

    protected Curve25519FieldElement calculateJacobianModifiedW(final Curve25519FieldElement Z, int[] ZSquared)
    {
        final Curve25519FieldElement a4 = (Curve25519FieldElement)this.getCurve().getA();
        if (Z.isOne())
        {
            return a4;
        }

        final Curve25519FieldElement W = new Curve25519FieldElement();
        if (ZSquared == null)
        {
            ZSquared = W.x;
            Curve25519Field.square(Z.x, ZSquared);
        }
        Curve25519Field.square(ZSquared, W.x);
        Curve25519Field.multiply(W.x, a4.x, W.x);
        return W;
    }

    protected Curve25519FieldElement getJacobianModifiedW()
    {
        Curve25519FieldElement W = (Curve25519FieldElement)zs[1];
        if (W == null)
        {
            // NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
            zs[1] = W = calculateJacobianModifiedW((Curve25519FieldElement)zs[0], null);
        }
        return W;
    }

    protected Curve25519Point twiceJacobianModified(final boolean calculateW)
    {
        final Curve25519FieldElement X1 = (Curve25519FieldElement)x, Y1 = (Curve25519FieldElement)y,
            Z1 = (Curve25519FieldElement)zs[0], W1 = getJacobianModifiedW();

        int c;

        final int[] M = Nat256.create();
        Curve25519Field.square(X1.x, M);
        c = Nat256.addBothTo(M, M, M);
        c += Nat256.addTo(W1.x, M);
        Curve25519Field.reduce27(c, M);

        final int[] _2Y1 = Nat256.create();
        Curve25519Field.twice(Y1.x, _2Y1);

        final int[] _2Y1Squared = Nat256.create();
        Curve25519Field.multiply(_2Y1, Y1.x, _2Y1Squared);

        final int[] S = Nat256.create();
        Curve25519Field.multiply(_2Y1Squared, X1.x, S);
        Curve25519Field.twice(S, S);

        final int[] _8T = Nat256.create();
        Curve25519Field.square(_2Y1Squared, _8T);
        Curve25519Field.twice(_8T, _8T);

        final Curve25519FieldElement X3 = new Curve25519FieldElement(_2Y1Squared);
        Curve25519Field.square(M, X3.x);
        Curve25519Field.subtract(X3.x, S, X3.x);
        Curve25519Field.subtract(X3.x, S, X3.x);

        final Curve25519FieldElement Y3 = new Curve25519FieldElement(S);
        Curve25519Field.subtract(S, X3.x, Y3.x);
        Curve25519Field.multiply(Y3.x, M, Y3.x);
        Curve25519Field.subtract(Y3.x, _8T, Y3.x);

        final Curve25519FieldElement Z3 = new Curve25519FieldElement(_2Y1);
        if (!Nat256.isOne(Z1.x))
        {
            Curve25519Field.multiply(Z3.x, Z1.x, Z3.x);
        }

        Curve25519FieldElement W3 = null;
        if (calculateW)
        {
            W3 = new Curve25519FieldElement(_8T);
            Curve25519Field.multiply(W3.x, W1.x, W3.x);
            Curve25519Field.twice(W3.x, W3.x);
        }

        return new Curve25519Point(this.getCurve(), X3, Y3, new ECFieldElement[]{ Z3, W3 });
    }
}
