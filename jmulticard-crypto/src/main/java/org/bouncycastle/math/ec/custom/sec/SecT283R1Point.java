package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.AbstractF2m;

public class SecT283R1Point extends AbstractF2m
{
    SecT283R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        super(curve, x, y);
    }

    SecT283R1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    @Override
	protected ECPoint detach()
    {
        return new SecT283R1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override
	public ECFieldElement getYCoord()
    {
        final ECFieldElement X = x, L = y;

        if (this.isInfinity() || X.isZero())
        {
            return L;
        }

        // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
        ECFieldElement Y = L.add(X).multiply(X);

        final ECFieldElement Z = zs[0];
        if (!Z.isOne())
        {
            Y = Y.divide(Z);
        }

        return Y;
    }

    @Override
	protected boolean getCompressionYTilde()
    {
        final ECFieldElement X = this.getRawXCoord();
        if (X.isZero())
        {
            return false;
        }

        final ECFieldElement Y = this.getRawYCoord();

        // Y is actually Lambda (X + Y/X) here
        return Y.testBitZero() != X.testBitZero();
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

        final ECCurve curve = this.getCurve();

        ECFieldElement X1 = x;
        final ECFieldElement X2 = b.getRawXCoord();

        if (X1.isZero())
        {
            if (X2.isZero())
            {
                return curve.getInfinity();
            }

            return b.add(this);
        }

        final ECFieldElement L1 = y, Z1 = zs[0];
        final ECFieldElement L2 = b.getRawYCoord(), Z2 = b.getZCoord(0);

        final boolean Z1IsOne = Z1.isOne();
        ECFieldElement U2 = X2, S2 = L2;
        if (!Z1IsOne)
        {
            U2 = U2.multiply(Z1);
            S2 = S2.multiply(Z1);
        }

        final boolean Z2IsOne = Z2.isOne();
        ECFieldElement U1 = X1, S1 = L1;
        if (!Z2IsOne)
        {
            U1 = U1.multiply(Z2);
            S1 = S1.multiply(Z2);
        }

        final ECFieldElement A = S1.add(S2);
        ECFieldElement B = U1.add(U2);

        if (B.isZero())
        {
            if (A.isZero())
            {
                return twice();
            }

            return curve.getInfinity();
        }

        ECFieldElement X3, L3, Z3;
        if (X2.isZero())
        {
            // TODO This can probably be optimized quite a bit
            final ECPoint p = this.normalize();
            X1 = p.getXCoord();
            final ECFieldElement Y1 = p.getYCoord();

            final ECFieldElement Y2 = L2;
            final ECFieldElement L = Y1.add(Y2).divide(X1);

            X3 = L.square().add(L).add(X1).addOne();
            if (X3.isZero())
            {
                return new SecT283R1Point(curve, X3, curve.getB().sqrt());
            }

            final ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);
            L3 = Y3.divide(X3).add(X3);
            Z3 = curve.fromBigInteger(ECConstants.ONE);
        }
        else
        {
            B = B.square();

            final ECFieldElement AU1 = A.multiply(U1);
            final ECFieldElement AU2 = A.multiply(U2);

            X3 = AU1.multiply(AU2);
            if (X3.isZero())
            {
                return new SecT283R1Point(curve, X3, curve.getB().sqrt());
            }

            ECFieldElement ABZ2 = A.multiply(B);
            if (!Z2IsOne)
            {
                ABZ2 = ABZ2.multiply(Z2);
            }

            L3 = AU2.add(B).squarePlusProduct(ABZ2, L1.add(Z1));

            Z3 = ABZ2;
            if (!Z1IsOne)
            {
                Z3 = Z3.multiply(Z1);
            }
        }

        return new SecT283R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
    }

    @Override
	public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECCurve curve = this.getCurve();

        final ECFieldElement X1 = x;
        if (X1.isZero())
        {
            // A point with X == 0 is its own additive inverse
            return curve.getInfinity();
        }

        final ECFieldElement L1 = y, Z1 = zs[0];

        final boolean Z1IsOne = Z1.isOne();
        final ECFieldElement L1Z1 = Z1IsOne ? L1 : L1.multiply(Z1);
        final ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
        final ECFieldElement T = L1.square().add(L1Z1).add(Z1Sq);
        if (T.isZero())
        {
            return new SecT283R1Point(curve, T, curve.getB().sqrt());
        }

        final ECFieldElement X3 = T.square();
        final ECFieldElement Z3 = Z1IsOne ? T : T.multiply(Z1Sq);

        final ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.multiply(Z1);
        final ECFieldElement L3 = X1Z1.squarePlusProduct(T, L1Z1).add(X3).add(Z3);

        return new SecT283R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
    }

    @Override
	public ECPoint twicePlus(final ECPoint b)
    {
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return twice();
        }

        final ECCurve curve = this.getCurve();

        final ECFieldElement X1 = x;
        if (X1.isZero())
        {
            // A point with X == 0 is its own additive inverse
            return b;
        }

        final ECFieldElement X2 = b.getRawXCoord(), Z2 = b.getZCoord(0);
        if (X2.isZero() || !Z2.isOne())
        {
            return twice().add(b);
        }

        final ECFieldElement L1 = y, Z1 = zs[0];
        final ECFieldElement L2 = b.getRawYCoord();

        final ECFieldElement X1Sq = X1.square();
        final ECFieldElement L1Sq = L1.square();
        final ECFieldElement Z1Sq = Z1.square();
        final ECFieldElement L1Z1 = L1.multiply(Z1);

        final ECFieldElement T = Z1Sq.add(L1Sq).add(L1Z1);
        final ECFieldElement A = L2.multiply(Z1Sq).add(L1Sq).multiplyPlusProduct(T, X1Sq, Z1Sq);
        final ECFieldElement X2Z1Sq = X2.multiply(Z1Sq);
        final ECFieldElement B = X2Z1Sq.add(T).square();

        if (B.isZero())
        {
            if (A.isZero())
            {
                return b.twice();
            }

            return curve.getInfinity();
        }

        if (A.isZero())
        {
            return new SecT283R1Point(curve, A, curve.getB().sqrt());
        }

        final ECFieldElement X3 = A.square().multiply(X2Z1Sq);
        final ECFieldElement Z3 = A.multiply(B).multiply(Z1Sq);
        final ECFieldElement L3 = A.add(B).square().multiplyPlusProduct(T, L2.addOne(), Z3);

        return new SecT283R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
    }

    @Override
	public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        final ECFieldElement X = x;
        if (X.isZero())
        {
            return this;
        }

        // L is actually Lambda (X + Y/X) here
        final ECFieldElement L = y, Z = zs[0];
        return new SecT283R1Point(curve, X, L.add(Z), new ECFieldElement[]{ Z });
    }
}
