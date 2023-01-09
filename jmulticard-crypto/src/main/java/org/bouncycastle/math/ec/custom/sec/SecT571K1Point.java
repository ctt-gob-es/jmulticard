package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.AbstractF2m;
import org.bouncycastle.math.raw.Nat576;

public class SecT571K1Point extends AbstractF2m
{
    SecT571K1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        super(curve, x, y);
    }

    SecT571K1Point(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    @Override
	protected ECPoint detach()
    {
        return new SecT571K1Point(null, this.getAffineXCoord(), this.getAffineYCoord()); // earlier JDK
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

        SecT571FieldElement X1 = (SecT571FieldElement)x;
        final SecT571FieldElement X2 = (SecT571FieldElement)b.getRawXCoord();

        if (X1.isZero())
        {
            if (X2.isZero())
            {
                return curve.getInfinity();
            }

            return b.add(this);
        }

        final SecT571FieldElement L1 = (SecT571FieldElement)y, Z1 = (SecT571FieldElement)zs[0];
        final SecT571FieldElement L2 = (SecT571FieldElement)b.getRawYCoord(), Z2 = (SecT571FieldElement)b.getZCoord(0);

        final long[] t1 = Nat576.create64();
        final long[] t2 = Nat576.create64();
        final long[] t3 = Nat576.create64();
        final long[] t4 = Nat576.create64();

        final long[] Z1Precomp = Z1.isOne() ? null : SecT571Field.precompMultiplicand(Z1.x);
        long[] U2, S2;
        if (Z1Precomp == null)
        {
            U2 = X2.x;
            S2 = L2.x;
        }
        else
        {
            SecT571Field.multiplyPrecomp(X2.x, Z1Precomp, U2 = t2);
            SecT571Field.multiplyPrecomp(L2.x, Z1Precomp, S2 = t4);
        }

        final long[] Z2Precomp = Z2.isOne() ? null : SecT571Field.precompMultiplicand(Z2.x);
        long[] U1, S1;
        if (Z2Precomp == null)
        {
            U1 = X1.x;
            S1 = L1.x;
        }
        else
        {
            SecT571Field.multiplyPrecomp(X1.x, Z2Precomp, U1 = t1);
            SecT571Field.multiplyPrecomp(L1.x, Z2Precomp, S1 = t3);
        }

        final long[] A = t3;
        SecT571Field.add(S1, S2, A);

        final long[] B = t4;
        SecT571Field.add(U1, U2, B);

        if (Nat576.isZero64(B))
        {
            if (Nat576.isZero64(A))
            {
                return twice();
            }

            return curve.getInfinity();
        }

        SecT571FieldElement X3, L3, Z3;
        if (X2.isZero())
        {
            // TODO This can probably be optimized quite a bit
            final ECPoint p = this.normalize();
            X1 = (SecT571FieldElement)p.getXCoord();
            final ECFieldElement Y1 = p.getYCoord();

            final ECFieldElement Y2 = L2;
            final ECFieldElement L = Y1.add(Y2).divide(X1);

            X3 = (SecT571FieldElement)L.square().add(L).add(X1);
            if (X3.isZero())
            {
                return new SecT571K1Point(curve, X3, curve.getB());
            }

            final ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);
            L3 = (SecT571FieldElement)Y3.divide(X3).add(X3);
            Z3 = (SecT571FieldElement)curve.fromBigInteger(ECConstants.ONE);
        }
        else
        {
            SecT571Field.square(B, B);

            final long[] APrecomp = SecT571Field.precompMultiplicand(A);

            final long[] AU1 = t1;
            final long[] AU2 = t2;

            SecT571Field.multiplyPrecomp(U1, APrecomp, AU1);
            SecT571Field.multiplyPrecomp(U2, APrecomp, AU2);

            X3 = new SecT571FieldElement(t1);
            SecT571Field.multiply(AU1, AU2, X3.x);

            if (X3.isZero())
            {
                return new SecT571K1Point(curve, X3, curve.getB());
            }

            Z3 = new SecT571FieldElement(t3);
            SecT571Field.multiplyPrecomp(B, APrecomp, Z3.x);

            if (Z2Precomp != null)
            {
                SecT571Field.multiplyPrecomp(Z3.x, Z2Precomp, Z3.x);
            }

            final long[] tt = Nat576.createExt64();

            SecT571Field.add(AU2, B, t4);
            SecT571Field.squareAddToExt(t4, tt);

            SecT571Field.add(L1.x, Z1.x, t4);
            SecT571Field.multiplyAddToExt(t4, Z3.x, tt);

            L3 = new SecT571FieldElement(t4);
            SecT571Field.reduce(tt, L3.x);

            if (Z1Precomp != null)
            {
                SecT571Field.multiplyPrecomp(Z3.x, Z1Precomp, Z3.x);
            }
        }

        return new SecT571K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
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
        final ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
        ECFieldElement T;
        if (Z1IsOne)
        {
            T = L1.square().add(L1);
        }
        else
        {
            T = L1.add(Z1).multiply(L1);
        }

        if (T.isZero())
        {
            return new SecT571K1Point(curve, T, curve.getB());
        }

        final ECFieldElement X3 = T.square();
        final ECFieldElement Z3 = Z1IsOne ? T : T.multiply(Z1Sq);

        final ECFieldElement t1 = L1.add(X1).square();
        final ECFieldElement t2 = Z1IsOne ? Z1 : Z1Sq.square();
        final ECFieldElement L3 = t1.add(T).add(Z1Sq).multiply(t1).add(t2).add(X3).add(Z3);

        return new SecT571K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
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

        // NOTE: twicePlus() only optimized for lambda-affine argument
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

        final ECFieldElement T = L1Sq.add(L1Z1);
        final ECFieldElement L2plus1 = L2.addOne();
        final ECFieldElement A = L2plus1.multiply(Z1Sq).add(L1Sq).multiplyPlusProduct(T, X1Sq, Z1Sq);
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
            return new SecT571K1Point(curve, A, curve.getB());
        }

        final ECFieldElement X3 = A.square().multiply(X2Z1Sq);
        final ECFieldElement Z3 = A.multiply(B).multiply(Z1Sq);
        final ECFieldElement L3 = A.add(B).square().multiplyPlusProduct(T, L2plus1, Z3);

        return new SecT571K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
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
        return new SecT571K1Point(curve, X, L.add(Z), new ECFieldElement[]{ Z });
    }
}
