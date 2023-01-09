package org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

/**
 * base class for points on elliptic curves.
 */
public abstract class ECPoint
{
    protected final static ECFieldElement[] EMPTY_ZS = {};

    protected static ECFieldElement[] getInitialZCoords(final ECCurve curve)
    {
        // Cope with null curve, most commonly used by implicitlyCa
        final int coord = null == curve ? ECCurve.COORD_AFFINE : curve.getCoordinateSystem();

        switch (coord)
        {
        case ECCurve.COORD_AFFINE:
        case ECCurve.COORD_LAMBDA_AFFINE:
            return EMPTY_ZS;
        default:
            break;
        }

        final ECFieldElement one = curve.fromBigInteger(ECConstants.ONE);

        switch (coord)
        {
        case ECCurve.COORD_HOMOGENEOUS:
        case ECCurve.COORD_JACOBIAN:
        case ECCurve.COORD_LAMBDA_PROJECTIVE:
            return new ECFieldElement[]{ one };
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
            return new ECFieldElement[]{ one, one, one };
        case ECCurve.COORD_JACOBIAN_MODIFIED:
            return new ECFieldElement[]{ one, curve.getA() };
        default:
            throw new IllegalArgumentException("unknown coordinate system");
        }
    }

    protected ECCurve curve;
    protected ECFieldElement x;
    protected ECFieldElement y;
    protected ECFieldElement[] zs;

    // Hashtable is (String -> PreCompInfo)
    protected Hashtable preCompTable = null;

    protected ECPoint(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
    {
        this(curve, x, y, getInitialZCoords(curve));
    }

    protected ECPoint(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.zs = zs;
    }

    protected abstract boolean satisfiesCurveEquation();

    protected boolean satisfiesOrder()
    {
        if (ECConstants.ONE.equals(curve.getCofactor()))
        {
            return true;
        }

        final BigInteger n = curve.getOrder();

        // TODO Require order to be available for all curves

        return n == null || ECAlgorithms.referenceMultiply(this, n).isInfinity();
    }

    public final ECPoint getDetachedPoint()
    {
        return normalize().detach();
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    protected abstract ECPoint detach();

    protected int getCurveCoordinateSystem()
    {
        // Cope with null curve, most commonly used by implicitlyCa
        return null == curve ? ECCurve.COORD_AFFINE : curve.getCoordinateSystem();
    }

    /**
     * Returns the affine x-coordinate after checking that this point is normalized.
     *
     * @return The affine x-coordinate of this point
     * @throws IllegalStateException if the point is not normalized
     */
    public ECFieldElement getAffineXCoord()
    {
        checkNormalized();
        return getXCoord();
    }

    /**
     * Returns the affine y-coordinate after checking that this point is normalized
     *
     * @return The affine y-coordinate of this point
     * @throws IllegalStateException if the point is not normalized
     */
    public ECFieldElement getAffineYCoord()
    {
        checkNormalized();
        return getYCoord();
    }

    /**
     * Returns the x-coordinate.
     *
     * Caution: depending on the curve's coordinate system, this may not be the same value as in an
     * affine coordinate system; use normalize() to get a point where the coordinates have their
     * affine values, or use getAffineXCoord() if you expect the point to already have been
     * normalized.
     *
     * @return the x-coordinate of this point
     */
    public ECFieldElement getXCoord()
    {
        return x;
    }

    /**
     * Returns the y-coordinate.
     *
     * Caution: depending on the curve's coordinate system, this may not be the same value as in an
     * affine coordinate system; use normalize() to get a point where the coordinates have their
     * affine values, or use getAffineYCoord() if you expect the point to already have been
     * normalized.
     *
     * @return the y-coordinate of this point
     */
    public ECFieldElement getYCoord()
    {
        return y;
    }

    public ECFieldElement getZCoord(final int index)
    {
        return index < 0 || index >= zs.length ? null : zs[index];
    }

    public ECFieldElement[] getZCoords()
    {
        final int zsLen = zs.length;
        if (zsLen == 0)
        {
            return EMPTY_ZS;
        }
        final ECFieldElement[] copy = new ECFieldElement[zsLen];
        System.arraycopy(zs, 0, copy, 0, zsLen);
        return copy;
    }

    public final ECFieldElement getRawXCoord()
    {
        return x;
    }

    public final ECFieldElement getRawYCoord()
    {
        return y;
    }

    protected final ECFieldElement[] getRawZCoords()
    {
        return zs;
    }

    protected void checkNormalized()
    {
        if (!isNormalized())
        {
            throw new IllegalStateException("point not in normal form");
        }
    }

    public boolean isNormalized()
    {
        final int coord = this.getCurveCoordinateSystem();

        return coord == ECCurve.COORD_AFFINE
            || coord == ECCurve.COORD_LAMBDA_AFFINE
            || isInfinity()
            || zs[0].isOne();
    }

    /**
     * Normalization ensures that any projective coordinate is 1, and therefore that the x, y
     * coordinates reflect those of the equivalent point in an affine coordinate system.
     *
     * @return a new ECPoint instance representing the same point, but with normalized coordinates
     */
    public ECPoint normalize()
    {
        if (this.isInfinity())
        {
            return this;
        }

        switch (this.getCurveCoordinateSystem())
        {
        case ECCurve.COORD_AFFINE:
        case ECCurve.COORD_LAMBDA_AFFINE:
        {
            return this;
        }
        default:
        {
            final ECFieldElement z = getZCoord(0);
            if (z.isOne())
            {
                return this;
            }

            if (null == curve)
            {
                throw new IllegalStateException("Detached points must be in affine coordinates");
            }

            /*
             * Use blinding to avoid the side-channel leak identified and analyzed in the paper
             * "Yet another GCD based inversion side-channel affecting ECC implementations" by Nir
             * Drucker and Shay Gueron.
             *
             * To blind the calculation of z^-1, choose a multiplicative (i.e. non-zero) field
             * element 'b' uniformly at random, then calculate the result instead as (z * b)^-1 * b.
             * Any side-channel in the implementation of 'inverse' now only leaks information about
             * the value (z * b), and no longer reveals information about 'z' itself.
             */
            final SecureRandom r = CryptoServicesRegistrar.getSecureRandom();
            final ECFieldElement b = curve.randomFieldElementMult(r);
            final ECFieldElement zInv = z.multiply(b).invert().multiply(b);
            return normalize(zInv);
        }
        }
    }

    ECPoint normalize(final ECFieldElement zInv)
    {
        switch (this.getCurveCoordinateSystem())
        {
        case ECCurve.COORD_HOMOGENEOUS:
        case ECCurve.COORD_LAMBDA_PROJECTIVE:
        {
            return createScaledPoint(zInv, zInv);
        }
        case ECCurve.COORD_JACOBIAN:
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
        case ECCurve.COORD_JACOBIAN_MODIFIED:
        {
            final ECFieldElement zInv2 = zInv.square(), zInv3 = zInv2.multiply(zInv);
            return createScaledPoint(zInv2, zInv3);
        }
        default:
        {
            throw new IllegalStateException("not a projective coordinate system");
        }
        }
    }

    protected ECPoint createScaledPoint(final ECFieldElement sx, final ECFieldElement sy)
    {
        return this.getCurve().createRawPoint(getRawXCoord().multiply(sx), getRawYCoord().multiply(sy));
    }

    public boolean isInfinity()
    {
        return x == null || y == null || zs.length > 0 && zs[0].isZero();
    }

    public boolean isValid()
    {
        return implIsValid(false, true);
    }

    boolean isValidPartial()
    {
        return implIsValid(false, false);
    }

    boolean implIsValid(final boolean decompressed, final boolean checkOrder)
    {
        if (isInfinity())
        {
            return true;
        }

        final ValidityPrecompInfo validity = (ValidityPrecompInfo)getCurve().precompute(this, ValidityPrecompInfo.PRECOMP_NAME, new PreCompCallback()
        {
            @Override
			public PreCompInfo precompute(final PreCompInfo existing)
            {
                ValidityPrecompInfo info = existing instanceof ValidityPrecompInfo ? (ValidityPrecompInfo)existing : null;
                if (info == null)
                {
                    info = new ValidityPrecompInfo();
                }

                if (info.hasFailed())
                {
                    return info;
                }
                if (!info.hasCurveEquationPassed())
                {
                    if (!decompressed && !satisfiesCurveEquation())
                    {
                        info.reportFailed();
                        return info;
                    }
                    info.reportCurveEquationPassed();
                }
                if (checkOrder && !info.hasOrderPassed())
                {
                    if (!satisfiesOrder())
                    {
                        info.reportFailed();
                        return info;
                    }
                    info.reportOrderPassed();
                }
                return info;
            }
        });

        return !validity.hasFailed();
    }

    public ECPoint scaleX(final ECFieldElement scale)
    {
        return isInfinity()
            ?   this
            :   getCurve().createRawPoint(getRawXCoord().multiply(scale), getRawYCoord(), getRawZCoords());
    }

    public ECPoint scaleXNegateY(final ECFieldElement scale)
    {
        return isInfinity()
            ?   this
            :   getCurve().createRawPoint(getRawXCoord().multiply(scale), getRawYCoord().negate(), getRawZCoords());
    }

    public ECPoint scaleY(final ECFieldElement scale)
    {
        return isInfinity()
            ?   this
            :   getCurve().createRawPoint(getRawXCoord(), getRawYCoord().multiply(scale), getRawZCoords());
    }

    public ECPoint scaleYNegateX(final ECFieldElement scale)
    {
        return isInfinity()
            ?   this
            :   getCurve().createRawPoint(getRawXCoord().negate(), getRawYCoord().multiply(scale), getRawZCoords());
    }

    public boolean equals(final ECPoint other)
    {
        if (null == other)
        {
            return false;
        }

        final ECCurve c1 = this.getCurve(), c2 = other.getCurve();
        final boolean n1 = null == c1, n2 = null == c2;
        final boolean i1 = isInfinity(), i2 = other.isInfinity();

        if (i1 || i2)
        {
            return i1 && i2 && (n1 || n2 || c1.equals(c2));
        }

        ECPoint p1 = this, p2 = other;
        if (n1 && n2)
        {
            // Points with null curve are in affine form, so already normalized
        }
        else if (n1)
        {
            p2 = p2.normalize();
        }
        else if (n2)
        {
            p1 = p1.normalize();
        }
        else if (!c1.equals(c2))
        {
            return false;
        }
        else
        {
            // TODO Consider just requiring already normalized, to avoid silent performance degradation

            final ECPoint[] points = { this, c1.importPoint(p2) };

            // TODO This is a little strong, really only requires coZNormalizeAll to get Zs equal
            c1.normalizeAll(points);

            p1 = points[0];
            p2 = points[1];
        }

        return p1.getXCoord().equals(p2.getXCoord()) && p1.getYCoord().equals(p2.getYCoord());
    }

    @Override
	public boolean equals(final Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof ECPoint))
        {
            return false;
        }

        return equals((ECPoint)other);
    }

    @Override
	public int hashCode()
    {
        final ECCurve c = this.getCurve();
        int hc = null == c ? 0 : ~c.hashCode();

        if (!this.isInfinity())
        {
            // TODO Consider just requiring already normalized, to avoid silent performance degradation

            final ECPoint p = normalize();

            hc ^= p.getXCoord().hashCode() * 17;
            hc ^= p.getYCoord().hashCode() * 257;
        }

        return hc;
    }

    @Override
	public String toString()
    {
        if (this.isInfinity())
        {
            return "INF";
        }

        final StringBuilder sb = new StringBuilder();
        sb.append('(');
        sb.append(getRawXCoord());
        sb.append(',');
        sb.append(getRawYCoord());
        for (final ECFieldElement element : zs) {
            sb.append(',');
            sb.append(element);
        }
        sb.append(')');
        return sb.toString();
    }

    /**
     * Get an encoding of the point value, optionally in compressed format.
     *
     * @param compressed whether to generate a compressed point encoding.
     * @return the point encoding
     */
    public byte[] getEncoded(final boolean compressed)
    {
        if (this.isInfinity())
        {
            return new byte[1];
        }

        final ECPoint normed = normalize();

        final byte[] X = normed.getXCoord().getEncoded();

        if (compressed)
        {
            final byte[] PO = new byte[X.length + 1];
            PO[0] = (byte)(normed.getCompressionYTilde() ? 0x03 : 0x02);
            System.arraycopy(X, 0, PO, 1, X.length);
            return PO;
        }

        final byte[] Y = normed.getYCoord().getEncoded();

        final byte[] PO = new byte[X.length + Y.length + 1];
        PO[0] = 0x04;
        System.arraycopy(X, 0, PO, 1, X.length);
        System.arraycopy(Y, 0, PO, X.length + 1, Y.length);
        return PO;
    }

    protected abstract boolean getCompressionYTilde();

    public abstract ECPoint add(ECPoint b);

    public abstract ECPoint negate();

    public abstract ECPoint subtract(ECPoint b);

    public ECPoint timesPow2(int e)
    {
        if (e < 0)
        {
            throw new IllegalArgumentException("'e' cannot be negative");
        }

        ECPoint p = this;
        while (--e >= 0)
        {
            p = p.twice();
        }
        return p;
    }

    public abstract ECPoint twice();

    public ECPoint twicePlus(final ECPoint b)
    {
        return twice().add(b);
    }

    public ECPoint threeTimes()
    {
        return twicePlus(this);
    }

    /**
     * Multiplies this <code>ECPoint</code> by the given number.
     * @param k The multiplicator.
     * @return <code>k * this</code>.
     */
    public ECPoint multiply(final BigInteger k)
    {
        return this.getCurve().getMultiplier().multiply(this, k);
    }

    public static abstract class AbstractFp extends ECPoint
    {
        protected AbstractFp(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
        {
            super(curve, x, y);
        }

        protected AbstractFp(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
        {
            super(curve, x, y, zs);
        }

        @Override
		protected boolean getCompressionYTilde()
        {
            return this.getAffineYCoord().testBitZero();
        }

        @Override
		protected boolean satisfiesCurveEquation()
        {
            final ECFieldElement X = x, Y = y;
			ECFieldElement A = curve.getA(), B = curve.getB();
            ECFieldElement lhs = Y.square();

            switch (this.getCurveCoordinateSystem())
            {
            case ECCurve.COORD_AFFINE:
                break;
            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Z = zs[0];
                if (!Z.isOne())
                {
                    final ECFieldElement Z2 = Z.square(), Z3 = Z.multiply(Z2);
                    lhs = lhs.multiply(Z);
                    A = A.multiply(Z2);
                    B = B.multiply(Z3);
                }
                break;
            }
            case ECCurve.COORD_JACOBIAN:
            case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                final ECFieldElement Z = zs[0];
                if (!Z.isOne())
                {
                    final ECFieldElement Z2 = Z.square(), Z4 = Z2.square(), Z6 = Z2.multiply(Z4);
                    A = A.multiply(Z4);
                    B = B.multiply(Z6);
                }
                break;
            }
            default:
                throw new IllegalStateException("unsupported coordinate system");
            }

            final ECFieldElement rhs = X.square().add(A).multiply(X).add(B);
            return lhs.equals(rhs);
        }

        @Override
		public ECPoint subtract(final ECPoint b)
        {
            if (b.isInfinity())
            {
                return this;
            }

            // Add -b
            return this.add(b.negate());
        }
    }

    /**
     * Elliptic curve points over Fp
     */
    public static class Fp extends AbstractFp
    {
        Fp(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
        {
            super(curve, x, y);
        }

        Fp(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
        {
            super(curve, x, y, zs);
        }

        @Override
		protected ECPoint detach()
        {
            return new ECPoint.Fp(null, this.getAffineXCoord(), this.getAffineYCoord());
        }

        @Override
		public ECFieldElement getZCoord(final int index)
        {
            if (index == 1 && ECCurve.COORD_JACOBIAN_MODIFIED == this.getCurveCoordinateSystem())
            {
                return getJacobianModifiedW();
            }

            return super.getZCoord(index);
        }

        // B.3 pg 62
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
            final int coord = curve.getCoordinateSystem();

            final ECFieldElement X1 = x, Y1 = y;
            final ECFieldElement X2 = b.x, Y2 = b.y;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement dx = X2.subtract(X1), dy = Y2.subtract(Y1);

                if (dx.isZero())
                {
                    if (dy.isZero())
                    {
                        // this == b, i.e. this must be doubled
                        return twice();
                    }

                    // this == -b, i.e. the result is the point at infinity
                    return curve.getInfinity();
                }

                final ECFieldElement gamma = dy.divide(dx);
                final ECFieldElement X3 = gamma.square().subtract(X1).subtract(X2);
                final ECFieldElement Y3 = gamma.multiply(X1.subtract(X3)).subtract(Y1);

                return new ECPoint.Fp(curve, X3, Y3);
            }

            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Z1 = zs[0];
                final ECFieldElement Z2 = b.zs[0];

                final boolean Z1IsOne = Z1.isOne();
                final boolean Z2IsOne = Z2.isOne();

                final ECFieldElement u1 = Z1IsOne ? Y2 : Y2.multiply(Z1);
                final ECFieldElement u2 = Z2IsOne ? Y1 : Y1.multiply(Z2);
                final ECFieldElement u = u1.subtract(u2);
                final ECFieldElement v1 = Z1IsOne ? X2 : X2.multiply(Z1);
                final ECFieldElement v2 = Z2IsOne ? X1 : X1.multiply(Z2);
                final ECFieldElement v = v1.subtract(v2);

                // Check if b == this or b == -this
                if (v.isZero())
                {
                    if (u.isZero())
                    {
                        // this == b, i.e. this must be doubled
                        return this.twice();
                    }

                    // this == -b, i.e. the result is the point at infinity
                    return curve.getInfinity();
                }

                // TODO Optimize for when w == 1
                final ECFieldElement w = Z1IsOne ? Z2 : Z2IsOne ? Z1 : Z1.multiply(Z2);
                final ECFieldElement vSquared = v.square();
                final ECFieldElement vCubed = vSquared.multiply(v);
                final ECFieldElement vSquaredV2 = vSquared.multiply(v2);
                final ECFieldElement A = u.square().multiply(w).subtract(vCubed).subtract(two(vSquaredV2));

                final ECFieldElement X3 = v.multiply(A);
                final ECFieldElement Y3 = vSquaredV2.subtract(A).multiplyMinusProduct(u, u2, vCubed);
                final ECFieldElement Z3 = vCubed.multiply(w);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            case ECCurve.COORD_JACOBIAN:
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                final ECFieldElement Z1 = zs[0];
                final ECFieldElement Z2 = b.zs[0];

                final boolean Z1IsOne = Z1.isOne();

                ECFieldElement X3, Y3, Z3, Z3Squared = null;

                if (!Z1IsOne && Z1.equals(Z2))
                {
                    // TODO Make this available as public method coZAdd?

                    final ECFieldElement dx = X1.subtract(X2), dy = Y1.subtract(Y2);
                    if (dx.isZero())
                    {
                        if (dy.isZero())
                        {
                            return twice();
                        }
                        return curve.getInfinity();
                    }

                    final ECFieldElement C = dx.square();
                    final ECFieldElement W1 = X1.multiply(C), W2 = X2.multiply(C);
                    final ECFieldElement A1 = W1.subtract(W2).multiply(Y1);

                    X3 = dy.square().subtract(W1).subtract(W2);
                    Y3 = W1.subtract(X3).multiply(dy).subtract(A1);
                    Z3 = dx;

                    Z3 = Z3.multiply(Z1);
                }
                else
                {
                    ECFieldElement Z1Squared, U2, S2;
                    if (Z1IsOne)
                    {
                        Z1Squared = Z1; U2 = X2; S2 = Y2;
                    }
                    else
                    {
                        Z1Squared = Z1.square();
                        U2 = Z1Squared.multiply(X2);
                        final ECFieldElement Z1Cubed = Z1Squared.multiply(Z1);
                        S2 = Z1Cubed.multiply(Y2);
                    }

                    final boolean Z2IsOne = Z2.isOne();
                    ECFieldElement Z2Squared, U1, S1;
                    if (Z2IsOne)
                    {
                        Z2Squared = Z2; U1 = X1; S1 = Y1;
                    }
                    else
                    {
                        Z2Squared = Z2.square();
                        U1 = Z2Squared.multiply(X1);
                        final ECFieldElement Z2Cubed = Z2Squared.multiply(Z2);
                        S1 = Z2Cubed.multiply(Y1);
                    }

                    final ECFieldElement H = U1.subtract(U2);
                    final ECFieldElement R = S1.subtract(S2);

                    // Check if b == this or b == -this
                    if (H.isZero())
                    {
                        if (R.isZero())
                        {
                            // this == b, i.e. this must be doubled
                            return this.twice();
                        }

                        // this == -b, i.e. the result is the point at infinity
                        return curve.getInfinity();
                    }

                    final ECFieldElement HSquared = H.square();
                    final ECFieldElement G = HSquared.multiply(H);
                    final ECFieldElement V = HSquared.multiply(U1);

                    X3 = R.square().add(G).subtract(two(V));
                    Y3 = V.subtract(X3).multiplyMinusProduct(R, G, S1);

                    Z3 = H;
                    if (!Z1IsOne)
                    {
                        Z3 = Z3.multiply(Z1);
                    }
                    if (!Z2IsOne)
                    {
                        Z3 = Z3.multiply(Z2);
                    }

                    // Alternative calculation of Z3 using fast square
    //                X3 = four(X3);
    //                Y3 = eight(Y3);
    //                Z3 = doubleProductFromSquares(Z1, Z2, Z1Squared, Z2Squared).multiply(H);

                    if (Z3 == H)
                    {
                        Z3Squared = HSquared;
                    }
                }

                ECFieldElement[] zs;
                if (coord == ECCurve.COORD_JACOBIAN_MODIFIED)
                {
                    // TODO If the result will only be used in a subsequent addition, we don't need W3
                    final ECFieldElement W3 = calculateJacobianModifiedW(Z3, Z3Squared);

                    zs = new ECFieldElement[]{ Z3, W3 };
                }
                else
                {
                    zs = new ECFieldElement[]{ Z3 };
                }

                return new ECPoint.Fp(curve, X3, Y3, zs);
            }

            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }

        // B.3 pg 62
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

            final int coord = curve.getCoordinateSystem();

            final ECFieldElement X1 = x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement X1Squared = X1.square();
                final ECFieldElement gamma = three(X1Squared).add(this.getCurve().getA()).divide(two(Y1));
                final ECFieldElement X3 = gamma.square().subtract(two(X1));
                final ECFieldElement Y3 = gamma.multiply(X1.subtract(X3)).subtract(Y1);

                return new ECPoint.Fp(curve, X3, Y3);
            }

            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Z1 = zs[0];

                final boolean Z1IsOne = Z1.isOne();

                // TODO Optimize for small negative a4 and -3
                ECFieldElement w = curve.getA();
                if (!w.isZero() && !Z1IsOne)
                {
                    w = w.multiply(Z1.square());
                }
                w = w.add(three(X1.square()));

                final ECFieldElement s = Z1IsOne ? Y1 : Y1.multiply(Z1);
                final ECFieldElement t = Z1IsOne ? Y1.square() : s.multiply(Y1);
                final ECFieldElement B = X1.multiply(t);
                final ECFieldElement _4B = four(B);
                final ECFieldElement h = w.square().subtract(two(_4B));

                final ECFieldElement _2s = two(s);
                final ECFieldElement X3 = h.multiply(_2s);
                final ECFieldElement _2t = two(t);
                final ECFieldElement Y3 = _4B.subtract(h).multiply(w).subtract(two(_2t.square()));
                final ECFieldElement _4sSquared = Z1IsOne ? two(_2t) : _2s.square();
                final ECFieldElement Z3 = two(_4sSquared).multiply(s);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            case ECCurve.COORD_JACOBIAN:
            {
                final ECFieldElement Z1 = zs[0];

                final boolean Z1IsOne = Z1.isOne();

                final ECFieldElement Y1Squared = Y1.square();
                final ECFieldElement T = Y1Squared.square();

                final ECFieldElement a4 = curve.getA();
                final ECFieldElement a4Neg = a4.negate();

                ECFieldElement M, S;
                if (a4Neg.toBigInteger().equals(BigInteger.valueOf(3)))
                {
                    final ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.square();
                    M = three(X1.add(Z1Squared).multiply(X1.subtract(Z1Squared)));
                    S = four(Y1Squared.multiply(X1));
                }
                else
                {
                    final ECFieldElement X1Squared = X1.square();
                    M = three(X1Squared);
                    if (Z1IsOne)
                    {
                        M = M.add(a4);
                    }
                    else if (!a4.isZero())
                    {
                        final ECFieldElement Z1Squared = Z1.square();
                        final ECFieldElement Z1Pow4 = Z1Squared.square();
                        if (a4Neg.bitLength() < a4.bitLength())
                        {
                            M = M.subtract(Z1Pow4.multiply(a4Neg));
                        }
                        else
                        {
                            M = M.add(Z1Pow4.multiply(a4));
                        }
                    }
//                  S = two(doubleProductFromSquares(X1, Y1Squared, X1Squared, T));
                    S = four(X1.multiply(Y1Squared));
                }

                final ECFieldElement X3 = M.square().subtract(two(S));
                final ECFieldElement Y3 = S.subtract(X3).multiply(M).subtract(eight(T));

                ECFieldElement Z3 = two(Y1);
                if (!Z1IsOne)
                {
                    Z3 = Z3.multiply(Z1);
                }

                // Alternative calculation of Z3 using fast square
//                ECFieldElement Z3 = doubleProductFromSquares(Y1, Z1, Y1Squared, Z1Squared);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return twiceJacobianModified(true);
            }

            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
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

            final ECCurve curve = this.getCurve();
            final int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement X1 = x;
                final ECFieldElement X2 = b.x, Y2 = b.y;

                final ECFieldElement dx = X2.subtract(X1), dy = Y2.subtract(Y1);

                if (dx.isZero())
                {
                    if (dy.isZero())
                    {
                        // this == b i.e. the result is 3P
                        return threeTimes();
                    }

                    // this == -b, i.e. the result is P
                    return this;
                }

                /*
                 * Optimized calculation of 2P + Q, as described in "Trading Inversions for
                 * Multiplications in Elliptic Curve Cryptography", by Ciet, Joye, Lauter, Montgomery.
                 */

                final ECFieldElement X = dx.square(), Y = dy.square();
                final ECFieldElement d = X.multiply(two(X1).add(X2)).subtract(Y);
                if (d.isZero())
                {
                    return curve.getInfinity();
                }

                final ECFieldElement D = d.multiply(dx);
                final ECFieldElement I = D.invert();
                final ECFieldElement L1 = d.multiply(I).multiply(dy);
                final ECFieldElement L2 = two(Y1).multiply(X).multiply(dx).multiply(I).subtract(L1);
                final ECFieldElement X4 = L2.subtract(L1).multiply(L1.add(L2)).add(X2);
                final ECFieldElement Y4 = X1.subtract(X4).multiply(L2).subtract(Y1);

                return new ECPoint.Fp(curve, X4, Y4);
            }
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return twiceJacobianModified(false).add(b);
            }
            default:
            {
                return twice().add(b);
            }
            }
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

            final ECCurve curve = this.getCurve();
            final int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement X1 = x;

                final ECFieldElement _2Y1 = two(Y1);
                final ECFieldElement X = _2Y1.square();
                final ECFieldElement Z = three(X1.square()).add(this.getCurve().getA());
                final ECFieldElement Y = Z.square();

                final ECFieldElement d = three(X1).multiply(X).subtract(Y);
                if (d.isZero())
                {
                    return this.getCurve().getInfinity();
                }

                final ECFieldElement D = d.multiply(_2Y1);
                final ECFieldElement I = D.invert();
                final ECFieldElement L1 = d.multiply(I).multiply(Z);
                final ECFieldElement L2 = X.square().multiply(I).subtract(L1);

                final ECFieldElement X4 = L2.subtract(L1).multiply(L1.add(L2)).add(X1);
                final ECFieldElement Y4 = X1.subtract(X4).multiply(L2).subtract(Y1);
                return new ECPoint.Fp(curve, X4, Y4);
            }
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return twiceJacobianModified(false).add(this);
            }
            default:
            {
                // NOTE: Be careful about recursions between twicePlus and threeTimes
                return twice().add(this);
            }
            }
        }

        @Override
		public ECPoint timesPow2(final int e)
        {
            if (e < 0)
            {
                throw new IllegalArgumentException("'e' cannot be negative");
            }
            if (e == 0 || this.isInfinity())
            {
                return this;
            }
            if (e == 1)
            {
                return twice();
            }

            final ECCurve curve = this.getCurve();

            ECFieldElement Y1 = y;
            if (Y1.isZero())
            {
                return curve.getInfinity();
            }

            final int coord = curve.getCoordinateSystem();

            ECFieldElement W1 = curve.getA();
            ECFieldElement X1 = x;
            ECFieldElement Z1 = zs.length < 1 ? curve.fromBigInteger(ECConstants.ONE) : zs[0];

            if (!Z1.isOne())
            {
                switch (coord)
                {
                case ECCurve.COORD_AFFINE:
                    break;
                case ECCurve.COORD_HOMOGENEOUS:
                    final ECFieldElement Z1Sq = Z1.square();
                    X1 = X1.multiply(Z1);
                    Y1 = Y1.multiply(Z1Sq);
                    W1 = calculateJacobianModifiedW(Z1, Z1Sq);
                    break;
                case ECCurve.COORD_JACOBIAN:
                    W1 = calculateJacobianModifiedW(Z1, null);
                    break;
                case ECCurve.COORD_JACOBIAN_MODIFIED:
                    W1 = getJacobianModifiedW();
                    break;
                default:
                    throw new IllegalStateException("unsupported coordinate system");
                }
            }

            for (int i = 0; i < e; ++i)
            {
                if (Y1.isZero())
                {
                    return curve.getInfinity();
                }

                final ECFieldElement X1Squared = X1.square();
                ECFieldElement M = three(X1Squared);
                final ECFieldElement _2Y1 = two(Y1);
                final ECFieldElement _2Y1Squared = _2Y1.multiply(Y1);
                final ECFieldElement S = two(X1.multiply(_2Y1Squared));
                final ECFieldElement _4T = _2Y1Squared.square();
                final ECFieldElement _8T = two(_4T);

                if (!W1.isZero())
                {
                    M = M.add(W1);
                    W1 = two(_8T.multiply(W1));
                }

                X1 = M.square().subtract(two(S));
                Y1 = M.multiply(S.subtract(X1)).subtract(_8T);
                Z1 = Z1.isOne() ? _2Y1 : _2Y1.multiply(Z1);
            }

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
                final ECFieldElement zInv = Z1.invert(), zInv2 = zInv.square(), zInv3 = zInv2.multiply(zInv);
                return new Fp(curve, X1.multiply(zInv2), Y1.multiply(zInv3));
            case ECCurve.COORD_HOMOGENEOUS:
                X1 = X1.multiply(Z1);
                Z1 = Z1.multiply(Z1.square());
                return new Fp(curve, X1, Y1, new ECFieldElement[]{ Z1 });
            case ECCurve.COORD_JACOBIAN:
                return new Fp(curve, X1, Y1, new ECFieldElement[]{ Z1 });
            case ECCurve.COORD_JACOBIAN_MODIFIED:
                return new Fp(curve, X1, Y1, new ECFieldElement[]{ Z1, W1 });
            default:
                throw new IllegalStateException("unsupported coordinate system");
            }
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

            final ECCurve curve = this.getCurve();
            final int coord = curve.getCoordinateSystem();

            if (ECCurve.COORD_AFFINE != coord)
            {
                return new ECPoint.Fp(curve, x, y.negate(), zs);
            }

            return new ECPoint.Fp(curve, x, y.negate());
        }

        protected ECFieldElement calculateJacobianModifiedW(final ECFieldElement Z, ECFieldElement ZSquared)
        {
            final ECFieldElement a4 = this.getCurve().getA();
            if (a4.isZero() || Z.isOne())
            {
                return a4;
            }

            if (ZSquared == null)
            {
                ZSquared = Z.square();
            }

            ECFieldElement W = ZSquared.square();
            final ECFieldElement a4Neg = a4.negate();
            if (a4Neg.bitLength() < a4.bitLength())
            {
                W = W.multiply(a4Neg).negate();
            }
            else
            {
                W = W.multiply(a4);
            }
            return W;
        }

        protected ECFieldElement getJacobianModifiedW()
        {
            ECFieldElement W = zs[1];
            if (W == null)
            {
                // NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
                zs[1] = W = calculateJacobianModifiedW(zs[0], null);
            }
            return W;
        }

        protected ECPoint.Fp twiceJacobianModified(final boolean calculateW)
        {
            final ECFieldElement X1 = x, Y1 = y, Z1 = zs[0], W1 = getJacobianModifiedW();

            final ECFieldElement X1Squared = X1.square();
            final ECFieldElement M = three(X1Squared).add(W1);
            final ECFieldElement _2Y1 = two(Y1);
            final ECFieldElement _2Y1Squared = _2Y1.multiply(Y1);
            final ECFieldElement S = two(X1.multiply(_2Y1Squared));
            final ECFieldElement X3 = M.square().subtract(two(S));
            final ECFieldElement _4T = _2Y1Squared.square();
            final ECFieldElement _8T = two(_4T);
            final ECFieldElement Y3 = M.multiply(S.subtract(X3)).subtract(_8T);
            final ECFieldElement W3 = calculateW ? two(_8T.multiply(W1)) : null;
            final ECFieldElement Z3 = Z1.isOne() ? _2Y1 : _2Y1.multiply(Z1);

            return new ECPoint.Fp(this.getCurve(), X3, Y3, new ECFieldElement[]{ Z3, W3 });
        }
    }

    public static abstract class AbstractF2m extends ECPoint
    {
        protected AbstractF2m(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
        {
            super(curve, x, y);
        }

        protected AbstractF2m(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
        {
            super(curve, x, y, zs);
        }

        @Override
		protected boolean satisfiesCurveEquation()
        {
            final ECCurve curve = this.getCurve();
            final ECFieldElement X = x;
			ECFieldElement A = curve.getA(), B = curve.getB();

            final int coord = curve.getCoordinateSystem();
            if (coord == ECCurve.COORD_LAMBDA_PROJECTIVE)
            {
                final ECFieldElement Z = zs[0];
                final boolean ZIsOne = Z.isOne();

                if (X.isZero())
                {
                    // NOTE: For x == 0, we expect the affine-y instead of the lambda-y
                    final ECFieldElement Y = y;
                    final ECFieldElement lhs = Y.square();
					ECFieldElement rhs = B;
                    if (!ZIsOne)
                    {
                        rhs = rhs.multiply(Z.square());
                    }
                    return lhs.equals(rhs);
                }

                final ECFieldElement L = y, X2 = X.square();
                ECFieldElement lhs, rhs;
                if (ZIsOne)
                {
                    lhs = L.square().add(L).add(A);
                    rhs = X2.square().add(B);
                }
                else
                {
                    final ECFieldElement Z2 = Z.square(), Z4 = Z2.square();
                    lhs = L.add(Z).multiplyPlusProduct(L, A, Z2);
                    // TODO If sqrt(b) is precomputed this can be simplified to a single square
                    rhs = X2.squarePlusProduct(B, Z4);
                }
                lhs = lhs.multiply(X2);
                return lhs.equals(rhs);
            }

            final ECFieldElement Y = y;
            ECFieldElement lhs = Y.add(X).multiply(Y);

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
                break;
            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Z = zs[0];
                if (!Z.isOne())
                {
                    final ECFieldElement Z2 = Z.square(), Z3 = Z.multiply(Z2);
                    lhs = lhs.multiply(Z);
                    A = A.multiply(Z);
                    B = B.multiply(Z3);
                }
                break;
            }
            default:
                throw new IllegalStateException("unsupported coordinate system");
            }

            final ECFieldElement rhs = X.add(A).multiply(X.square()).add(B);
            return lhs.equals(rhs);
        }

        @Override
		protected boolean satisfiesOrder()
        {
            final BigInteger cofactor = curve.getCofactor();
            if (ECConstants.TWO.equals(cofactor))
            {
                /*
                 * Check that 0 == Tr(X + A); then there exists a solution to L^2 + L = X + A, and
                 * so a halving is possible, so this point is the double of another.
                 *
                 * Note: Tr(A) == 1 for cofactor 2 curves.
                 */
                final ECPoint N = this.normalize();
                final ECFieldElement X = N.getAffineXCoord();
                return 0 != ((ECFieldElement.AbstractF2m)X).trace();
            }
            if (ECConstants.FOUR.equals(cofactor))
            {
                /*
                 * Solve L^2 + L = X + A to find the half of this point, if it exists (fail if not).
                 *
                 * Note: Tr(A) == 0 for cofactor 4 curves.
                 */
                final ECPoint N = this.normalize();
                final ECFieldElement X = N.getAffineXCoord();
                final ECFieldElement L = ((ECCurve.AbstractF2m)curve).solveQuadraticEquation(X.add(curve.getA()));
                if (null == L)
                {
                    return false;
                }

                /*
                 * A solution exists, therefore 0 == Tr(X + A) == Tr(X).
                 */
                final ECFieldElement Y = N.getAffineYCoord();
                final ECFieldElement T = X.multiply(L).add(Y);

                /*
                 * Either T or (T + X) is the square of a half-point's x coordinate (hx). In either
                 * case, the half-point can be halved again when 0 == Tr(hx + A).
                 *
                 * Note: Tr(hx + A) == Tr(hx) == Tr(hx^2) == Tr(T) == Tr(T + X)
                 *
                 * Check that 0 == Tr(T); then there exists a solution to L^2 + L = hx + A, and so a
                 * second halving is possible and this point is four times some other.
                 */
                return 0 == ((ECFieldElement.AbstractF2m)T).trace();
            }

            return super.satisfiesOrder();
        }

        @Override
		public ECPoint scaleX(final ECFieldElement scale)
        {
            if (this.isInfinity())
            {
                return this;
            }

            final int coord = this.getCurveCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                // Y is actually Lambda (X + Y/X) here
                final ECFieldElement X = this.getRawXCoord(), L = this.getRawYCoord(); // earlier JDK

                final ECFieldElement X2 = X.multiply(scale);
                final ECFieldElement L2 = L.add(X).divide(scale).add(X2);

                return this.getCurve().createRawPoint(X, L2, this.getRawZCoords()); // earlier JDK
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // Y is actually Lambda (X + Y/X) here
                final ECFieldElement X = this.getRawXCoord(), L = this.getRawYCoord(), Z = this.getRawZCoords()[0]; // earlier JDK

                // We scale the Z coordinate also, to avoid an inversion
                final ECFieldElement X2 = X.multiply(scale.square());
                final ECFieldElement L2 = L.add(X).add(X2);
                final ECFieldElement Z2 = Z.multiply(scale);

                return this.getCurve().createRawPoint(X2, L2, new ECFieldElement[]{ Z2 }); // earlier JDK
            }
            default:
            {
                return super.scaleX(scale);
            }
            }
        }

        @Override
		public ECPoint scaleXNegateY(final ECFieldElement scale)
        {
            return scaleX(scale);
        }

        @Override
		public ECPoint scaleY(final ECFieldElement scale)
        {
            if (this.isInfinity())
            {
                return this;
            }

            final int coord = this.getCurveCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                final ECFieldElement X = this.getRawXCoord(), L = this.getRawYCoord(); // earlier JDK

                // Y is actually Lambda (X + Y/X) here
                final ECFieldElement L2 = L.add(X).multiply(scale).add(X);

                return this.getCurve().createRawPoint(X, L2, this.getRawZCoords()); // earlier JDK
            }
            default:
            {
                return super.scaleY(scale);
            }
            }
        }

        @Override
		public ECPoint scaleYNegateX(final ECFieldElement scale)
        {
            return scaleY(scale);
        }

        @Override
		public ECPoint subtract(final ECPoint b)
        {
            if (b.isInfinity())
            {
                return this;
            }

            // Add -b
            return this.add(b.negate());
        }

        public ECPoint.AbstractF2m tau()
        {
            if (this.isInfinity())
            {
                return this;
            }

            final ECCurve curve = this.getCurve();
            final int coord = curve.getCoordinateSystem();

            final ECFieldElement X1 = x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                final ECFieldElement Y1 = y;
                return (ECPoint.AbstractF2m)curve.createRawPoint(X1.square(), Y1.square());
            }
            case ECCurve.COORD_HOMOGENEOUS:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                final ECFieldElement Y1 = y, Z1 = zs[0];
                return (ECPoint.AbstractF2m)curve.createRawPoint(X1.square(), Y1.square(),
                    new ECFieldElement[]{ Z1.square() });
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }

        public ECPoint.AbstractF2m tauPow(final int pow)
        {
            if (this.isInfinity())
            {
                return this;
            }

            final ECCurve curve = this.getCurve();
            final int coord = curve.getCoordinateSystem();

            final ECFieldElement X1 = x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                final ECFieldElement Y1 = y;
                return (ECPoint.AbstractF2m)curve.createRawPoint(X1.squarePow(pow), Y1.squarePow(pow));
            }
            case ECCurve.COORD_HOMOGENEOUS:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                final ECFieldElement Y1 = y, Z1 = zs[0];
                return (ECPoint.AbstractF2m)curve.createRawPoint(X1.squarePow(pow), Y1.squarePow(pow),
                    new ECFieldElement[]{ Z1.squarePow(pow) });
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }
    }

    /**
     * Elliptic curve points over F2m
     */
    public static class F2m extends AbstractF2m
    {
        F2m(final ECCurve curve, final ECFieldElement x, final ECFieldElement y)
        {
            super(curve, x, y);

//            checkCurveEquation();
        }

        F2m(final ECCurve curve, final ECFieldElement x, final ECFieldElement y, final ECFieldElement[] zs)
        {
            super(curve, x, y, zs);

//            checkCurveEquation();
        }

        @Override
		protected ECPoint detach()
        {
            return new ECPoint.F2m(null, this.getAffineXCoord(), this.getAffineYCoord()); // earlier JDK
        }

        @Override
		public ECFieldElement getYCoord()
        {
            final int coord = this.getCurveCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                final ECFieldElement X = x, L = y;

                if (this.isInfinity() || X.isZero())
                {
                    return L;
                }

                // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
                ECFieldElement Y = L.add(X).multiply(X);
                if (ECCurve.COORD_LAMBDA_PROJECTIVE == coord)
                {
                    final ECFieldElement Z = zs[0];
                    if (!Z.isOne())
                    {
                        Y = Y.divide(Z);
                    }
                }
                return Y;
            }
            default:
            {
                return y;
            }
            }
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

            switch (this.getCurveCoordinateSystem())
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // Y is actually Lambda (X + Y/X) here
                return Y.testBitZero() != X.testBitZero();
            }
            default:
            {
                return Y.divide(X).testBitZero();
            }
            }
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
            final int coord = curve.getCoordinateSystem();

            ECFieldElement X1 = x;
            final ECFieldElement X2 = b.x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement Y1 = y;
                final ECFieldElement Y2 = b.y;

                final ECFieldElement dx = X1.add(X2), dy = Y1.add(Y2);
                if (dx.isZero())
                {
                    if (dy.isZero())
                    {
                        return twice();
                    }

                    return curve.getInfinity();
                }

                final ECFieldElement L = dy.divide(dx);

                final ECFieldElement X3 = L.square().add(L).add(dx).add(curve.getA());
                final ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);

                return new ECPoint.F2m(curve, X3, Y3);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Y1 = y, Z1 = zs[0];
                final ECFieldElement Y2 = b.y, Z2 = b.zs[0];

                final boolean Z2IsOne = Z2.isOne();

                final ECFieldElement U1 = Z1.multiply(Y2);
                final ECFieldElement U2 = Z2IsOne ? Y1 : Y1.multiply(Z2);
                final ECFieldElement U = U1.add(U2);
                final ECFieldElement V1 = Z1.multiply(X2);
                final ECFieldElement V2 = Z2IsOne ? X1 : X1.multiply(Z2);
                final ECFieldElement V = V1.add(V2);

                if (V.isZero())
                {
                    if (U.isZero())
                    {
                        return twice();
                    }

                    return curve.getInfinity();
                }

                final ECFieldElement VSq = V.square();
                final ECFieldElement VCu = VSq.multiply(V);
                final ECFieldElement W = Z2IsOne ? Z1 : Z1.multiply(Z2);
                final ECFieldElement uv = U.add(V);
                final ECFieldElement A = uv.multiplyPlusProduct(U, VSq, curve.getA()).multiply(W).add(VCu);

                final ECFieldElement X3 = V.multiply(A);
                final ECFieldElement VSqZ2 = Z2IsOne ? VSq : VSq.multiply(Z2);
                final ECFieldElement Y3 = U.multiplyPlusProduct(X1, V, Y1).multiplyPlusProduct(VSqZ2, uv, A);
                final ECFieldElement Z3 = VCu.multiply(W);

                return new ECPoint.F2m(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                if (X1.isZero())
                {
                    if (X2.isZero())
                    {
                        return curve.getInfinity();
                    }

                    return b.add(this);
                }

                final ECFieldElement L1 = y, Z1 = zs[0];
                final ECFieldElement L2 = b.y, Z2 = b.zs[0];

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

                    X3 = L.square().add(L).add(X1).add(curve.getA());
                    if (X3.isZero())
                    {
                        return new ECPoint.F2m(curve, X3, curve.getB().sqrt());
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
                        return new ECPoint.F2m(curve, X3, curve.getB().sqrt());
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

                return new ECPoint.F2m(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
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

            final int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement Y1 = y;

                final ECFieldElement L1 = Y1.divide(X1).add(X1);

                final ECFieldElement X3 = L1.square().add(L1).add(curve.getA());
                final ECFieldElement Y3 = X1.squarePlusProduct(X3, L1.addOne());

                return new ECPoint.F2m(curve, X3, Y3);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Y1 = y, Z1 = zs[0];

                final boolean Z1IsOne = Z1.isOne();
                final ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.multiply(Z1);
                final ECFieldElement Y1Z1 = Z1IsOne ? Y1 : Y1.multiply(Z1);

                final ECFieldElement X1Sq = X1.square();
                final ECFieldElement S = X1Sq.add(Y1Z1);
                final ECFieldElement V = X1Z1;
                final ECFieldElement vSquared = V.square();
                final ECFieldElement sv = S.add(V);
                final ECFieldElement h = sv.multiplyPlusProduct(S, vSquared, curve.getA());

                final ECFieldElement X3 = V.multiply(h);
                final ECFieldElement Y3 = X1Sq.square().multiplyPlusProduct(V, h, sv);
                final ECFieldElement Z3 = V.multiply(vSquared);

                return new ECPoint.F2m(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                final ECFieldElement L1 = y, Z1 = zs[0];

                final boolean Z1IsOne = Z1.isOne();
                final ECFieldElement L1Z1 = Z1IsOne ? L1 : L1.multiply(Z1);
                final ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
                final ECFieldElement a = curve.getA();
                final ECFieldElement aZ1Sq = Z1IsOne ? a : a.multiply(Z1Sq);
                final ECFieldElement T = L1.square().add(L1Z1).add(aZ1Sq);
                if (T.isZero())
                {
                    return new ECPoint.F2m(curve, T, curve.getB().sqrt());
                }

                final ECFieldElement X3 = T.square();
                final ECFieldElement Z3 = Z1IsOne ? T : T.multiply(Z1Sq);

                final ECFieldElement b = curve.getB();
                ECFieldElement L3;
                if (b.bitLength() < curve.getFieldSize() >> 1)
                {
                    final ECFieldElement t1 = L1.add(X1).square();
                    ECFieldElement t2;
                    if (b.isOne())
                    {
                        t2 = aZ1Sq.add(Z1Sq).square();
                    }
                    else
                    {
                        // TODO Can be calculated with one square if we pre-compute sqrt(b)
                        t2 = aZ1Sq.squarePlusProduct(b, Z1Sq.square());
                    }
                    L3 = t1.add(T).add(Z1Sq).multiply(t1).add(t2).add(X3);
                    if (a.isZero())
                    {
                        L3 = L3.add(Z3);
                    }
                    else if (!a.isOne())
                    {
                        L3 = L3.add(a.addOne().multiply(Z3));
                    }
                }
                else
                {
                    final ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.multiply(Z1);
                    L3 = X1Z1.squarePlusProduct(T, L1Z1).add(X3).add(Z3);
                }

                return new ECPoint.F2m(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
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

            final int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // NOTE: twicePlus() only optimized for lambda-affine argument
                final ECFieldElement X2 = b.x, Z2 = b.zs[0];
                if (X2.isZero() || !Z2.isOne())
                {
                    return twice().add(b);
                }

                final ECFieldElement L1 = y, Z1 = zs[0];
                final ECFieldElement L2 = b.y;

                final ECFieldElement X1Sq = X1.square();
                final ECFieldElement L1Sq = L1.square();
                final ECFieldElement Z1Sq = Z1.square();
                final ECFieldElement L1Z1 = L1.multiply(Z1);

                final ECFieldElement T = curve.getA().multiply(Z1Sq).add(L1Sq).add(L1Z1);
                final ECFieldElement L2plus1 = L2.addOne();
                final ECFieldElement A = curve.getA().add(L2plus1).multiply(Z1Sq).add(L1Sq).multiplyPlusProduct(T, X1Sq, Z1Sq);
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
                    return new ECPoint.F2m(curve, A, curve.getB().sqrt());
                }

                final ECFieldElement X3 = A.square().multiply(X2Z1Sq);
                final ECFieldElement Z3 = A.multiply(B).multiply(Z1Sq);
                final ECFieldElement L3 = A.add(B).square().multiplyPlusProduct(T, L2plus1, Z3);

                return new ECPoint.F2m(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }
            default:
            {
                return twice().add(b);
            }
            }
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

            switch (this.getCurveCoordinateSystem())
            {
            case ECCurve.COORD_AFFINE:
            {
                final ECFieldElement Y = y;
                return new ECPoint.F2m(curve, X, Y.add(X));
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                final ECFieldElement Y = y, Z = zs[0];
                return new ECPoint.F2m(curve, X, Y.add(X), new ECFieldElement[]{ Z });
            }
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                final ECFieldElement L = y;
                return new ECPoint.F2m(curve, X, L.addOne());
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // L is actually Lambda (X + Y/X) here
                final ECFieldElement L = y, Z = zs[0];
                return new ECPoint.F2m(curve, X, L.add(Z), new ECFieldElement[]{ Z });
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }
    }
}
