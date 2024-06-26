package org.bouncycastle.math.ec;

import java.math.BigInteger;

/** Class implementing the WTNAF (Window
 * <code>&tau;</code>-adic Non-Adjacent Form) algorithm. */
public class WTauNafMultiplier extends AbstractECMultiplier {

    // TODO Create WTauNafUtil class and move various functionality into it
    static final String PRECOMP_NAME = "bc_wtnaf";

    /** Multiplies a {@link org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m}
     * by <code>k</code> using the reduced <code>&tau;</code>-adic NAF (RTNAF)
     * method.
     * @param point The ECPoint.AbstractF2m to multiply.
     * @param k The integer by which to multiply <code>k</code>.
     * @return <code>p</code> multiplied by <code>k</code>. */
    @Override
	protected ECPoint multiplyPositive(final ECPoint point, final BigInteger k) {
        if (!(point instanceof ECPoint.AbstractF2m)) {
            throw new IllegalArgumentException("Only ECPoint.AbstractF2m can be " +
                    "used in WTauNafMultiplier");
        }

        final ECPoint.AbstractF2m p = (ECPoint.AbstractF2m)point;
        final ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m)p.getCurve();
        final int m = curve.getFieldSize();
        final byte a = curve.getA().toBigInteger().byteValue();
        final byte mu = Tnaf.getMu(a);
        final BigInteger[] s = curve.getSi();

        final ZTauElement rho = Tnaf.partModReduction(k, m, a, s, mu, (byte)10);

        return multiplyWTnaf(p, rho, a, mu);
    }

    /** Multiplies a {@link org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m}
     * by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code> using
     * the <code>&tau;</code>-adic NAF (TNAF) method.
     * @param p The ECPoint.AbstractF2m to multiply.
     * @param lambda The element <code>&lambda;</code> of
     * <code><b>Z</b>[&tau;]</code> of which to compute the
     * <code>[&tau;]</code>-adic NAF.
     * @return <code>p</code> multiplied by <code>&lambda;</code>. */
    private ECPoint.AbstractF2m multiplyWTnaf(final ECPoint.AbstractF2m p, final ZTauElement lambda, final byte a, final byte mu) {

        final ZTauElement[] alpha = a == 0 ? Tnaf.alpha0 : Tnaf.alpha1;

        final BigInteger tw = Tnaf.getTw(mu, Tnaf.WIDTH);

        final byte[]u = Tnaf.tauAdicWNaf(mu, lambda, Tnaf.WIDTH,
            BigInteger.valueOf(Tnaf.POW_2_WIDTH), tw, alpha);

        return multiplyFromWTnaf(p, u);
    }

    /** Multiplies a {@link org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m}
     * by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>
     * using the window <code>&tau;</code>-adic NAF (TNAF) method, given the
     * WTNAF of <code>&lambda;</code>.
     * @param p The ECPoint.AbstractF2m to multiply.
     * @param u The the WTNAF of <code>&lambda;</code>.
     * @return <code>&lambda; * p</code>.  */
    private static ECPoint.AbstractF2m multiplyFromWTnaf(final ECPoint.AbstractF2m p, final byte[] u) {
        final ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m)p.getCurve();
        final byte a = curve.getA().toBigInteger().byteValue();

        final WTauNafPreCompInfo preCompInfo = (WTauNafPreCompInfo)curve.precompute(p, PRECOMP_NAME, existing -> {
		    if (existing instanceof WTauNafPreCompInfo) {
		        return existing;
		    }

		    final WTauNafPreCompInfo result = new WTauNafPreCompInfo();
		    result.setPreComp(Tnaf.getPreComp(p, a));
		    return result;
		});

        final ECPoint.AbstractF2m[] pu = preCompInfo.getPreComp();

        // TODO Include negations in precomp (optionally) and use from here
        final ECPoint.AbstractF2m[] puNeg = new ECPoint.AbstractF2m[pu.length];
        for (int i = 0; i < pu.length; ++i) {
            puNeg[i] = (ECPoint.AbstractF2m)pu[i].negate();
        }

        // q = infinity
        ECPoint.AbstractF2m q = (ECPoint.AbstractF2m) p.getCurve().getInfinity();

        int tauCount = 0;
        for (int i = u.length - 1; i >= 0; i--) {
            ++tauCount;
            final int ui = u[i];
            if (ui != 0) {
                q = q.tauPow(tauCount);
                tauCount = 0;

                final ECPoint x = ui > 0 ? pu[ui >>> 1] : puNeg[-ui >>> 1];
                q = (ECPoint.AbstractF2m)q.add(x);
            }
        }
        if (tauCount > 0) {
            q = q.tauPow(tauCount);
        }
        return q;
    }
}
