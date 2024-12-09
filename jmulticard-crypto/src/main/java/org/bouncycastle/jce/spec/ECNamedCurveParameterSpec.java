package org.bouncycastle.jce.spec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * specification signifying that the curve parameters can also be
 * referred to by name.
 * <p>
 * If you are using JDK 1.5 you should be looking at {@link ECNamedCurveSpec}.
 */
public class ECNamedCurveParameterSpec
    extends ECParameterSpec
{
    private final String  name;

    public ECNamedCurveParameterSpec(
        final String      name,
        final ECCurve     curve,
        final ECPoint     G,
        final BigInteger  n)
    {
        super(curve, G, n);

        this.name = name;
    }

    public ECNamedCurveParameterSpec(
        final String      name,
        final ECCurve     curve,
        final ECPoint     G,
        final BigInteger  n,
        final BigInteger  h)
    {
        super(curve, G, n, h);

        this.name = name;
    }

    public ECNamedCurveParameterSpec(
        final String      name,
        final ECCurve     curve,
        final ECPoint     G,
        final BigInteger  n,
        final BigInteger  h,
        final byte[]      seed)
    {
        super(curve, G, n, h, seed);

        this.name = name;
    }

    /**
     * @return the name of the curve the EC domain parameters belong to.
     */
    public String getName()
    {
        return this.name;
    }
}
