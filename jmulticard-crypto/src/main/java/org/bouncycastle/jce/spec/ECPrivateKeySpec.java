package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/**
 * Elliptic Curve private key specification.
 */
public class ECPrivateKeySpec
    extends ECKeySpec
{
    private final BigInteger    d;

    /**
     * base constructor
     *
     * @param d the private number for the key.
     * @param spec the domain parameters for the curve being used.
     */
    public ECPrivateKeySpec(
        final BigInteger      d,
        final ECParameterSpec spec)
    {
        super(spec);

        this.d = d;
    }

    /**
     * @return the private number D
     */
    public BigInteger getD()
    {
        return this.d;
    }
}
