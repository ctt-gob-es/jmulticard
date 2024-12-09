package org.bouncycastle.jce.spec;

import java.security.spec.KeySpec;

/**
 * base class for an Elliptic Curve Key Spec
 */
public class ECKeySpec
    implements KeySpec
{
    private final ECParameterSpec     spec;

    protected ECKeySpec(
        final ECParameterSpec spec)
    {
        this.spec = spec;
    }

    /**
     * @return the domain parameters for the curve
     */
    public ECParameterSpec getParams()
    {
        return this.spec;
    }
}
