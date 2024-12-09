package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * XMSS key-pair generation parameters.
 */
public final class XMSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final XMSSParameters xmssParameters;

    /**
     * XMSSMT constructor...
     *
     * @param xmssParameters XMSS parameters.
     * @param prng   Secure random to use.
     */
    public XMSSKeyGenerationParameters(final XMSSParameters xmssParameters, final SecureRandom prng)
    {
        super(prng,-1);

        this.xmssParameters = xmssParameters;
    }

    public XMSSParameters getParameters()
    {
        return this.xmssParameters;
    }
}
