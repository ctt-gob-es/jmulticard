package org.bouncycastle.crypto.constraints;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;

public class DefaultServiceProperties
    implements CryptoServiceProperties
{
    private final String algorithm;
    private final int bitsOfSecurity;
    private final Object params;
    private final CryptoServicePurpose purpose;

    public DefaultServiceProperties(final String algorithm, final int bitsOfSecurity)
    {
        this(algorithm, bitsOfSecurity, null, CryptoServicePurpose.ANY);
    }

    public DefaultServiceProperties(final String algorithm, final int bitsOfSecurity, final Object params)
    {
        this(algorithm, bitsOfSecurity, params, CryptoServicePurpose.ANY);
    }

    public DefaultServiceProperties(final String algorithm, final int bitsOfSecurity, final Object params, final CryptoServicePurpose purpose)
    {
        this.algorithm = algorithm;
        this.bitsOfSecurity = bitsOfSecurity;
        this.params = params;
        if (params instanceof CryptoServicePurpose)
        {
            throw new IllegalArgumentException("params should not be CryptoServicePurpose");
        }
        this.purpose = purpose;
    }

    @Override
	public int bitsOfSecurity()
    {
        return bitsOfSecurity;
    }

    @Override
	public String getServiceName()
    {
        return algorithm;
    }

    @Override
	public CryptoServicePurpose getPurpose()
    {
        return purpose;
    }

    @Override
	public Object getParams()
    {
        return params;
    }
}
