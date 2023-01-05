package org.bouncycastle.math.ec;

public abstract class AbstractECLookupTable
    implements ECLookupTable
{
    @Override
	public ECPoint lookupVar(int index)
    {
        return lookup(index);
    }
}
