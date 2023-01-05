package org.bouncycastle.math.field;

import java.math.BigInteger;

class PrimeField implements FiniteField
{
    protected final BigInteger characteristic;

    PrimeField(BigInteger characteristic)
    {
        this.characteristic = characteristic;
    }

    @Override
	public BigInteger getCharacteristic()
    {
        return characteristic;
    }

    @Override
	public int getDimension()
    {
        return 1;
    }

    @Override
	public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof PrimeField))
        {
            return false;
        }
        PrimeField other = (PrimeField)obj;
        return characteristic.equals(other.characteristic);
    }

    @Override
	public int hashCode()
    {
        return characteristic.hashCode();
    }
}
