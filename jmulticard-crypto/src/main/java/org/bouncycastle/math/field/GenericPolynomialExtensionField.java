package org.bouncycastle.math.field;

import java.math.BigInteger;

import org.bouncycastle.util.Integers;

class GenericPolynomialExtensionField implements PolynomialExtensionField
{
    protected final FiniteField subfield;
    protected final Polynomial minimalPolynomial;

    GenericPolynomialExtensionField(FiniteField subfield, Polynomial polynomial)
    {
        this.subfield = subfield;
        this.minimalPolynomial = polynomial;
    }

    @Override
	public BigInteger getCharacteristic()
    {
        return subfield.getCharacteristic();
    }

    @Override
	public int getDimension()
    {
        return subfield.getDimension() * minimalPolynomial.getDegree();
    }

    @Override
	public FiniteField getSubfield()
    {
        return subfield;
    }

    @Override
	public int getDegree()
    {
        return minimalPolynomial.getDegree();
    }

    @Override
	public Polynomial getMinimalPolynomial()
    {
        return minimalPolynomial;
    }

    @Override
	public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof GenericPolynomialExtensionField))
        {
            return false;
        }
        GenericPolynomialExtensionField other = (GenericPolynomialExtensionField)obj;
        return subfield.equals(other.subfield) && minimalPolynomial.equals(other.minimalPolynomial);
    }

    @Override
	public int hashCode()
    {
        return subfield.hashCode()
            ^ Integers.rotateLeft(minimalPolynomial.hashCode(), 16);
    }
}
