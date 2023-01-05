package org.bouncycastle.asn1;

abstract class ASN1Type
{
    final Class javaClass;

    ASN1Type(Class javaClass)
    {
        this.javaClass = javaClass;
    }

    final Class getJavaClass()
    {
        return javaClass;
    }

    @Override
	public final boolean equals(Object that)
    {
        return this == that;
    }

    @Override
	public final int hashCode()
    {
        return super.hashCode();
    }
}
