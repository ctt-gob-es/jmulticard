package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
public abstract class ASN1Null
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Null.class, BERTags.NULL)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return an instance of ASN.1 NULL from the passed in object.
     * <p>
     * Accepted inputs:
     * </p>
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1Null} object
     * <li> a byte[] containing ASN.1 NULL object
     * </ul>
     *
     * @param o object to be converted.
     * @return an instance of ASN1Null, or null.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Null getInstance(final Object o)
    {
        if (o instanceof ASN1Null)
        {
            return (ASN1Null)o;
        }

        if (o != null)
        {
            try
            {
                return (ASN1Null)TYPE.fromByteArray((byte[])o);
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.getMessage());
            }
        }

        return null;
    }

    public static ASN1Null getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1Null)TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1Null()
    {
    }

    @Override
	public int hashCode()
    {
        return -1;
    }

    @Override
	boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1Null))
        {
            return false;
        }

        return true;
    }

    @Override
	public String toString()
    {
         return "NULL";
    }

    static ASN1Null createPrimitive(final byte[] contents)
    {
        if (0 != contents.length)
        {
            throw new IllegalStateException("malformed NULL encoding encountered");
        }
        return DERNull.INSTANCE;
    }
}
