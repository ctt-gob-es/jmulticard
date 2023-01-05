package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 GENERAL-STRING data type.
 * <p>
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 * </p>
 */
public abstract class ASN1GeneralString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1GeneralString.class, BERTags.GENERAL_STRING)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a GeneralString from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1GeneralString instance, or null.
     */
    public static ASN1GeneralString getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ASN1GeneralString)
        {
            return (ASN1GeneralString) obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1GeneralString)
            {
                return (ASN1GeneralString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1GeneralString)TYPE.fromByteArray((byte[])obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    /**
     * Return a GeneralString from a tagged object.
     *
     * @param taggedObject      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1GeneralString instance.
     */
    public static ASN1GeneralString getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1GeneralString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1GeneralString(final String string)
    {
        contents = Strings.toByteArray(string);
    }

    ASN1GeneralString(final byte[] contents, final boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    /**
     * Return a Java String representation of our contained String.
     *
     * @return a Java String representing our contents.
     */
    @Override
	public final String getString()
    {
        return Strings.fromByteArray(contents);
    }

    @Override
	public String toString()
    {
        return getString();
    }

    /**
     * Return a byte array representation of our contained String.
     *
     * @return a byte array representing our contents.
     */
    public final byte[] getOctets()
    {
        return Arrays.clone(contents);
    }

    @Override
	final boolean encodeConstructed()
    {
        return false;
    }

    @Override
	final int encodedLength(final boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    @Override
	final void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.GENERAL_STRING, contents);
    }

    @Override
	final boolean asn1Equals(final ASN1Primitive other)
    {
        if (!(other instanceof ASN1GeneralString))
        {
            return false;
        }

        final ASN1GeneralString that = (ASN1GeneralString)other;

        return Arrays.areEqual(contents, that.contents);
    }

    @Override
	public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    static ASN1GeneralString createPrimitive(final byte[] contents)
    {
        return new DERGeneralString(contents, false);
    }
}
