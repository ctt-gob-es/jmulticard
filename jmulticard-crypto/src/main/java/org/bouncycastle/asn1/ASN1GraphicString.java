package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1GraphicString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1GraphicString.class, BERTags.GRAPHIC_STRING)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a GraphicString from the passed in object.
     *
     * @param obj an ASN1GraphicString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1GraphicString instance, or null.
     */
    public static ASN1GraphicString getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ASN1GraphicString)
        {
            return (ASN1GraphicString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1GraphicString)
            {
                return (ASN1GraphicString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1GraphicString)TYPE.fromByteArray((byte[])obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a GraphicString from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want.
     * @param explicit     true if the object is meant to be explicitly tagged,
     *                     false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1GraphicString instance, or null.
     */
    public static ASN1GraphicString getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1GraphicString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1GraphicString(final byte[] contents, final boolean clone)
    {
        if (null == contents)
        {
            throw new NullPointerException("'contents' cannot be null");
        }

        this.contents = clone ? Arrays.clone(contents) : contents;
    }

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
        out.writeEncodingDL(withTag, BERTags.GRAPHIC_STRING, contents);
    }

    @Override
	final boolean asn1Equals(final ASN1Primitive other)
    {
        if (!(other instanceof ASN1GraphicString))
        {
            return false;
        }

        final ASN1GraphicString that = (ASN1GraphicString)other;

        return Arrays.areEqual(contents, that.contents);
    }

    @Override
	public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    @Override
	public final String getString()
    {
        return Strings.fromByteArray(contents);
    }

    static ASN1GraphicString createPrimitive(final byte[] contents)
    {
        return new DERGraphicString(contents, false);
    }
}
