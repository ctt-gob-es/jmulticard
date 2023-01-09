package org.bouncycastle.asn1;

import java.io.IOException;

public final class ASN1ObjectDescriptor
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectDescriptor.class, BERTags.OBJECT_DESCRIPTOR)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return new ASN1ObjectDescriptor(
                (ASN1GraphicString)ASN1GraphicString.TYPE.fromImplicitPrimitive(octetString));
        }

        @Override
		ASN1Primitive fromImplicitConstructed(final ASN1Sequence sequence)
        {
            return new ASN1ObjectDescriptor(
                (ASN1GraphicString)ASN1GraphicString.TYPE.fromImplicitConstructed(sequence));
        }
    };

    /**
     * Return an ObjectDescriptor from the passed in object.
     *
     * @param obj an ASN1ObjectDescriptor or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1ObjectDescriptor instance, or null.
     */
    public static ASN1ObjectDescriptor getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ASN1ObjectDescriptor)
        {
            return (ASN1ObjectDescriptor)obj;
        }
        else if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1ObjectDescriptor)
            {
                return (ASN1ObjectDescriptor)primitive;
            }
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return (ASN1ObjectDescriptor)TYPE.fromByteArray((byte[])obj);
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("failed to construct object descriptor from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an ObjectDescriptor from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want.
     * @param explicit     true if the object is meant to be explicitly tagged,
     *                     false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1ObjectDescriptor instance, or null.
     */
    public static ASN1ObjectDescriptor getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1ObjectDescriptor)TYPE.getContextInstance(taggedObject, explicit);
    }

    private final ASN1GraphicString baseGraphicString;

    public ASN1ObjectDescriptor(final ASN1GraphicString baseGraphicString)
    {
        if (null == baseGraphicString)
        {
            throw new NullPointerException("'baseGraphicString' cannot be null");
        }

        this.baseGraphicString = baseGraphicString;
    }

    public ASN1GraphicString getBaseGraphicString()
    {
        return baseGraphicString;
    }

    @Override
	boolean encodeConstructed()
    {
        return false;
    }

    @Override
	int encodedLength(final boolean withTag)
    {
        return baseGraphicString.encodedLength(withTag);
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeIdentifier(withTag, BERTags.OBJECT_DESCRIPTOR);
        baseGraphicString.encode(out, false);
    }

    @Override
	ASN1Primitive toDERObject()
    {
        final ASN1GraphicString der = (ASN1GraphicString)baseGraphicString.toDERObject();

        return der == baseGraphicString ? this : new ASN1ObjectDescriptor(der);
    }

    @Override
	ASN1Primitive toDLObject()
    {
        final ASN1GraphicString dl = (ASN1GraphicString)baseGraphicString.toDLObject();

        return dl == baseGraphicString ? this : new ASN1ObjectDescriptor(dl);
    }

    @Override
	boolean asn1Equals(final ASN1Primitive other)
    {
        if (!(other instanceof ASN1ObjectDescriptor))
        {
            return false;
        }

        final ASN1ObjectDescriptor that = (ASN1ObjectDescriptor)other;

        return baseGraphicString.asn1Equals(that.baseGraphicString);
    }

    @Override
	public int hashCode()
    {
        return ~baseGraphicString.hashCode();
    }

    static ASN1ObjectDescriptor createPrimitive(final byte[] contents)
    {
        return new ASN1ObjectDescriptor(ASN1GraphicString.createPrimitive(contents));
    }
}
