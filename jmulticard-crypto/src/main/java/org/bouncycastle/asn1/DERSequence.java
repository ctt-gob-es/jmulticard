package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Definite length SEQUENCE, encoding tells explicit number of bytes
 * that the content of this sequence occupies.
 * <p>
 * For X.690 syntax rules, see {@link ASN1Sequence}.
 */
public class DERSequence
    extends ASN1Sequence
{
    public static DERSequence convert(final ASN1Sequence seq)
    {
        return (DERSequence)seq.toDERObject();
    }

    private int contentsLength = -1;

    /**
     * Create an empty sequence
     */
    public DERSequence()
    {
    }

    /**
     * Create a sequence containing one object
     * @param element the object to go in the sequence.
     */
    public DERSequence(final ASN1Encodable element)
    {
        super(element);
    }

    /**
     * Create a sequence containing a vector of objects.
     * @param elementVector the vector of objects to make up the sequence.
     */
    public DERSequence(final ASN1EncodableVector elementVector)
    {
        super(elementVector);
    }

    /**
     * Create a sequence containing an array of objects.
     * @param elements the array of objects to make up the sequence.
     */
    public DERSequence(final ASN1Encodable[] elements)
    {
        super(elements);
    }

    DERSequence(final ASN1Encodable[] elements, final boolean clone)
    {
        super(elements, clone);
    }

    private int getContentsLength() throws IOException
    {
        if (contentsLength < 0)
        {
            final int count = elements.length;
            int totalLength = 0;

            for (int i = 0; i < count; ++i)
            {
                final ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                totalLength += derObject.encodedLength(true);
            }

            contentsLength = totalLength;
        }

        return contentsLength;
    }

    @Override
	int encodedLength(final boolean withTag) throws IOException
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getContentsLength());
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeIdentifier(withTag, BERTags.CONSTRUCTED | BERTags.SEQUENCE);

        final DEROutputStream derOut = out.getDERSubStream();

        final int count = elements.length;
        if (contentsLength >= 0 || count > 16)
        {
            out.writeDL(getContentsLength());

            for (int i = 0; i < count; ++i)
            {
                final ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                derObject.encode(derOut, true);
            }
        }
        else
        {
            int totalLength = 0;

            final ASN1Primitive[] derObjects = new ASN1Primitive[count];
            for (int i = 0; i < count; ++i)
            {
                final ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                derObjects[i] = derObject;
                totalLength += derObject.encodedLength(true);
            }

            contentsLength = totalLength;
            out.writeDL(totalLength);

            for (int i = 0; i < count; ++i)
            {
                derObjects[i].encode(derOut, true);
            }
        }
    }

    @Override
	ASN1BitString toASN1BitString()
    {
        return new DERBitString(BERBitString.flattenBitStrings(getConstructedBitStrings()), false);
    }

    @Override
	ASN1External toASN1External()
    {
        return new DERExternal(this);
    }

    @Override
	ASN1OctetString toASN1OctetString()
    {
        return new DEROctetString(BEROctetString.flattenOctetStrings(getConstructedOctetStrings()));
    }

    @Override
	ASN1Set toASN1Set()
    {
        // NOTE: DLSet is intentional, we don't want sorting
        return new DLSet(false, toArrayInternal());
    }

    @Override
	ASN1Primitive toDERObject()
    {
        return this;
    }

    @Override
	ASN1Primitive toDLObject()
    {
        return this;
    }
}
