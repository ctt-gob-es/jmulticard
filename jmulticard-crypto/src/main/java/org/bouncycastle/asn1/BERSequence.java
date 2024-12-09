package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Indefinite length SEQUENCE of objects.
 * <p>
 * Length field has value 0x80, and the sequence ends with two bytes of: 0x00, 0x00.
 * </p><p>
 * For X.690 syntax rules, see {@link ASN1Sequence}.
 * </p>
 */
public class BERSequence
    extends ASN1Sequence
{
    /**
     * Create an empty sequence
     */
    public BERSequence()
    {
    }

    /**
     * Create a sequence containing one object
     * @param element Encodable element.
     */
    public BERSequence(final ASN1Encodable element)
    {
        super(element);
    }

    /**
     * Create a sequence containing a vector of objects.
     * @param elementVector Encodable vector.
     */
    public BERSequence(final ASN1EncodableVector elementVector)
    {
        super(elementVector);
    }

    /**
     * Create a sequence containing an array of objects.
     * @param elements Encodable elements.
     */
    public BERSequence(final ASN1Encodable[] elements)
    {
        super(elements);
    }

    @Override
	int encodedLength(final boolean withTag) throws IOException
    {
        int totalLength = withTag ? 4 : 3;

        for (final ASN1Encodable element : this.elements) {
            final ASN1Primitive p = element.toASN1Primitive();
            totalLength += p.encodedLength(true);
        }

        return totalLength;
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeEncodingIL(withTag, BERTags.CONSTRUCTED | BERTags.SEQUENCE, this.elements);
    }

    @Override
	ASN1BitString toASN1BitString()
    {
        return new BERBitString(getConstructedBitStrings());
    }

    @Override
	ASN1External toASN1External()
    {
        // TODO There is currently no BERExternal class
        return ((ASN1Sequence)toDLObject()).toASN1External();
    }

    @Override
	ASN1OctetString toASN1OctetString()
    {
        return new BEROctetString(getConstructedOctetStrings());
    }

    @Override
	ASN1Set toASN1Set()
    {
        return new BERSet(false, toArrayInternal());
    }
}
