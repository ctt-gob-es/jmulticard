package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DERTaggedObject
    extends ASN1TaggedObject
{
    public DERTaggedObject(final int tagNo, final ASN1Encodable encodable)
    {
        super(true, tagNo, encodable);
    }

    public DERTaggedObject(final int tagClass, final int tagNo, final ASN1Encodable obj)
    {
        super(true, tagClass, tagNo, obj);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DERTaggedObject(final boolean explicit, final int tagNo, final ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public DERTaggedObject(final boolean explicit, final int tagClass, final int tagNo, final ASN1Encodable obj)
    {
        super(explicit, tagClass, tagNo, obj);
    }

    DERTaggedObject(final int explicitness, final int tagClass, final int tagNo, final ASN1Encodable obj)
    {
        super(explicitness, tagClass, tagNo, obj);
    }

    @Override
	boolean encodeConstructed()
    {
        return isExplicit() || obj.toASN1Primitive().toDERObject().encodeConstructed();
    }

    @Override
	int encodedLength(final boolean withTag) throws IOException
    {
        final ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();
        final boolean explicit = isExplicit();

        int length = primitive.encodedLength(explicit);

        if (explicit)
        {
            length += ASN1OutputStream.getLengthOfDL(length);
        }

        length += withTag ? ASN1OutputStream.getLengthOfIdentifier(tagNo) : 0;

        return length;
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
//      assert out.getClass().isAssignableFrom(DEROutputStream.class);

        final ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();
        final boolean explicit = isExplicit();

        if (withTag)
        {
            int flags = tagClass;
            if (explicit || primitive.encodeConstructed())
            {
                flags |= BERTags.CONSTRUCTED;
            }

            out.writeIdentifier(true, flags, tagNo);
        }

        if (explicit)
        {
            out.writeDL(primitive.encodedLength(true));
        }

        primitive.encode(out.getDERSubStream(), explicit);
    }

    @Override
	String getASN1Encoding()
    {
        return ASN1Encoding.DER;
    }

    @Override
	ASN1Sequence rebuildConstructed(final ASN1Primitive primitive)
    {
        return new DERSequence(primitive);
    }

    @Override
	ASN1TaggedObject replaceTag(final int tagClass, final int tagNo)
    {
        return new DERTaggedObject(explicitness, tagClass, tagNo, obj);
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
