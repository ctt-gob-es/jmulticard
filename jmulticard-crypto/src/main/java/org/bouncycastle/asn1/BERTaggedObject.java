package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * BER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class BERTaggedObject
    extends ASN1TaggedObject
{
    /**
     * create an implicitly tagged object that contains a zero
     * length sequence.
     * @param tagNo Tag number.
     * @deprecated Will be removed.
     */
    @Deprecated
	public BERTaggedObject(final int tagNo)
    {
        super(false, tagNo, new BERSequence());
    }

    /**
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(final int tagNo, final ASN1Encodable obj)
    {
        super(true, tagNo, obj);
    }

    public BERTaggedObject(final int tagClass, final int tagNo, final ASN1Encodable obj)
    {
        super(true, tagClass, tagNo, obj);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(final boolean explicit, final int tagNo, final ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public BERTaggedObject(final boolean explicit, final int tagClass, final int tagNo, final ASN1Encodable obj)
    {
        super(explicit, tagClass, tagNo, obj);
    }

    BERTaggedObject(final int explicitness, final int tagClass, final int tagNo, final ASN1Encodable obj)
    {
        super(explicitness, tagClass, tagNo, obj);
    }

    @Override
	boolean encodeConstructed()
    {
        return isExplicit() || this.obj.toASN1Primitive().encodeConstructed();
    }

    @Override
	int encodedLength(final boolean withTag) throws IOException
    {
        final ASN1Primitive primitive = this.obj.toASN1Primitive();
        final boolean explicit = isExplicit();

        int length = primitive.encodedLength(explicit);

        if (explicit)
        {
            length += 3;
        }

        length += withTag ? ASN1OutputStream.getLengthOfIdentifier(this.tagNo) : 0;

        return length;
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
//        assert out.getClass().isAssignableFrom(ASN1OutputStream.class);

        final ASN1Primitive primitive = this.obj.toASN1Primitive();
        final boolean explicit = isExplicit();

        if (withTag)
        {
            int flags = this.tagClass;
            if (explicit || primitive.encodeConstructed())
            {
                flags |= BERTags.CONSTRUCTED;
            }

            out.writeIdentifier(true, flags, this.tagNo);
        }

        if (explicit)
        {
            out.write(0x80);
            primitive.encode(out, true);
            out.write(0x00);
            out.write(0x00);
        }
        else
        {
            primitive.encode(out, false);
        }
    }

    @Override
	String getASN1Encoding()
    {
        return ASN1Encoding.BER;
    }

    @Override
	ASN1Sequence rebuildConstructed(final ASN1Primitive primitive)
    {
        return new BERSequence(primitive);
    }

    @Override
	ASN1TaggedObject replaceTag(final int tagClass, final int tagNo)
    {
        return new BERTaggedObject(this.explicitness, tagClass, tagNo, this.obj);
    }
}
