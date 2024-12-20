package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * An indefinite-length encoding version of an ASN.1 ApplicationSpecific object.
 *
 * @deprecated Will be removed. See comments for
 *             {@link ASN1ApplicationSpecific}.
 */
@Deprecated
public class BERApplicationSpecific
    extends ASN1ApplicationSpecific
{
    /**
     * Create an application specific object with an explicit tag
     *
     * @param tagNo the tag number for this object.
     * @param baseEncodable the object to be contained.
     * @throws IOException If IO error occurs.
     */
    public BERApplicationSpecific(final int tagNo, final ASN1Encodable baseEncodable) throws IOException
    {
        this(true, tagNo, baseEncodable);
    }

    /**
     * Create an application specific object with the tagging style given by the value of explicit.
     *
     * @param explicit true if the object is explicitly tagged.
     * @param tagNo the tag number for this object.
     * @param baseEncodable the object to be contained.
     * @throws IOException If IO error occurs.
     */
    public BERApplicationSpecific(final boolean explicit, final int tagNo, final ASN1Encodable baseEncodable) throws IOException
    {
        super(new BERTaggedObject(explicit, BERTags.APPLICATION, tagNo, baseEncodable));
    }

    /**
     * Create an application specific object which is marked as constructed
     *
     * @param tagNo the tag number for this object.
     * @param contentsElements the objects making up the application specific object.
     */
    public BERApplicationSpecific(final int tagNo, final ASN1EncodableVector contentsElements)
    {
        super(new BERTaggedObject(false, BERTags.APPLICATION, tagNo, BERFactory.createSequence(contentsElements)));
    }

    BERApplicationSpecific(final ASN1TaggedObject taggedObject)
    {
        super(taggedObject);
    }
}
