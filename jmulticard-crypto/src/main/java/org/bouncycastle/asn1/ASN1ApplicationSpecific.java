package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Base class for an ASN.1 ApplicationSpecific object
 *
 * @deprecated Will be removed. Change application code to handle as {@link ASN1TaggedObject} only, testing
 *             for the expected {@link ASN1TaggedObject#getTagClass() tag class} of
 *             {@link BERTags#APPLICATION} in relevant objects before using. If using a
 *             {@link ASN1StreamParser stream parser}, handle application-tagged objects using
 *             {@link ASN1TaggedObjectParser} in the usual way, again testing for a
 *             {@link ASN1TaggedObjectParser#getTagClass() tag class} of {@link BERTags#APPLICATION}.
 */
@Deprecated
public abstract class ASN1ApplicationSpecific
    extends ASN1TaggedObject
    implements ASN1ApplicationSpecificParser
{
    /**
     * Return an ASN1ApplicationSpecific from the passed in object, which may be a byte array, or null.
     *
     * @param obj the object to be converted.
     * @return obj's representation as an ASN1ApplicationSpecific object.
     */
    public static ASN1ApplicationSpecific getInstance(final Object obj) {
        if (obj == null || obj instanceof ASN1ApplicationSpecific) {
            return (ASN1ApplicationSpecific)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("Failed to construct object from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    final ASN1TaggedObject taggedObject;

    ASN1ApplicationSpecific(final ASN1TaggedObject taggedObject)
    {
        super(taggedObject.explicitness, checkTagClass(taggedObject.tagClass), taggedObject.tagNo, taggedObject.obj);

        this.taggedObject = taggedObject;
    }

    /**
     * Return the tag number associated with this object,
     *
     * @return the application tag number.
     */
    public int getApplicationTag()
    {
        return this.taggedObject.getTagNo();
    }

    /**
     * Return the contents of this object as a byte[]
     *
     * @return the encoded contents of the object.
     */
    @Override
	public byte[] getContents()
    {
        return this.taggedObject.getContents();
    }

    /**
     * Return the enclosed object assuming explicit tagging.
     *
     * @return  the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getEnclosedObject() throws IOException
    {
        return this.taggedObject.getBaseObject().toASN1Primitive();
    }

    /**
     * Return the enclosed object assuming implicit tagging.
     *
     * @param tagNo the type tag that should be applied to the object's contents.
     * @return the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getObject(final int tagNo) throws IOException
    {
        return this.taggedObject.getBaseUniversal(false, tagNo);
    }

    @Override
	public ASN1Encodable getObjectParser(final int tag, final boolean isExplicit) throws IOException
    {
        throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
    }

    @Override
	public ASN1Encodable parseBaseUniversal(final boolean declaredExplicit, final int baseTagNo) throws IOException
    {
        return this.taggedObject.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    @Override
	public ASN1Encodable parseExplicitBaseObject() throws IOException
    {
        return this.taggedObject.parseExplicitBaseObject();
    }

    @Override
	public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException
    {
        return this.taggedObject.parseExplicitBaseTagged();
    }

    @Override
	public ASN1TaggedObjectParser parseImplicitBaseTagged(final int baseTagClass, final int baseTagNo) throws IOException
    {
        return this.taggedObject.parseImplicitBaseTagged(baseTagClass, baseTagNo);
    }

    public boolean hasApplicationTag(final int tagNo)
    {
        return this.tagNo == tagNo;
    }

    @Override
	public boolean hasContextTag(final int tagNo)
    {
        return false;
    }

    /**
     * ASN1ApplicationSpecific uses an internal ASN1TaggedObject for the
     * implementation, and will soon be deprecated in favour of using
     * ASN1TaggedObject with a tag class of {@link BERTags#APPLICATION}. This method
     * lets you get the internal ASN1TaggedObject so that client code can begin the
     * migration.
     * @return Object to migration.
     */
    public ASN1TaggedObject getTaggedObject()
    {
        return this.taggedObject;
    }

    /**
     * Return true if the object is marked as constructed, false otherwise.
     *
     * @return true if constructed, otherwise false.
     */
    @Override
	public boolean isConstructed()
    {
        return this.taggedObject.isConstructed();
    }

    @Override
	public ASN1Encodable readObject() throws IOException
    {
        // NOTE: No way to say you're looking for an implicitly-tagged object via ASN1ApplicationSpecificParser
        return parseExplicitBaseObject();
    }

    @Override
	boolean encodeConstructed()
    {
        return this.taggedObject.encodeConstructed();
    }

    @Override
	int encodedLength(final boolean withTag) throws IOException
    {
        return this.taggedObject.encodedLength(withTag);
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        this.taggedObject.encode(out, withTag);
    }

    @Override
	String getASN1Encoding()
    {
        return this.taggedObject.getASN1Encoding();
    }

    @Override
	ASN1Sequence rebuildConstructed(final ASN1Primitive primitive)
    {
        return this.taggedObject.rebuildConstructed(primitive);
    }

    @Override
	ASN1TaggedObject replaceTag(final int tagClass, final int tagNo)
    {
        return this.taggedObject.replaceTag(tagClass, tagNo);
    }

    @Override
	ASN1Primitive toDERObject()
    {
        return new DERApplicationSpecific((ASN1TaggedObject)this.taggedObject.toDERObject());
    }

    @Override
	ASN1Primitive toDLObject()
    {
        return new DLApplicationSpecific((ASN1TaggedObject)this.taggedObject.toDLObject());
    }

    private static int checkTagClass(final int tagClass)
    {
        if (BERTags.APPLICATION != tagClass)
        {
            throw new IllegalArgumentException();
        }
        return tagClass;
    }
}
