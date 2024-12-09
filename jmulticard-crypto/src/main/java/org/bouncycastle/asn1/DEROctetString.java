package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Carrier class for a DER encoding OCTET STRING
 */
public class DEROctetString
    extends ASN1OctetString
{
    /**
     * Base constructor.
     *
     * @param string the octets making up the octet string.
     */
    public DEROctetString(
        final byte[]  string)
    {
        super(string);
    }

    /**
     * Constructor from the encoding of an ASN.1 object.
     *
     * @param obj the object to be encoded.
     * @throws IOException If IO error occurs.
     */
    public DEROctetString(
        final ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    @Override
	boolean encodeConstructed()
    {
        return false;
    }

    @Override
	int encodedLength(final boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.string.length);
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.OCTET_STRING, this.string);
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

    static void encode(final ASN1OutputStream out, final boolean withTag, final byte[] buf, final int off, final int len) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.OCTET_STRING, buf, off, len);
    }

    static int encodedLength(final boolean withTag, final int contentsLength)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }
}
