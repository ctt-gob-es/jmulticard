package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A Definite length BIT STRING
 */
public class DLBitString
    extends ASN1BitString
{
    public DLBitString(final byte[] data)
    {
        this(data, 0);
    }

    public DLBitString(final byte data, final int padBits)
    {
        super(data, padBits);
    }

    public DLBitString(final byte[] data, final int padBits)
    {
        super(data, padBits);
    }

    public DLBitString(final int value)
    {
        // TODO[asn1] Unify in single allocation of 'contents'
        super(getBytes(value), getPadBits(value));
    }

    public DLBitString(final ASN1Encodable obj) throws IOException
    {
        // TODO[asn1] Unify in single allocation of 'contents'
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    DLBitString(final byte[] contents, final boolean check)
    {
        super(contents, check);
    }

    @Override
	boolean encodeConstructed()
    {
        return false;
    }

    @Override
	int encodedLength(final boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents);
    }

    @Override
	ASN1Primitive toDLObject()
    {
        return this;
    }

    static int encodedLength(final boolean withTag, final int contentsLength)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }

    static void encode(final ASN1OutputStream out, final boolean withTag, final byte[] buf, final int off, final int len) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, buf, off, len);
    }

    static void encode(final ASN1OutputStream out, final boolean withTag, final byte pad, final byte[] buf, final int off, final int len)
        throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, pad, buf, off, len);
    }
}
