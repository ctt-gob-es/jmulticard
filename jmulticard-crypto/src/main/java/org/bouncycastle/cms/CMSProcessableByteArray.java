package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * a holding class for a byte array of data to be processed.
 */
public class CMSProcessableByteArray
    implements CMSTypedData, CMSReadable
{
    private final ASN1ObjectIdentifier type;
    private final byte[]  bytes;

    public CMSProcessableByteArray(
        byte[]  bytes)
    {
        this(CMSObjectIdentifiers.data, bytes);
    }

    public CMSProcessableByteArray(
        ASN1ObjectIdentifier type,
        byte[]  bytes)
    {
        this.type = type;
        this.bytes = bytes;
    }

    @Override
	public InputStream getInputStream()
    {
        return new ByteArrayInputStream(bytes);
    }

    @Override
	public void write(OutputStream zOut)
        throws IOException, CMSException
    {
        zOut.write(bytes);
    }

    @Override
	public Object getContent()
    {
        return Arrays.clone(bytes);
    }

    @Override
	public ASN1ObjectIdentifier getContentType()
    {
        return type;
    }
}
