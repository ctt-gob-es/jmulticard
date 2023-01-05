package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

public class PKCS7ProcessableObject
    implements CMSTypedData
{
    private final ASN1ObjectIdentifier type;
    private final ASN1Encodable structure;

    public PKCS7ProcessableObject(
        final ASN1ObjectIdentifier type,
        final ASN1Encodable structure)
    {
        this.type = type;
        this.structure = structure;
    }

    @Override
	public ASN1ObjectIdentifier getContentType()
    {
        return type;
    }

    @Override
	public void write(final OutputStream cOut)
        throws IOException, CMSException
    {
        if (structure instanceof ASN1Sequence)
        {
            final ASN1Sequence s = ASN1Sequence.getInstance(structure);

            for (final Object element : s) {
                final ASN1Encodable enc = (ASN1Encodable)element;

                cOut.write(enc.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }
        else
        {
            final byte[] encoded = structure.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            int index = 1;

            while ((encoded[index] & 0xff) > 127)
            {
                index++;
            }

            index++;

            cOut.write(encoded, index, encoded.length - index);
        }
    }

    @Override
	public Object getContent()
    {
        return structure;
    }
}
