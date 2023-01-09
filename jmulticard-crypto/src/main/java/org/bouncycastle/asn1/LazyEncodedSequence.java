package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * Note: this class is for processing DER/DL encoded sequences only.
 */
class LazyEncodedSequence
    extends ASN1Sequence
{
    private byte[] encoded;

    LazyEncodedSequence(final byte[] encoded) throws IOException
    {
        // NOTE: Initially, the actual 'elements' will be empty
        if (null == encoded)
        {
            throw new NullPointerException("'encoded' cannot be null");
        }

        this.encoded = encoded;
    }

    @Override
	public ASN1Encodable getObjectAt(final int index)
    {
        force();

        return super.getObjectAt(index);
    }

    @Override
	public Enumeration getObjects()
    {
        final byte[] encoded = getContents();
        if (null != encoded)
        {
            return new LazyConstructionEnumeration(encoded);
        }

        return super.getObjects();
    }

    @Override
	public int hashCode()
    {
        force();

        return super.hashCode();
    }

    @Override
	public Iterator<ASN1Encodable> iterator()
    {
        force();

        return super.iterator();
    }

    @Override
	public int size()
    {
        force();

        return super.size();
    }

    @Override
	public ASN1Encodable[] toArray()
    {
        force();

        return super.toArray();
    }

    @Override
	ASN1Encodable[] toArrayInternal()
    {
        force();

        return super.toArrayInternal();
    }

    @Override
	int encodedLength(final boolean withTag)
        throws IOException
    {
        final byte[] encoded = getContents();
        if (null != encoded)
        {
            return ASN1OutputStream.getLengthOfEncodingDL(withTag, encoded.length);
        }

        return super.toDLObject().encodedLength(withTag);
    }

    @Override
	void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        final byte[] encoded = getContents();
        if (null != encoded)
        {
            out.writeEncodingDL(withTag, BERTags.CONSTRUCTED | BERTags.SEQUENCE, encoded);
            return;
        }

        super.toDLObject().encode(out, withTag);
    }

    @Override
	ASN1BitString toASN1BitString()
    {
        return ((ASN1Sequence)toDLObject()).toASN1BitString();
    }

    @Override
	ASN1External toASN1External()
    {
        return ((ASN1Sequence)toDLObject()).toASN1External();
    }

    @Override
	ASN1OctetString toASN1OctetString()
    {
        return ((ASN1Sequence)toDLObject()).toASN1OctetString();
    }

    @Override
	ASN1Set toASN1Set()
    {
        return ((ASN1Sequence)toDLObject()).toASN1Set();
    }

    @Override
	ASN1Primitive toDERObject()
    {
        force();

        return super.toDERObject();
    }

    @Override
	ASN1Primitive toDLObject()
    {
        force();

        return super.toDLObject();
    }

    private synchronized void force()
    {
        if (null != encoded)
        {
            final ASN1InputStream aIn = new ASN1InputStream(encoded, true);
            try
            {
                final ASN1EncodableVector v = aIn.readVector();
                aIn.close();

                elements = v.takeElements();
                encoded = null;
            }
            catch (final IOException e)
            {
                throw new ASN1ParsingException("malformed ASN.1: " + e, e);
            }
        }
    }

    private synchronized byte[] getContents()
    {
        return encoded;
    }
}
