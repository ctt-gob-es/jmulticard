package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * ASN.1 BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 * <p>
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 * </p>
 */
public abstract class ASN1BMPString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BMPString.class, BERTags.BMP_STRING)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a BMP String from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1BMPString instance, or null.
     */
    public static ASN1BMPString getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ASN1BMPString)
        {
            return (ASN1BMPString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1BMPString)
            {
                return (ASN1BMPString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1BMPString)TYPE.fromByteArray((byte[])obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a BMP String from a tagged object.
     *
     * @param taggedObject      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1BMPString instance.
     */
    public static ASN1BMPString getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1BMPString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final char[] string;

    ASN1BMPString(final String string)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }

        this.string = string.toCharArray();
    }

    ASN1BMPString(final byte[] string)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }

        final int byteLen = string.length;
        if (0 != (byteLen & 1))
        {
            throw new IllegalArgumentException("malformed BMPString encoding encountered");
        }

        final int charLen = byteLen / 2;
        final char[] cs = new char[charLen];

        for (int i = 0; i != charLen; i++)
        {
            cs[i] = (char)(string[2 * i] << 8 | string[2 * i + 1] & 0xff);
        }

        this.string = cs;
    }

    ASN1BMPString(final char[] string)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }

        this.string = string;
    }

    @Override
	public final String getString()
    {
        return new String(this.string);
    }

    @Override
	public String toString()
    {
        return getString();
    }

    @Override
	final boolean asn1Equals(final ASN1Primitive other)
    {
        if (!(other instanceof ASN1BMPString))
        {
            return false;
        }

        final ASN1BMPString that = (ASN1BMPString)other;

        return Arrays.areEqual(this.string, that.string);
    }

    @Override
	public final int hashCode()
    {
        return Arrays.hashCode(this.string);
    }

    @Override
	final boolean encodeConstructed()
    {
        return false;
    }

    @Override
	final int encodedLength(final boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, this.string.length * 2);
    }

    @Override
	final void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        final int count = this.string.length;

        out.writeIdentifier(withTag, BERTags.BMP_STRING);
        out.writeDL(count * 2);

        final byte[] buf = new byte[8];

        int i = 0;
		final int limit = count & -4;
        while (i < limit)
        {
            final char c0 = this.string[i], c1 = this.string[i + 1], c2 = this.string[i + 2], c3 = this.string[i + 3];
            i += 4;

            buf[0] = (byte)(c0 >> 8);
            buf[1] = (byte)c0;
            buf[2] = (byte)(c1 >> 8);
            buf[3] = (byte)c1;
            buf[4] = (byte)(c2 >> 8);
            buf[5] = (byte)c2;
            buf[6] = (byte)(c3 >> 8);
            buf[7] = (byte)c3;

            out.write(buf, 0, 8);
        }
        if (i < count)
        {
            int bufPos = 0;
            do
            {
                final char c0 = this.string[i];
                i += 1;

                buf[bufPos++] = (byte)(c0 >> 8);
                buf[bufPos++] = (byte)c0;
            }
            while (i < count);

            out.write(buf, 0, bufPos);
        }
    }

    static ASN1BMPString createPrimitive(final byte[] contents)
    {
        return new DERBMPString(contents);
    }

    static ASN1BMPString createPrimitive(final char[] string)
    {
        // TODO ASN1InputStream has a validator/converter that should be unified in this class somehow
        return new DERBMPString(string);
    }
}
