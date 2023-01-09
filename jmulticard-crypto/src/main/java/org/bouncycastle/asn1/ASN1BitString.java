package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Arrays;

/**
 * Base class for BIT STRING objects
 */
public abstract class ASN1BitString
    extends ASN1Primitive
    implements ASN1String, ASN1BitStringParser
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BitString.class, BERTags.BIT_STRING)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }

        @Override
		ASN1Primitive fromImplicitConstructed(final ASN1Sequence sequence)
        {
            return sequence.toASN1BitString();
        }
    };

    public static ASN1BitString getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ASN1BitString)
        {
            return (ASN1BitString)obj;
        }
//      else if (obj instanceof ASN1BitStringParser)
        else if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1BitString)
            {
                return (ASN1BitString)primitive;
            }
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return (ASN1BitString)TYPE.fromByteArray((byte[])obj);
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("failed to construct BIT STRING from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1BitString getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1BitString)TYPE.getContextInstance(taggedObject, explicit);
    }

    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * @param bitString an int containing the BIT STRING
     * @return the correct number of pad bits for a bit string defined in
     * a 32 bit constant
     */
    static protected int getPadBits(
        final int bitString)
    {
        int val = 0;
        for (int i = 3; i >= 0; i--)
        {
            //
            // this may look a little odd, but if it isn't done like this pre jdk1.2
            // JVM's break!
            //
            if (i != 0)
            {
                if (bitString >> i * 8 != 0)
                {
                    val = bitString >> i * 8 & 0xFF;
                    break;
                }
            } else if (bitString != 0)
			{
			    val = bitString & 0xFF;
			    break;
			}
        }

        if (val == 0)
        {
            return 0;
        }


        int bits = 1;

        while (((val <<= 1) & 0xFF) != 0)
        {
            bits++;
        }

        return 8 - bits;
    }

    /**
     * @param bitString an int containing the BIT STRING
     * @return the correct number of bytes for a bit string defined in
     * a 32 bit constant
     */
    static protected byte[] getBytes(final int bitString)
    {
        if (bitString == 0)
        {
            return new byte[0];
        }

        int bytes = 4;
        for (int i = 3; i >= 1; i--)
        {
            if ((bitString & 0xFF << i * 8) != 0)
            {
                break;
            }
            bytes--;
        }

        final byte[] result = new byte[bytes];
        for (int i = 0; i < bytes; i++)
        {
            result[i] = (byte) (bitString >> i * 8 & 0xFF);
        }

        return result;
    }

    final byte[] contents;

    ASN1BitString(final byte data, final int padBits)
    {
        if (padBits > 7 || padBits < 0)
        {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        }

        contents = new byte[]{ (byte)padBits, data };
    }

    /**
     * Base constructor.
     *
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    ASN1BitString(final byte[] data, final int padBits)
    {
        if (data == null)
        {
            throw new NullPointerException("'data' cannot be null");
        }
        if (data.length == 0 && padBits != 0)
        {
            throw new IllegalArgumentException("zero length data with non-zero pad bits");
        }
        if (padBits > 7 || padBits < 0)
        {
            throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
        }

        contents = Arrays.prepend(data, (byte)padBits);
    }

    ASN1BitString(final byte[] contents, final boolean check)
    {
        if (check)
        {
            if (null == contents)
            {
                throw new NullPointerException("'contents' cannot be null");
            }
            if (contents.length < 1)
            {
                throw new IllegalArgumentException("'contents' cannot be empty");
            }

            final int padBits = contents[0] & 0xFF;
            if (padBits > 0)
            {
                if (contents.length < 2)
                {
                    throw new IllegalArgumentException("zero length data with non-zero pad bits");
                }
                if (padBits > 7)
                {
                    throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0");
                }
            }
        }

        this.contents = contents;
    }

    @Override
	public InputStream getBitStream() throws IOException
    {
        return new ByteArrayInputStream(contents, 1, contents.length - 1);
    }

    @Override
	public InputStream getOctetStream() throws IOException
    {
        final int padBits = contents[0] & 0xFF;
        if (0 != padBits)
        {
            throw new IOException("expected octet-aligned bitstring, but found padBits: " + padBits);
        }

        return getBitStream();
    }

    public ASN1BitStringParser parser()
    {
        return this;
    }

    /**
     * Return a String representation of this BIT STRING
     *
     * @return a String representation.
     */
    @Override
	public String getString()
    {
        byte[] string;
        try
        {
            string = getEncoded();
        }
        catch (final IOException e)
        {
            throw new ASN1ParsingException("Internal error encoding BitString: " + e.getMessage(), e);
        }

        final StringBuilder buf = new StringBuilder(1 + string.length * 2);
        buf.append('#');

        for (final byte b : string) {
            buf.append(table[b >>> 4 & 0xf]);
            buf.append(table[b & 0xf]);
        }

        return buf.toString();
    }

    /**
     * @return the value of the bit string as an int (truncating if necessary)
     */
    public int intValue()
    {
        int value = 0;
        final int end = Math.min(5, contents.length - 1);
        for (int i = 1; i < end; ++i)
        {
            value |= (contents[i] & 0xFF) << 8 * (i - 1);
        }
        if (1 <= end && end < 5)
        {
            final int padBits = contents[0] & 0xFF;
            final byte der = (byte)(contents[end] & 0xFF << padBits);
            value |= (der & 0xFF) << 8 * (end - 1);
        }
        return value;
    }

    /**
     * Return the octets contained in this BIT STRING, checking that this BIT STRING really
     * does represent an octet aligned string. Only use this method when the standard you are
     * following dictates that the BIT STRING will be octet aligned.
     *
     * @return a copy of the octet aligned data.
     */
    public byte[] getOctets()
    {
        if (contents[0] != 0)
        {
            throw new IllegalStateException("attempt to get non-octet aligned data from BIT STRING");
        }

        return Arrays.copyOfRange(contents, 1, contents.length);
    }

    public byte[] getBytes()
    {
        if (contents.length == 1)
        {
            return ASN1OctetString.EMPTY_OCTETS;
        }

        final int padBits = contents[0] & 0xFF;
        final byte[] rv = Arrays.copyOfRange(contents, 1, contents.length);
        // DER requires pad bits be zero
        rv[rv.length - 1] &= (byte)(0xFF << padBits);
        return rv;
    }

    @Override
	public int getPadBits()
    {
        return contents[0] & 0xFF;
    }

    @Override
	public String toString()
    {
        return getString();
    }

    @Override
	public int hashCode()
    {
        if (contents.length < 2)
        {
            return 1;
        }

        final int padBits = contents[0] & 0xFF;
        final int last = contents.length - 1;

        final byte lastOctetDER = (byte)(contents[last] & 0xFF << padBits);

        int hc = Arrays.hashCode(contents, 0, last);
        hc *= 257;
        hc ^= lastOctetDER;
        return hc;
    }

    @Override
	boolean asn1Equals(final ASN1Primitive other)
    {
        if (!(other instanceof ASN1BitString))
        {
            return false;
        }

        final ASN1BitString that = (ASN1BitString)other;
        final byte[] thisContents = contents, thatContents = that.contents;

        final int length = thisContents.length;
        if (thatContents.length != length)
        {
            return false;
        }
        if (length == 1)
        {
            return true;
        }

        final int last = length - 1;
        for (int i = 0; i < last; ++i)
        {
            if (thisContents[i] != thatContents[i])
            {
                return false;
            }
        }

        final int padBits = thisContents[0] & 0xFF;
        final byte thisLastOctetDER = (byte)(thisContents[last] & 0xFF << padBits);
        final byte thatLastOctetDER = (byte)(thatContents[last] & 0xFF << padBits);

        return thisLastOctetDER == thatLastOctetDER;
    }

    @Override
	public ASN1Primitive getLoadedObject()
    {
        return this.toASN1Primitive();
    }

    @Override
	ASN1Primitive toDERObject()
    {
        return new DERBitString(contents, false);
    }

    @Override
	ASN1Primitive toDLObject()
    {
        return new DLBitString(contents, false);
    }

    static ASN1BitString createPrimitive(final byte[] contents)
    {
        final int length = contents.length;
        if (length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        final int padBits = contents[0] & 0xFF;
        if (padBits > 0)
        {
            if (padBits > 7 || length < 2)
            {
                throw new IllegalArgumentException("invalid pad bits detected");
            }

            final byte finalOctet = contents[length - 1];
            if (finalOctet != (byte)(finalOctet & 0xFF << padBits))
            {
                return new DLBitString(contents, false);
            }
        }

        return new DERBitString(contents, false);
    }
}
