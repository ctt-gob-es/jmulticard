package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
 * this has been withdrawn.
 */
public abstract class ASN1T61String
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1T61String.class, BERTags.T61_STRING)
    {
        @Override
		ASN1Primitive fromImplicitPrimitive(final DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a T61 string from the passed in object.
     *
     * @param obj an ASN1T61String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1T61String instance, or null
     */
    public static ASN1T61String getInstance(final Object obj)
    {
        if (obj == null || obj instanceof ASN1T61String)
        {
            return (ASN1T61String)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            final ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1T61String)
            {
                return (ASN1T61String)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1T61String)TYPE.fromByteArray((byte[])obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an T61 String from a tagged object.
     *
     * @param taggedObject      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1T61String instance, or null
     */
    public static ASN1T61String getInstance(final ASN1TaggedObject taggedObject, final boolean explicit)
    {
        return (ASN1T61String)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1T61String(final String string)
    {
        contents = Strings.toByteArray(string);
    }

    ASN1T61String(final byte[] contents, final boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    /**
     * Decode the encoded string and return it, 8 bit encoding assumed.
     * @return the decoded String
     */
    @Override
	public final String getString()
    {
        return Strings.fromByteArray(contents);
    }

    @Override
	public String toString()
    {
        return getString();
    }

    @Override
	final boolean encodeConstructed()
    {
        return false;
    }

    @Override
	final int encodedLength(final boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    @Override
	final void encode(final ASN1OutputStream out, final boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.T61_STRING, contents);
    }

    /**
     * Return the encoded string as a byte array.
     * @return the actual bytes making up the encoded body of the T61 string.
     */
    public final byte[] getOctets()
    {
        return Arrays.clone(contents);
    }

    @Override
	final boolean asn1Equals(final ASN1Primitive other)
    {
        if (!(other instanceof ASN1T61String))
        {
            return false;
        }

        final ASN1T61String that = (ASN1T61String)other;

        return Arrays.areEqual(contents, that.contents);
    }

    @Override
	public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    static ASN1T61String createPrimitive(final byte[] contents)
    {
        return new DERT61String(contents, false);
    }
}
