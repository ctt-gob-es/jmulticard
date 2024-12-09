package org.bouncycastle.jce;

import java.io.IOException;
import java.security.Principal;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * a general extension of X509Name with a couple of extra methods and
 * constructors.
 * <p>
 * Objects of this type can be created from certificates and CRLs using the
 * PrincipalUtil class.
 * </p>
 * @deprecated use the X500Name class.
 */
@Deprecated
public class X509Principal
    extends X509Name
    implements Principal
{
    private static ASN1Sequence readSequence(
        final ASN1InputStream aIn)
        throws IOException
    {
        try
        {
            return ASN1Sequence.getInstance(aIn.readObject());
        }
        catch (final IllegalArgumentException e)
        {
            throw new IOException("not an ASN.1 Sequence: " + e);
        }
    }

    /**
     * Constructor from an encoded byte array.
     * @param bytes Envoded principal.
     * @throws IOException If encoding error occurs.
     */
    public X509Principal(
        final byte[]  bytes)
        throws IOException
    {
        super(readSequence(new ASN1InputStream(bytes)));
    }

    /**
     * Constructor from an X509Name object.
     * @param name X509Name
     */
    public X509Principal(
        final X509Name  name)
    {
        super((ASN1Sequence)name.toASN1Primitive());
    }

     /**
     * Constructor from an X509Name object.
     * @param name X500Name
     */
    public X509Principal(
        final X500Name name)
    {
        super((ASN1Sequence)name.toASN1Primitive());
    }

    /**
     * constructor from a table of attributes.
     * it's is assumed the table contains OID/String pairs.
     * @param attributes Principal attriutes.
     */
    public X509Principal(
        final Hashtable  attributes)
    {
        super(attributes);
    }

    /**
     * constructor from a table of attributes and a vector giving the
     * specific ordering required for encoding or conversion to a string.
     * it's is assumed the table contains OID/String pairs.
     * @param ordering Vector with the ordered elements.
     * @param attributes Principal attriutes.
     */
    public X509Principal(
        final Vector      ordering,
        final Hashtable   attributes)
    {
        super(ordering, attributes);
    }

    /**
     * constructor from a vector of attribute values and a vector of OIDs.
     * @param oids Attribute's identifiers.
     * @param values Attribute's values.
     */
    public X509Principal(
        final Vector      oids,
        final Vector      values)
    {
        super(oids, values);
    }

    /**
     * takes an X509 dir name as a string of the format "C=AU,ST=Victoria", or
     * some such, converting it into an ordered set of name attributes.
     * @param dirName Directory name.
     */
    public X509Principal(
        final String  dirName)
    {
        super(dirName);
    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU,ST=Victoria", or
     * some such, converting it into an ordered set of name attributes.
     * @param reverse If reverse is false the dir name will be encoded in the
     * order of the (name, value) pairs presented, otherwise the encoding will
     * start with the last (name, value) pair and work back.
     * @param dirName Directory name.
     */
    public X509Principal(
        final boolean reverse,
        final String  dirName)
    {
        super(reverse, dirName);
    }

    /**
     * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
     * some such, converting it into an ordered set of name attributes.
     * @param reverse If reverse is true, create the encoded version of the sequence starting
     * from the last element in the string.
     * @param lookUp should provide a table of lookups, indexed by lowercase only strings and
     * yielding a ASN1ObjectIdentifier, other than that OID. and numeric oids
     * will be processed automatically.
     * @param dirName Directory name.
     */
    public X509Principal(
        final boolean     reverse,
        final Hashtable   lookUp,
        final String      dirName)
    {
        super(reverse, lookUp, dirName);
    }

    @Override
	public String getName()
    {
        return this.toString();
    }

    /**
     * return a DER encoded byte array representing this object
     */
    @Override
	public byte[] getEncoded()
    {
        try
        {
            return this.getEncoded(ASN1Encoding.DER);
        }
        catch (final IOException e)
        {
            throw new RuntimeException(e.toString());
        }
    }
}
