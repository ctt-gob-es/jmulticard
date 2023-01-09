package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 * The object that contains the public key stored in a certificate.
 * <p>
 * The getEncoded() method in the public keys in the JCE produces a DER
 * encoded one of these.
 */
public class SubjectPublicKeyInfo
    extends ASN1Object
{
    private final AlgorithmIdentifier     algId;
    private final ASN1BitString           keyData;

    public static SubjectPublicKeyInfo getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SubjectPublicKeyInfo getInstance(
        final Object  obj)
    {
        if (obj instanceof SubjectPublicKeyInfo)
        {
            return (SubjectPublicKeyInfo)obj;
        }
        else if (obj != null)
        {
            return new SubjectPublicKeyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public SubjectPublicKeyInfo(
        final AlgorithmIdentifier algId,
        final ASN1Encodable       publicKey)
        throws IOException
    {
        keyData = new DERBitString(publicKey);
        this.algId = algId;
    }

    public SubjectPublicKeyInfo(
        final AlgorithmIdentifier algId,
        final byte[]              publicKey)
    {
        keyData = new DERBitString(publicKey);
        this.algId = algId;
    }

    /**
     @deprecated use SubjectPublicKeyInfo.getInstance()
     */
    @Deprecated
	public SubjectPublicKeyInfo(
        final ASN1Sequence  seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        final Enumeration         e = seq.getObjects();

        algId = AlgorithmIdentifier.getInstance(e.nextElement());
        keyData = DERBitString.getInstance(e.nextElement());
    }

    public AlgorithmIdentifier getAlgorithm()
    {
        return algId;
    }

    /**
     * @deprecated use getAlgorithm()
     * @return    alg ID.
     */
    @Deprecated
	public AlgorithmIdentifier getAlgorithmId()
    {
        return algId;
    }

    /**
     * for when the public key is an encoded object - if the bitstring
     * can't be decoded this routine throws an IOException.
     *
     * @exception IOException - if the bit string doesn't represent a DER
     * encoded object.
     * @return the public key as an ASN.1 primitive.
     */
    public ASN1Primitive parsePublicKey()
        throws IOException
    {
        return ASN1Primitive.fromByteArray(keyData.getOctets());
    }

    /**
     * for when the public key is an encoded object - if the bitstring
     * can't be decoded this routine throws an IOException.
     *
     * @exception IOException - if the bit string doesn't represent a DER
     * encoded object.
     * @deprecated use parsePublicKey
     * @return the public key as an ASN.1 primitive.
     */
    @Deprecated
	public ASN1Primitive getPublicKey()
        throws IOException
    {
        return ASN1Primitive.fromByteArray(keyData.getOctets());
    }

    /**
     * for when the public key is raw bits.
     *
     * @return the public key as the raw bit string...
     */
    public ASN1BitString getPublicKeyData()
    {
        return keyData;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *                          algorithm AlgorithmIdentifier,
     *                          publicKey BIT STRING }
     * </pre>
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algId);
        v.add(keyData);

        return new DERSequence(v);
    }
}
