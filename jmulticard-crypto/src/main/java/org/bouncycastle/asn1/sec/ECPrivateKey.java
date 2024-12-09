package org.bouncycastle.asn1.sec;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.BigIntegers;

/**
 * the elliptic curve private key object from SEC 1
 */
public class ECPrivateKey
    extends ASN1Object
{
    private final ASN1Sequence seq;

    private ECPrivateKey(
        final ASN1Sequence seq)
    {
        this.seq = seq;
    }

    public static ECPrivateKey getInstance(
        final Object obj)
    {
        if (obj instanceof ECPrivateKey)
        {
            return (ECPrivateKey)obj;
        }

        if (obj != null)
        {
            return new ECPrivateKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * @param key the private key value.
     * @deprecated use constructor which takes orderBitLength to guarantee correct encoding.
     */
    @Deprecated
	public ECPrivateKey(
        final BigInteger key)
    {
        this(key.bitLength(), key);
    }

    /**
     * Base constructor.
     *
     * @param orderBitLength the bitLength of the order of the curve.
     * @param key the private key value.
     */
    public ECPrivateKey(
        final int        orderBitLength,
        final BigInteger key)
    {
        final byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));

        this.seq = new DERSequence(v);
    }

    /**
     * @param key the private key value.
     * @param parameters Parameters.
     * @deprecated use constructor which takes orderBitLength to guarantee correct encoding.
     */
    @Deprecated
	public ECPrivateKey(
        final BigInteger key,
        final ASN1Encodable parameters)
    {
        this(key, null, parameters);
    }

    /**
     * @param key the private key value.
     * @param publicKey Public key.
     * @param parameters Parameters.
     * @deprecated use constructor which takes orderBitLength to guarantee correct encoding.
     */
    @Deprecated
	public ECPrivateKey(
        final BigInteger key,
        final ASN1BitString publicKey,
        final ASN1Encodable parameters)
    {
        this(key.bitLength(), key, publicKey, parameters);
    }

    public ECPrivateKey(
        final int orderBitLength,
        final BigInteger key,
        final ASN1Encodable parameters)
    {
        this(orderBitLength, key, null, parameters);
    }

    public ECPrivateKey(
        final int orderBitLength,
        final BigInteger key,
        final ASN1BitString publicKey,
        final ASN1Encodable parameters)
    {
        final byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

        final ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));

        if (parameters != null)
        {
            v.add(new DERTaggedObject(true, 0, parameters));
        }

        if (publicKey != null)
        {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }

        this.seq = new DERSequence(v);
    }

    public BigInteger getKey()
    {
        final ASN1OctetString octs = (ASN1OctetString)this.seq.getObjectAt(1);

        return new BigInteger(1, octs.getOctets());
    }

    public ASN1BitString getPublicKey()
    {
        return (ASN1BitString)getObjectInTag(1, BERTags.BIT_STRING);
    }

    /**
     * @return Parameters.
     * @deprecated Use {@link #getParametersObject()} instead and getInstance
     *             methods or similar to get the object at the desired type.
     */
    @Deprecated
	public ASN1Primitive getParameters()
    {
        return getParametersObject().toASN1Primitive();
    }

    public ASN1Object getParametersObject()
    {
        return getObjectInTag(0, -1);
    }

    private ASN1Object getObjectInTag(final int tagNo, final int baseTagNo)
    {
        final Enumeration e = this.seq.getObjects();

        while (e.hasMoreElements())
        {
            final ASN1Encodable obj = (ASN1Encodable)e.nextElement();

            if (obj instanceof ASN1TaggedObject)
            {
                final ASN1TaggedObject tag = (ASN1TaggedObject)obj;
                if (tag.hasContextTag(tagNo))
                {
                    return baseTagNo < 0
                        ?   tag.getExplicitBaseObject().toASN1Primitive()
                        :   tag.getBaseUniversal(true, baseTagNo);
                }
            }
        }
        return null;
    }

    /**
     * ECPrivateKey ::= SEQUENCE {
     *     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *     privateKey OCTET STRING,
     *     parameters [0] Parameters OPTIONAL,
     *     publicKey [1] BIT STRING OPTIONAL }
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        return this.seq;
    }
}
