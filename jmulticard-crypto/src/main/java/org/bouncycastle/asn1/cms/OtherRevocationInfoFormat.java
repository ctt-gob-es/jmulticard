package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.1">RFC 5652</a>: OtherRevocationInfoFormat object.
 * <pre>
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *      otherRevInfoFormat OBJECT IDENTIFIER,
 *      otherRevInfo ANY DEFINED BY otherRevInfoFormat }
 * </pre>
 */
public class OtherRevocationInfoFormat
    extends ASN1Object
{
    private final ASN1ObjectIdentifier otherRevInfoFormat;
    private final ASN1Encodable otherRevInfo;

    public OtherRevocationInfoFormat(
        final ASN1ObjectIdentifier otherRevInfoFormat,
        final ASN1Encodable otherRevInfo)
    {
        this.otherRevInfoFormat = otherRevInfoFormat;
        this.otherRevInfo = otherRevInfo;
    }

    private OtherRevocationInfoFormat(
        final ASN1Sequence seq)
    {
        this.otherRevInfoFormat = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.otherRevInfo = seq.getObjectAt(1);
    }

    /**
     * Return a OtherRevocationInfoFormat object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @return OtherRevocationInfoFormat.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OtherRevocationInfoFormat getInstance(
        final ASN1TaggedObject    obj,
        final boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Return a OtherRevocationInfoFormat object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OtherRevocationInfoFormat} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with OtherRevocationInfoFormat structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @return OtherRevocationInfoFormat.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OtherRevocationInfoFormat getInstance(
        final Object obj)
    {
        if (obj instanceof OtherRevocationInfoFormat)
        {
            return (OtherRevocationInfoFormat)obj;
        }

        if (obj != null)
        {
            return new OtherRevocationInfoFormat(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getInfoFormat()
    {
        return this.otherRevInfoFormat;
    }

    public ASN1Encodable getInfo()
    {
        return this.otherRevInfo;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(this.otherRevInfoFormat);
        v.add(this.otherRevInfo);

        return new DERSequence(v);
    }
}
