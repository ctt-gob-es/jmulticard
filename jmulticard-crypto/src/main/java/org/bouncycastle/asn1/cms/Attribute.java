package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#page-14">RFC 5652</a>:
 * Attribute is a pair of OID (as type identifier) + set of values.
 * <pre>
 * Attribute ::= SEQUENCE {
 *     attrType OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue
 * }
 *
 * AttributeValue ::= ANY
 * </pre>
 * <p>
 * General rule on values is that same AttributeValue must not be included
 * multiple times into the set. That is, if the value is a SET OF INTEGERs,
 * then having same value repeated is wrong: (1, 1), but different values is OK: (1, 2).
 * Normally the AttributeValue syntaxes are more complicated than that.
 * <p>
 * General rule of Attribute usage is that the {@link Attributes} containers
 * must not have multiple Attribute:s with same attrType (OID) there.
 */
public class Attribute
    extends ASN1Object
{
    private final ASN1ObjectIdentifier attrType;
    private final ASN1Set             attrValues;

    /**
     * Return an Attribute object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link Attribute} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with Attribute structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @return Attribute.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Attribute getInstance(
        final Object o)
    {
        if (o instanceof Attribute)
        {
            return (Attribute)o;
        }

        if (o != null)
        {
            return new Attribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private Attribute(
        final ASN1Sequence seq)
    {
        this.attrType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        this.attrValues = (ASN1Set)seq.getObjectAt(1);
    }

    public Attribute(
        final ASN1ObjectIdentifier attrType,
        final ASN1Set             attrValues)
    {
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public ASN1ObjectIdentifier getAttrType()
    {
        return this.attrType;
    }

    public ASN1Set getAttrValues()
    {
        return this.attrValues;
    }

    public ASN1Encodable[] getAttributeValues()
    {
        return this.attrValues.toArray();
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(this.attrType);
        v.add(this.attrValues);

        return new DERSequence(v);
    }
}
