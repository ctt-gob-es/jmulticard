package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;

public class Attribute
    extends ASN1Object
{
    private final ASN1ObjectIdentifier attrType;
    private final ASN1Set             attrValues;

    /**
     * @return an Attribute object from the given object.
     *
     * @param o the object we want converted.
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
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.attrType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.attrValues = ASN1Set.getInstance(seq.getObjectAt(1));
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
        return new ASN1ObjectIdentifier(this.attrType.getId());
    }

    public ASN1Encodable[] getAttributeValues()
    {
        return this.attrValues.toArray();
    }

    public ASN1Set getAttrValues()
    {
        return this.attrValues;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Attribute ::= SEQUENCE {
     *     attrType OBJECT IDENTIFIER,
     *     attrValues SET OF AttributeValue
     * }
     * </pre>
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
