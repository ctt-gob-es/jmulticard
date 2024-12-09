package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSet;

/**
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652</a> defines
 * 5 "SET OF Attribute" entities with 5 different names.
 * This is common implementation for them all:
 * <pre>
 *   SignedAttributes      ::= SET SIZE (1..MAX) OF Attribute
 *   UnsignedAttributes    ::= SET SIZE (1..MAX) OF Attribute
 *   UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *   AuthAttributes        ::= SET SIZE (1..MAX) OF Attribute
 *   UnauthAttributes      ::= SET SIZE (1..MAX) OF Attribute
 *
 * Attributes ::=
 *   SET SIZE(1..MAX) OF Attribute
 * </pre>
 */
public class Attributes
    extends ASN1Object
{
    private final ASN1Set attributes;

    private Attributes(final ASN1Set set)
    {
        this.attributes = set;
    }

    public Attributes(final ASN1EncodableVector v)
    {
        this.attributes = new DLSet(v);
    }

    /**
     * Return an Attribute set object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link Attributes} object
     * <li> {@link org.bouncycastle.asn1.ASN1Set#getInstance(java.lang.Object) ASN1Set} input formats with Attributes structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @return Attribute.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Attributes getInstance(final Object obj)
    {
        if (obj instanceof Attributes)
        {
            return (Attributes)obj;
        }
        else if (obj != null)
        {
            return new Attributes(ASN1Set.getInstance(obj));
        }

        return null;
    }

    public static Attributes getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        return getInstance(ASN1Set.getInstance(obj, explicit));
    }

    public Attribute[] getAttributes()
    {
        final Attribute[] rv = new Attribute[this.attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Attribute.getInstance(this.attributes.getObjectAt(i));
        }

        return rv;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        return this.attributes;
    }
}
