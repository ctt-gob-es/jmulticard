package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Strings;

/**
 * The DistributionPointName object.
 * <pre>
 * DistributionPointName ::= CHOICE {
 *     fullName                 [0] GeneralNames,
 *     nameRelativeToCRLIssuer  [1] RDN
 * }
 * </pre>
 */
public class DistributionPointName
    extends ASN1Object
    implements ASN1Choice
{
    ASN1Encodable        name;
    int                 type;

    public static final int FULL_NAME = 0;
    public static final int NAME_RELATIVE_TO_CRL_ISSUER = 1;

    public static DistributionPointName getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        return getInstance(ASN1TaggedObject.getInstance(obj, true));
    }

    public static DistributionPointName getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DistributionPointName)
        {
            return (DistributionPointName)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new DistributionPointName((ASN1TaggedObject)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DistributionPointName(
        final int             type,
        final ASN1Encodable   name)
    {
        this.type = type;
        this.name = name;
    }

    public DistributionPointName(
        final GeneralNames name)
    {
        this(FULL_NAME, name);
    }

    /**
     * Return the tag number applying to the underlying choice.
     *
     * @return the tag number for this point name.
     */
    public int getType()
    {
        return type;
    }

    /**
     * Return the tagged object inside the distribution point name.
     *
     * @return the underlying choice item.
     */
    public ASN1Encodable getName()
    {
        return name;
    }

    public DistributionPointName(
        final ASN1TaggedObject    obj)
    {
        type = obj.getTagNo();

        if (type == 0)
        {
            name = GeneralNames.getInstance(obj, false);
        }
        else
        {
            name = ASN1Set.getInstance(obj, false);
        }
    }

    @Override
	public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, type, name);
    }

    @Override
	public String toString()
    {
        final String       sep = Strings.lineSeparator();
        final StringBuffer buf = new StringBuffer();
        buf.append("DistributionPointName: [");
        buf.append(sep);
        if (type == FULL_NAME)
        {
            appendObject(buf, sep, "fullName", name.toString());
        }
        else
        {
            appendObject(buf, sep, "nameRelativeToCRLIssuer", name.toString());
        }
        buf.append("]");
        buf.append(sep);
        return buf.toString();
    }

    private void appendObject(final StringBuffer buf, final String sep, final String name, final String value)
    {
        final String       indent = "    ";

        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }
}
