package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Strings;

public class GeneralNames
    extends ASN1Object
{
    private final GeneralName[] names;

    private static GeneralName[] copy(final GeneralName[] names)
    {
        final GeneralName[] result = new GeneralName[names.length];
        System.arraycopy(names, 0, result, 0, names.length);
        return result;
    }

    public static GeneralNames getInstance(
        final Object  obj)
    {
        if (obj instanceof GeneralNames)
        {
            return (GeneralNames)obj;
        }

        if (obj != null)
        {
            return new GeneralNames(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static GeneralNames getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        return new GeneralNames(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GeneralNames fromExtensions(final Extensions extensions, final ASN1ObjectIdentifier extOID)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, extOID));
    }

    /**
     * Construct a GeneralNames object containing one GeneralName.
     *
     * @param name the name to be contained.
     */
    public GeneralNames(
        final GeneralName  name)
    {
        names = new GeneralName[] { name };
    }


    public GeneralNames(
        final GeneralName[]  names)
    {
        this.names = copy(names);
    }

    private GeneralNames(
        final ASN1Sequence  seq)
    {
        names = new GeneralName[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            names[i] = GeneralName.getInstance(seq.getObjectAt(i));
        }
    }

    public GeneralName[] getNames()
    {
        return copy(names);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * GeneralNames ::= SEQUENCE SIZE {1..MAX} OF GeneralName
     * </pre>
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(names);
    }

    @Override
	public String toString()
    {
        final StringBuilder  buf = new StringBuilder();
        final String        sep = Strings.lineSeparator();

        buf.append("GeneralNames:");
        buf.append(sep);

        for (final GeneralName name : names) {
            buf.append("    ");
            buf.append(name);
            buf.append(sep);
        }
        return buf.toString();
    }
}
