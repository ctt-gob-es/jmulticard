package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * XMSSMTPublicKey
 * <pre>
 *     XMSSMTPublicKey ::= SEQUENCE {
 *         version       INTEGER -- 0
 *         publicSeed    OCTET STRING
 *         root          OCTET STRING
 *    }
 * </pre>
 */
public class XMSSMTPublicKey
    extends ASN1Object
{
    private final byte[] publicSeed;
    private final byte[] root;

    public XMSSMTPublicKey(final byte[] publicSeed, final byte[] root)
    {
        this.publicSeed = Arrays.clone(publicSeed);
        this.root = Arrays.clone(root);
    }

    private XMSSMTPublicKey(final ASN1Sequence seq)
    {
        if (!ASN1Integer.getInstance(seq.getObjectAt(0)).hasValue(0))
        {
            throw new IllegalArgumentException("unknown version of sequence");
        }

        publicSeed = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(1)).getOctets());
        root = Arrays.clone(DEROctetString.getInstance(seq.getObjectAt(2)).getOctets());
    }

    public static XMSSMTPublicKey getInstance(final Object o)
    {
        if (o instanceof XMSSMTPublicKey)
        {
            return (XMSSMTPublicKey)o;
        }
        else if (o != null)
        {
            return new XMSSMTPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(0)); // version

        v.add(new DEROctetString(publicSeed));
        v.add(new DEROctetString(root));

        return new DERSequence(v);
    }
}
