package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * XMMSMTKeyParams
 * <pre>
 *     XMMSMTKeyParams ::= SEQUENCE {
 *         version INTEGER -- 0
 *         height INTEGER
 *         layers INTEGER
 *         treeDigest AlgorithmIdentifier
 * }
 * </pre>
 */
public class XMSSMTKeyParams
    extends ASN1Object
{
    private final ASN1Integer version;
    private final int height;
    private final int layers;
    private final AlgorithmIdentifier treeDigest;

    public XMSSMTKeyParams(final int height, final int layers, final AlgorithmIdentifier treeDigest)
    {
        version = new ASN1Integer(0);
        this.height = height;
        this.layers = layers;
        this.treeDigest = treeDigest;
    }

    private XMSSMTKeyParams(final ASN1Sequence sequence)
    {
        version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        height = ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact();
        layers = ASN1Integer.getInstance(sequence.getObjectAt(2)).intValueExact();
        treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(3));
    }

    public static XMSSMTKeyParams getInstance(final Object o)
    {
        if (o instanceof XMSSMTKeyParams)
        {
            return (XMSSMTKeyParams)o;
        }
        else if (o != null)
        {
            return new XMSSMTKeyParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getHeight()
    {
        return height;
    }

    public int getLayers()
    {
        return layers;
    }

    public AlgorithmIdentifier getTreeDigest()
    {
        return treeDigest;
    }

    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(new ASN1Integer(height));
        v.add(new ASN1Integer(layers));
        v.add(treeDigest);

        return new DERSequence(v);
    }
}
