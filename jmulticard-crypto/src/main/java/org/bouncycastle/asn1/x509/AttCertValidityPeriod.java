package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class AttCertValidityPeriod
    extends ASN1Object
{
    ASN1GeneralizedTime  notBeforeTime;
    ASN1GeneralizedTime  notAfterTime;

    public static AttCertValidityPeriod getInstance(
            final Object  obj)
    {
        if (obj instanceof AttCertValidityPeriod)
        {
            return (AttCertValidityPeriod)obj;
        }
        else if (obj != null)
        {
            return new AttCertValidityPeriod(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private AttCertValidityPeriod(
        final ASN1Sequence    seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        this.notBeforeTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(0));
        this.notAfterTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
    }

    public AttCertValidityPeriod(
        final ASN1GeneralizedTime notBeforeTime,
        final ASN1GeneralizedTime notAfterTime)
    {
        this.notBeforeTime = notBeforeTime;
        this.notAfterTime = notAfterTime;
    }

    public ASN1GeneralizedTime getNotBeforeTime()
    {
        return this.notBeforeTime;
    }

    public ASN1GeneralizedTime getNotAfterTime()
    {
        return this.notAfterTime;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  AttCertValidityPeriod  ::= SEQUENCE {
     *       notBeforeTime  GeneralizedTime,
     *       notAfterTime   GeneralizedTime
     *  }
     * </pre>
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(this.notBeforeTime);
        v.add(this.notAfterTime);

        return new DERSequence(v);
    }
}
