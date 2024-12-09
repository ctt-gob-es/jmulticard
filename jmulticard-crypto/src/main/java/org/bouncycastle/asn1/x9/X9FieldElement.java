package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.ec.ECFieldElement;

/**
 * class for processing an FieldElement as a DER object.
 */
public class X9FieldElement
    extends ASN1Object
{
    protected ECFieldElement  f;

    private static X9IntegerConverter converter = new X9IntegerConverter();

    public X9FieldElement(final ECFieldElement f)
    {
        this.f = f;
    }

    public ECFieldElement getValue()
    {
        return this.f;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  FieldElement ::= OCTET STRING
     * </pre>
     * <ol>
     * <li> if <i>q</i> is an odd prime then the field element is
     * processed as an Integer and converted to an octet string
     * according to x 9.62 4.3.1.</li>
     * <li> if <i>q</i> is 2<sup>m</sup> then the bit string
     * contained in the field element is converted into an octet
     * string with the same ordering padded at the front if necessary.
     * </li>
     * </ol>
     */
    @Override
	public ASN1Primitive toASN1Primitive()
    {
        final int byteCount = converter.getByteLength(this.f);
        final byte[] paddedBigInteger = converter.integerToBytes(this.f.toBigInteger(), byteCount);

        return new DEROctetString(paddedBigInteger);
    }
}
