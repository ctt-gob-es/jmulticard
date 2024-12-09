package org.bouncycastle.asn1;

/**
 * Class representing the DER-type External
 */
public class DERExternal
    extends ASN1External
{
    /**
     * Construct a DER EXTERNAL object, the input encoding vector must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     * @param vector Encodable vector.
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     *
     * @deprecated Use {@link DERExternal#DERExternal(DERSequence)} instead.
     */
    @Deprecated
	public DERExternal(final ASN1EncodableVector vector)
    {
        this(DERFactory.createSequence(vector));
    }

    /**
     * Construct a DER EXTERNAL object, the input sequence must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     * @param sequence Encodable sequence.
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     */
    public DERExternal(final DERSequence sequence)
    {
        super(sequence);
    }

    /**
     * Creates a new instance of DERExternal
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param externalData The external data in its encoded form.
     */
    public DERExternal(final ASN1ObjectIdentifier directReference, final ASN1Integer indirectReference,
        final ASN1Primitive dataValueDescriptor, final DERTaggedObject externalData)
    {
        super(directReference, indirectReference, dataValueDescriptor, externalData);
    }

    /**
     * Creates a new instance of DERExternal.
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding The encoding to be used for the external data
     * @param externalData The external data
     */
    public DERExternal(final ASN1ObjectIdentifier directReference, final ASN1Integer indirectReference,
        final ASN1Primitive dataValueDescriptor, final int encoding, final ASN1Primitive externalData)
    {
        super(directReference, indirectReference, dataValueDescriptor, encoding, externalData);
    }

    @Override
	ASN1Sequence buildSequence()
    {
        final ASN1EncodableVector v = new ASN1EncodableVector(4);
        if (this.directReference != null)
        {
            v.add(this.directReference);
        }
        if (this.indirectReference != null)
        {
            v.add(this.indirectReference);
        }
        if (this.dataValueDescriptor != null)
        {
            v.add(this.dataValueDescriptor.toDERObject());
        }

        v.add(new DERTaggedObject(0 == this.encoding, this.encoding, this.externalContent));

        return new DERSequence(v);
    }

    @Override
	ASN1Primitive toDERObject()
    {
        return this;
    }

    @Override
	ASN1Primitive toDLObject()
    {
        return this;
    }
}
