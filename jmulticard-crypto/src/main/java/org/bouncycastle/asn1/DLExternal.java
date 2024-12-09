package org.bouncycastle.asn1;

/**
 * Class representing the Definite-Length-type External
 */
public class DLExternal
    extends ASN1External
{
    /**
     * Construct a Definite-Length EXTERNAL object, the input encoding vector must have exactly two elements on it.
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
     * @deprecated Use {@link DLExternal#DLExternal(DLSequence)} instead.
     */
    @Deprecated
	public DLExternal(final ASN1EncodableVector vector)
    {
        this(DLFactory.createSequence(vector));
    }

    /**
     * Construct a Definite-Length EXTERNAL object, the input sequence must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     * @param sequence Sequence.
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     */
    public DLExternal(final DLSequence sequence)
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
    public DLExternal(final ASN1ObjectIdentifier directReference, final ASN1Integer indirectReference,
        final ASN1Primitive dataValueDescriptor, final DERTaggedObject externalData)
    {
        super(directReference, indirectReference, dataValueDescriptor, externalData);
    }

    /**
     * Creates a new instance of Definite-Length External.
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding The encoding to be used for the external data
     * @param externalData The external data
     */
    public DLExternal(final ASN1ObjectIdentifier directReference, final ASN1Integer indirectReference,
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
            v.add(this.dataValueDescriptor.toDLObject());
        }

        v.add(new DLTaggedObject(0 == this.encoding, this.encoding, this.externalContent));

        return new DLSequence(v);
    }

    @Override
	ASN1Primitive toDLObject()
    {
        return this;
    }
}
