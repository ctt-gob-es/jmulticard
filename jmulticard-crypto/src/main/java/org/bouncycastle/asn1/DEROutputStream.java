package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
class DEROutputStream
    extends DLOutputStream
{
    DEROutputStream(final OutputStream os)
    {
        super(os);
    }

    @Override
	DEROutputStream getDERSubStream()
    {
        return this;
    }

    @Override
	void writeElements(final ASN1Encodable[] elements)
        throws IOException
    {
        for (final ASN1Encodable element : elements) {
            element.toASN1Primitive().toDERObject().encode(this, true);
        }
    }

    @Override
	void writePrimitive(final ASN1Primitive primitive, final boolean withTag) throws IOException
    {
        primitive.toDERObject().encode(this, withTag);
    }

    @Override
	void writePrimitives(final ASN1Primitive[] primitives)
        throws IOException
    {
        final int count = primitives.length;
        for (int i = 0; i < count; ++i)
        {
            primitives[i].toDERObject().encode(this, true);
        }
    }
}
