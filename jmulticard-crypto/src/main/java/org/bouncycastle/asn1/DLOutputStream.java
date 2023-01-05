package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on definite length.
 */
class DLOutputStream
    extends ASN1OutputStream
{
    DLOutputStream(final OutputStream os)
    {
        super(os);
    }

    @Override
	DLOutputStream getDLSubStream()
    {
        return this;
    }

    @Override
	void writeElements(final ASN1Encodable[] elements)
        throws IOException
    {
        for (final ASN1Encodable element : elements) {
            element.toASN1Primitive().toDLObject().encode(this, true);
        }
    }

    @Override
	void writePrimitive(final ASN1Primitive primitive, final boolean withTag) throws IOException
    {
        primitive.toDLObject().encode(this, withTag);
    }

    @Override
	void writePrimitives(final ASN1Primitive[] primitives)
        throws IOException
    {
        final int count = primitives.length;
        for (int i = 0; i < count; ++i)
        {
            primitives[i].toDLObject().encode(this, true);
        }
    }
}
