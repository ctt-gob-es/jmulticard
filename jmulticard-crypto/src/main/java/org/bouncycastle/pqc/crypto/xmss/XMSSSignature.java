package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;

import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS Signature.
 */
public final class XMSSSignature
    extends XMSSReducedSignature
    implements XMSSStoreableObjectInterface, Encodable
{

    private final int index;
    private final byte[] random;

    private XMSSSignature(final Builder builder)
    {
        super(builder);
        index = builder.index;
        final int n = getParams().getTreeDigestSize();
        final byte[] tmpRandom = builder.random;
        if (tmpRandom != null)
        {
            if (tmpRandom.length != n)
            {
                throw new IllegalArgumentException("size of random needs to be equal to size of digest");
            }
            random = tmpRandom;
        }
        else
        {
            random = new byte[n];
        }
    }

    @Override
	public byte[] getEncoded()
        throws IOException
    {
        return toByteArray();
    }

    public static class Builder
        extends XMSSReducedSignature.Builder
    {

        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private byte[] random = null;

        public Builder(final XMSSParameters params)
        {
            super(params);
            this.params = params;
        }

        public Builder withIndex(final int val)
        {
            index = val;
            return this;
        }

        public Builder withRandom(final byte[] val)
        {
            random = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSignature(final byte[] val)
        {
            if (val == null)
            {
                throw new NullPointerException("signature == null");
            }
            final int n = params.getTreeDigestSize();
            final int len = params.getWOTSPlus().getParams().getLen();
            final int height = params.getHeight();
            final int indexSize = 4;
            final int randomSize = n;
            final int signatureSize = len * n;
            final int authPathSize = height * n;
            int position = 0;
            /* extract index */
            index = Pack.bigEndianToInt(val, position);
            position += indexSize;
            /* extract random */
            random = XMSSUtil.extractBytesAtOffset(val, position, randomSize);
            position += randomSize;
            withReducedSignature(XMSSUtil.extractBytesAtOffset(val, position, signatureSize + authPathSize));
            return this;
        }

        @Override
		public XMSSSignature build()
        {
            return new XMSSSignature(this);
        }
    }

    /**
     * @deprecated use getEncoded() this method will become private.
     * @return
     */
    @Override
	@Deprecated
	public byte[] toByteArray()
    {
        /* index || random || signature || authentication path */
        final int n = getParams().getTreeDigestSize();
        final int indexSize = 4;
        final int randomSize = n;
        final int signatureSize = getParams().getWOTSPlus().getParams().getLen() * n;
        final int authPathSize = getParams().getHeight() * n;
        final int totalSize = indexSize + randomSize + signatureSize + authPathSize;
        final byte[] out = new byte[totalSize];
        int position = 0;
        /* copy index */
        Pack.intToBigEndian(index, out, position);
        position += indexSize;
        /* copy random */
        XMSSUtil.copyBytesAtOffset(out, random, position);
        position += randomSize;
        /* copy signature */
        final byte[][] signature = getWOTSPlusSignature().toByteArray();
        for (final byte[] element : signature) {
            XMSSUtil.copyBytesAtOffset(out, element, position);
            position += n;
        }
        /* copy authentication path */
        for (final XMSSNode element : getAuthPath()) {
            final byte[] value = element.getValue();
            XMSSUtil.copyBytesAtOffset(out, value, position);
            position += n;
        }
        return out;
    }

    public int getIndex()
    {
        return index;
    }

    public byte[] getRandom()
    {
        return XMSSUtil.cloneArray(random);
    }
}
