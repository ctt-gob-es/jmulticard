package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.util.Pack;

/**
 * L-tree address.
 */
final class LTreeAddress
    extends XMSSAddress
{

    private static final int TYPE = 0x01;

    private final int lTreeAddress;
    private final int treeHeight;
    private final int treeIndex;

    LTreeAddress(final Builder builder) {
        super(builder);
        lTreeAddress = builder.lTreeAddress;
        treeHeight = builder.treeHeight;
        treeIndex = builder.treeIndex;
    }

    protected static class Builder extends XMSSAddress.Builder<Builder> {

        /* optional */
        private int lTreeAddress = 0;
        private int treeHeight = 0;
        private int treeIndex = 0;

        protected Builder()
        {
            super(TYPE);
        }

        protected Builder withLTreeAddress(final int val)
        {
            lTreeAddress = val;
            return this;
        }

        protected Builder withTreeHeight(final int val)
        {
            treeHeight = val;
            return this;
        }

        protected Builder withTreeIndex(final int val)
        {
            treeIndex = val;
            return this;
        }

        @Override
        protected XMSSAddress build()
        {
            return new LTreeAddress(this);
        }

        @Override
        protected Builder getThis()
        {
            return this;
        }
    }

    @Override
    protected byte[] toByteArray()
    {
        final byte[] byteRepresentation = super.toByteArray();
        Pack.intToBigEndian(lTreeAddress, byteRepresentation, 16);
        Pack.intToBigEndian(treeHeight, byteRepresentation, 20);
        Pack.intToBigEndian(treeIndex, byteRepresentation, 24);
        return byteRepresentation;
    }

    protected int getLTreeAddress()
    {
        return lTreeAddress;
    }

    protected int getTreeHeight()
    {
        return treeHeight;
    }

    protected int getTreeIndex()
    {
        return treeIndex;
    }
}
