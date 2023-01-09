package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;

/**
 * Reduced XMSS Signature.
 */
public class XMSSReducedSignature
    implements XMSSStoreableObjectInterface
{

    private final XMSSParameters params;
    private final WOTSPlusSignature wotsPlusSignature;
    private final List<XMSSNode> authPath;

    protected XMSSReducedSignature(final Builder builder)
    {
        params = builder.params;
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        final int n = params.getTreeDigestSize();
        final int len = params.getWOTSPlus().getParams().getLen();
        final int height = params.getHeight();
        final byte[] reducedSignature = builder.reducedSignature;
        if (reducedSignature != null)
        {
            /* import */
            final int signatureSize = len * n;
            final int authPathSize = height * n;
            final int totalSize = signatureSize + authPathSize;
            if (reducedSignature.length != totalSize)
            {
                throw new IllegalArgumentException("signature has wrong size");
            }
            int position = 0;
            final byte[][] wotsPlusSignature = new byte[len][];
            for (int i = 0; i < wotsPlusSignature.length; i++)
            {
                wotsPlusSignature[i] = XMSSUtil.extractBytesAtOffset(reducedSignature, position, n);
                position += n;
            }
            this.wotsPlusSignature = new WOTSPlusSignature(params.getWOTSPlus().getParams(), wotsPlusSignature);

            final List<XMSSNode> nodeList = new ArrayList<>();
            for (int i = 0; i < height; i++)
            {
                nodeList.add(new XMSSNode(i, XMSSUtil.extractBytesAtOffset(reducedSignature, position, n)));
                position += n;
            }
            authPath = nodeList;
        }
        else
        {
            /* set */
            final WOTSPlusSignature tmpSignature = builder.wotsPlusSignature;
            if (tmpSignature != null)
            {
                wotsPlusSignature = tmpSignature;
            }
            else
            {
                wotsPlusSignature = new WOTSPlusSignature(params.getWOTSPlus().getParams(), new byte[len][n]);
            }
            final List<XMSSNode> tmpAuthPath = builder.authPath;
            if (tmpAuthPath != null)
            {
                if (tmpAuthPath.size() != height)
                {
                    throw new IllegalArgumentException("size of authPath needs to be equal to height of tree");
                }
                authPath = tmpAuthPath;
            }
            else
            {
                authPath = new ArrayList<>();
            }
        }
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private WOTSPlusSignature wotsPlusSignature = null;
        private List<XMSSNode> authPath = null;
        private byte[] reducedSignature = null;

        public Builder(final XMSSParameters params)
        {
            this.params = params;
        }

        public Builder withWOTSPlusSignature(final WOTSPlusSignature val)
        {
            wotsPlusSignature = val;
            return this;
        }

        public Builder withAuthPath(final List<XMSSNode> val)
        {
            authPath = val;
            return this;
        }

        public Builder withReducedSignature(final byte[] val)
        {
            reducedSignature = XMSSUtil.cloneArray(val);
            return this;
        }

        public XMSSReducedSignature build()
        {
            return new XMSSReducedSignature(this);
        }
    }

    @Override
	public byte[] toByteArray()
    {
        /* signature || authentication path */
        final int n = params.getTreeDigestSize();
        final int signatureSize = params.getWOTSPlus().getParams().getLen() * n;
        final int authPathSize = params.getHeight() * n;
        final int totalSize = signatureSize + authPathSize;
        final byte[] out = new byte[totalSize];
        int position = 0;
        /* copy signature */
        final byte[][] signature = wotsPlusSignature.toByteArray();
        for (final byte[] element : signature) {
            XMSSUtil.copyBytesAtOffset(out, element, position);
            position += n;
        }
        /* copy authentication path */
        for (final XMSSNode element : authPath) {
            final byte[] value = element.getValue();
            XMSSUtil.copyBytesAtOffset(out, value, position);
            position += n;
        }
        return out;
    }

    public XMSSParameters getParams()
    {
        return params;
    }

    public WOTSPlusSignature getWOTSPlusSignature()
    {
        return wotsPlusSignature;
    }

    public List<XMSSNode> getAuthPath()
    {
        return authPath;
    }
}
