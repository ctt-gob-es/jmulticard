package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;

import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

/**
 * XMSS Public Key.
 */
public final class XMSSPublicKeyParameters
    extends XMSSKeyParameters
    implements XMSSStoreableObjectInterface, Encodable
{

    /**
     * XMSS parameters object.
     */
    private final XMSSParameters params;
    private final int oid;
    private final byte[] root;
    private final byte[] publicSeed;

    private XMSSPublicKeyParameters(final Builder builder)
    {
        super(false, builder.params.getTreeDigest());
        params = builder.params;
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        final int n = params.getTreeDigestSize();
        final byte[] publicKey = builder.publicKey;
        if (publicKey != null)
        {
            /* import */
            final int oidSize = 4;
            final int rootSize = n;
            final int publicSeedSize = n;
            // updated key
            int position = 0;
            // pre-rfc final key without OID.
            if (publicKey.length == rootSize + publicSeedSize)
            {
                oid = 0;
            }
            else if (publicKey.length == oidSize + rootSize + publicSeedSize)
            {
                oid = Pack.bigEndianToInt(publicKey, 0);
                position += oidSize;
            }
            else
            {
                throw new IllegalArgumentException("public key has wrong size");
            }
			root = XMSSUtil.extractBytesAtOffset(publicKey, position, rootSize);
			position += rootSize;
			publicSeed = XMSSUtil.extractBytesAtOffset(publicKey, position, publicSeedSize);
        }
        else
        {
            /* set */
            if (params.getOid() != null)
            {
                oid = params.getOid().getOid();
            }
            else
            {
                oid = 0;
            }
            final byte[] tmpRoot = builder.root;
            if (tmpRoot != null)
            {
                if (tmpRoot.length != n)
                {
                    throw new IllegalArgumentException("length of root must be equal to length of digest");
                }
                root = tmpRoot;
            }
            else
            {
                root = new byte[n];
            }
            final byte[] tmpPublicSeed = builder.publicSeed;
            if (tmpPublicSeed != null)
            {
                if (tmpPublicSeed.length != n)
                {
                    throw new IllegalArgumentException("length of publicSeed must be equal to length of digest");
                }
                publicSeed = tmpPublicSeed;
            }
            else
            {
                publicSeed = new byte[n];
            }
        }
    }

    @Override
	public byte[] getEncoded()
        throws IOException
    {
        return toByteArray();
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private byte[] root = null;
        private byte[] publicSeed = null;
        private byte[] publicKey = null;

        public Builder(final XMSSParameters params)
        {
            this.params = params;
        }

        public Builder withRoot(final byte[] val)
        {
            root = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(final byte[] val)
        {
            publicSeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicKey(final byte[] val)
        {
            publicKey = XMSSUtil.cloneArray(val);
            return this;
        }

        public XMSSPublicKeyParameters build()
        {
            return new XMSSPublicKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    @Override
	@Deprecated
	public byte[] toByteArray()
    {
        /* oid || root || seed */
        final int n = params.getTreeDigestSize();
        final int oidSize = 4;
        final int rootSize = n;
        final int publicSeedSize = n;

        byte[] out;
        int position = 0;
        /* copy oid */
        if (oid != 0)
        {
            out = new byte[oidSize + rootSize + publicSeedSize];
            Pack.intToBigEndian(oid, out, position);
            position += oidSize;
        }
        else
        {
            out = new byte[rootSize + publicSeedSize];
        }
        /* copy root */
        XMSSUtil.copyBytesAtOffset(out, root, position);
        position += rootSize;
        /* copy public seed */
        XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
        return out;
    }

    public byte[] getRoot()
    {
        return XMSSUtil.cloneArray(root);
    }

    public byte[] getPublicSeed()
    {
        return XMSSUtil.cloneArray(publicSeed);
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}
