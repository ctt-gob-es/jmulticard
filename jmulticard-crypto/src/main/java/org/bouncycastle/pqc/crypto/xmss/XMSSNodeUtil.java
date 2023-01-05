package org.bouncycastle.pqc.crypto.xmss;

class XMSSNodeUtil
{
    /**
     * Compresses a WOTS+ public key to a single n-byte string.
     *
     * @param publicKey WOTS+ public key to compress.
     * @param address   Address.
     * @return Compressed n-byte string of public key.
     */
    static XMSSNode lTree(final WOTSPlus wotsPlus, final WOTSPlusPublicKeyParameters publicKey, LTreeAddress address)
    {
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        if (address == null)
        {
            throw new NullPointerException("address == null");
        }
        int len = wotsPlus.getParams().getLen();
            /* duplicate public key to XMSSNode Array */
        final byte[][] publicKeyBytes = publicKey.toByteArray();
        final XMSSNode[] publicKeyNodes = new XMSSNode[publicKeyBytes.length];
        for (int i = 0; i < publicKeyBytes.length; i++)
        {
            publicKeyNodes[i] = new XMSSNode(0, publicKeyBytes[i]);
        }
        address = (LTreeAddress)new LTreeAddress.Builder().withLayerAddress(address.getLayerAddress())
            .withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress()).withTreeHeight(0)
            .withTreeIndex(address.getTreeIndex()).withKeyAndMask(address.getKeyAndMask()).build();
        while (len > 1)
        {
            for (int i = 0; i < (int)Math.floor(len / 2); i++)
            {
                address = (LTreeAddress)new LTreeAddress.Builder().withLayerAddress(address.getLayerAddress())
                    .withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress())
                    .withTreeHeight(address.getTreeHeight()).withTreeIndex(i)
                    .withKeyAndMask(address.getKeyAndMask()).build();
                publicKeyNodes[i] = randomizeHash(wotsPlus, publicKeyNodes[2 * i], publicKeyNodes[2 * i + 1], address);
            }
            if (len % 2 == 1)
            {
                publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
            }
            len = (int)Math.ceil((double)len / 2);
            address = (LTreeAddress)new LTreeAddress.Builder().withLayerAddress(address.getLayerAddress())
                .withTreeAddress(address.getTreeAddress()).withLTreeAddress(address.getLTreeAddress())
                .withTreeHeight(address.getTreeHeight() + 1).withTreeIndex(address.getTreeIndex())
                .withKeyAndMask(address.getKeyAndMask()).build();
        }
        return publicKeyNodes[0];
    }

    /**
     * Randomization of nodes in binary tree.
     *
     * @param left    Left node.
     * @param right   Right node.
     * @param address Address.
     * @return Randomized hash of parent of left / right node.
     */
    static XMSSNode randomizeHash(final WOTSPlus wotsPlus, final XMSSNode left, final XMSSNode right, XMSSAddress address)
    {
        if (left == null)
        {
            throw new NullPointerException("left == null");
        }
        if (right == null)
        {
            throw new NullPointerException("right == null");
        }
        if (left.getHeight() != right.getHeight())
        {
            throw new IllegalStateException("height of both nodes must be equal");
        }
        if (address == null)
        {
            throw new NullPointerException("address == null");
        }
        final byte[] publicSeed = wotsPlus.getPublicSeed();

        if (address instanceof LTreeAddress)
        {
            final LTreeAddress tmpAddress = (LTreeAddress)address;
            address = new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
                .withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
                .withKeyAndMask(0).build();
        }
        else if (address instanceof HashTreeAddress)
        {
            final HashTreeAddress tmpAddress = (HashTreeAddress)address;
            address = new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
                .withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(0).build();
        }

        final byte[] key = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

        if (address instanceof LTreeAddress)
        {
            final LTreeAddress tmpAddress = (LTreeAddress)address;
            address = new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
                .withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
                .withKeyAndMask(1).build();
        }
        else if (address instanceof HashTreeAddress)
        {
            final HashTreeAddress tmpAddress = (HashTreeAddress)address;
            address = new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
                .withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(1).build();
        }

        final byte[] bitmask0 = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());

        if (address instanceof LTreeAddress)
        {
            final LTreeAddress tmpAddress = (LTreeAddress)address;
            address = new LTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withLTreeAddress(tmpAddress.getLTreeAddress())
                .withTreeHeight(tmpAddress.getTreeHeight()).withTreeIndex(tmpAddress.getTreeIndex())
                .withKeyAndMask(2).build();
        }
        else if (address instanceof HashTreeAddress)
        {
            final HashTreeAddress tmpAddress = (HashTreeAddress)address;
            address = new HashTreeAddress.Builder().withLayerAddress(tmpAddress.getLayerAddress())
                .withTreeAddress(tmpAddress.getTreeAddress()).withTreeHeight(tmpAddress.getTreeHeight())
                .withTreeIndex(tmpAddress.getTreeIndex()).withKeyAndMask(2).build();
        }

        final byte[] bitmask1 = wotsPlus.getKhf().PRF(publicSeed, address.toByteArray());
        final int n = wotsPlus.getParams().getTreeDigestSize();
        final byte[] tmpMask = new byte[2 * n];
        for (int i = 0; i < n; i++)
        {
            tmpMask[i] = (byte)(left.getValue()[i] ^ bitmask0[i]);
        }
        for (int i = 0; i < n; i++)
        {
            tmpMask[i + n] = (byte)(right.getValue()[i] ^ bitmask1[i]);
        }
        final byte[] out = wotsPlus.getKhf().H(key, tmpMask);
        return new XMSSNode(left.getHeight(), out);
    }
}
