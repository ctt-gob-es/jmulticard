package org.bouncycastle.pqc.crypto.lms;

import static org.bouncycastle.pqc.crypto.lms.LM_OTS.MAX_HASH;

import org.bouncycastle.crypto.Digest;

public class LMSContext
    implements Digest
{
    private final byte[] C;
    private final LMOtsPrivateKey key;
    private final LMSigParameters sigParams;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final Object signature;

    private LMSSignedPubKey[] signedPubKeys;
    private volatile Digest digest;

    public LMSContext(final LMOtsPrivateKey key, final LMSigParameters sigParams, final Digest digest, final byte[] C, final byte[][] path)
    {
        this.key = key;
        this.sigParams = sigParams;
        this.digest = digest;
        this.C = C;
        this.path = path;
        publicKey = null;
        signature = null;
    }

    public LMSContext(final LMOtsPublicKey publicKey, final Object signature, final Digest digest)
    {
        this.publicKey = publicKey;
        this.signature = signature;
        this.digest = digest;
        C = null;
        key = null;
        sigParams = null;
        path = null;
    }

    byte[] getC()
    {
        return C;
    }

    byte[] getQ()
    {
        final byte[] Q = new byte[MAX_HASH + 2];

        digest.doFinal(Q, 0);

        digest = null;

        return Q;
    }

    byte[][] getPath()
    {
        return path;
    }

    LMOtsPrivateKey getPrivateKey()
    {
        return key;
    }

    public LMOtsPublicKey getPublicKey()
    {
        return publicKey;
    }

    LMSigParameters getSigParams()
    {
        return sigParams;
    }

    public Object getSignature()
    {
        return signature;
    }

    LMSSignedPubKey[] getSignedPubKeys()
    {
        return signedPubKeys;
    }

    LMSContext withSignedPublicKeys(final LMSSignedPubKey[] signedPubKeys)
    {
        this.signedPubKeys = signedPubKeys;

        return this;
    }

    @Override
	public String getAlgorithmName()
    {
        return digest.getAlgorithmName();
    }

    @Override
	public int getDigestSize()
    {
        return digest.getDigestSize();
    }

    @Override
	public void update(final byte in)
    {
        digest.update(in);
    }

    @Override
	public void update(final byte[] in, final int inOff, final int len)
    {
        digest.update(in, inOff, len);
    }

    @Override
	public int doFinal(final byte[] out, final int outOff)
    {
        return digest.doFinal(out, outOff);
    }

    @Override
	public void reset()
    {
        digest.reset();
    }
}
