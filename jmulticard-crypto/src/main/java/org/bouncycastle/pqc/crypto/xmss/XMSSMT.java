package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;

/**
 * XMSS^MT.
 */
public final class XMSSMT
{

    private final XMSSMTParameters params;
    private final XMSSParameters xmssParams;
    private final SecureRandom prng;
    private XMSSMTPrivateKeyParameters privateKey;
    private XMSSMTPublicKeyParameters publicKey;

    /**
     * XMSSMT constructor...
     *
     * @param params XMSSMTParameters.
     * @param prng   Secure random to use.
     */
    public XMSSMT(final XMSSMTParameters params, final SecureRandom prng)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        this.xmssParams = params.getXMSSParameters();
        this.prng = prng;

        this.privateKey = new XMSSMTPrivateKeyParameters.Builder(params).build();
        this.publicKey = new XMSSMTPublicKeyParameters.Builder(params).build();
    }

    /**
     * Generate a new XMSSMT private key / public key pair.
     */
    public void generateKeys()
    {
        final XMSSMTKeyPairGenerator kpGen = new XMSSMTKeyPairGenerator();

        kpGen.init(new XMSSMTKeyGenerationParameters(getParams(), this.prng));

        final AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        this.privateKey = (XMSSMTPrivateKeyParameters)kp.getPrivate();
        this.publicKey = (XMSSMTPublicKeyParameters)kp.getPublic();

        importState(this.privateKey, this.publicKey);
    }

    private void importState(final XMSSMTPrivateKeyParameters privateKey, final XMSSMTPublicKeyParameters publicKey)
    {
        /* import to xmss */
        this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());

        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Import XMSSMT private key / public key pair.
     *
     * @param privateKey XMSSMT private key.
     * @param publicKey  XMSSMT public key.
     */
    public void importState(final byte[] privateKey, final byte[] publicKey)
    {
        if (privateKey == null)
        {
            throw new NullPointerException("privateKey == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        final XMSSMTPrivateKeyParameters xmssMTPrivateKey = new XMSSMTPrivateKeyParameters.Builder(this.params)
            .withPrivateKey(privateKey).build();
        final XMSSMTPublicKeyParameters xmssMTPublicKey = new XMSSMTPublicKeyParameters.Builder(this.params)
            .withPublicKey(publicKey).build();
        if (!Arrays.areEqual(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }

        /* import to xmss */
        this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], xmssMTPrivateKey.getPublicSeed());

        this.privateKey = xmssMTPrivateKey;
        this.publicKey = xmssMTPublicKey;
    }

    /**
     * Sign message.
     *
     * @param message Message to sign.
     * @return XMSSMT signature on digest of message.
     */
    public byte[] sign(final byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }

        final XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(true, this.privateKey);

        final byte[] signature = signer.generateSignature(message);

        this.privateKey = (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey();

        importState(this.privateKey, this.publicKey);

        return signature;
    }

    /**
     * Verify an XMSSMT signature.
     *
     * @param message   Message.
     * @param signature XMSSMT signature.
     * @param publicKey XMSSMT public key.
     * @return true if signature is valid false else.
     * @throws ParseException If error occurs while parsing XML signature.
     */
    public boolean verifySignature(final byte[] message, final byte[] signature, final byte[] publicKey)
        throws ParseException
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }

        final XMSSMTSigner signer = new XMSSMTSigner();

        signer.init(false, new XMSSMTPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey).build());

        return signer.verifySignature(message, signature);
    }

    /**
     * Export XMSSMT private key.
     *
     * @return XMSSMT private key.
     */
    public byte[] exportPrivateKey()
    {
        return this.privateKey.toByteArray();
    }

    /**
     * Export XMSSMT public key.
     *
     * @return XMSSMT public key.
     */
    public byte[] exportPublicKey()
    {
        return this.publicKey.toByteArray();
    }

    /**
     * Getter XMSSMT params.
     *
     * @return XMSSMT params.
     */
    public XMSSMTParameters getParams()
    {
        return this.params;
    }


    /**
     * Getter public seed.
     *
     * @return Public seed.
     */
    public byte[] getPublicSeed()
    {
        return this.privateKey.getPublicSeed();
    }

    protected XMSSParameters getXMSS()
    {
        return this.xmssParams;
    }
}
