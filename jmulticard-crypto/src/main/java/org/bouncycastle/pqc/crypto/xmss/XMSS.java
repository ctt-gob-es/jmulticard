package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;

/**
 * XMSS.
 */
public class XMSS
{

    /**
     * XMSS parameters.
     */
    private final XMSSParameters params;
    /**
     * WOTS+ instance.
     */
    private final WOTSPlus wotsPlus;
    /**
     * PRNG.
     */
    private final SecureRandom prng;

    /**
     * XMSS private key.
     */
    private XMSSPrivateKeyParameters privateKey;
    /**
     * XMSS public key.
     */
    private XMSSPublicKeyParameters publicKey;

    /**
     * XMSS constructor...
     *
     * @param params XMSSParameters.
     * @param prng Secure random.
     */
    public XMSS(final XMSSParameters params, final SecureRandom prng)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        this.params = params;
        this.wotsPlus = params.getWOTSPlus();
        this.prng = prng;
    }

//    public void generateKeys()
//    {
//        /* generate private key */
//        privateKey = generatePrivateKey(params, prng);
//        XMSSNode root = privateKey.getBDSState().initialize(privateKey, (OTSHashAddress)new OTSHashAddress.Builder().build());
//
//        privateKey = new XMSSPrivateKeyParameters.Builder(params).withIndex(privateKey.getIndex())
//            .withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF())
//            .withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue())
//            .withBDSState(privateKey.getBDSState()).build();
//        publicKey = new XMSSPublicKeyParameters.Builder(params).withRoot(root.getValue())
//            .withPublicSeed(getPublicSeed()).build();
//
//    }
//
//    /**
//     * Generate an XMSS private key.
//     *
//     * @return XMSS private key.
//     */
//    private XMSSPrivateKeyParameters generatePrivateKey(XMSSParameters params, SecureRandom prng)
//    {
//        int n = params.getDigestSize();
//        byte[] secretKeySeed = new byte[n];
//        prng.nextBytes(secretKeySeed);
//        byte[] secretKeyPRF = new byte[n];
//        prng.nextBytes(secretKeyPRF);
//        byte[] publicSeed = new byte[n];
//        prng.nextBytes(publicSeed);
//
//        XMSS xmss = new XMSS(params, prng);
//
////        this.privateKey = xmss.privateKey;
////        this.publicKey = xmss.publicKey;
////        this.wotsPlus = xmss.wotsPlus;
////        this.khf = xmss.khf;
//
//        XMSSPrivateKeyParameters privateKey = new XMSSPrivateKeyParameters.Builder(params).withSecretKeySeed(secretKeySeed)
//            .withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed)
//            .withBDSState(new BDS(xmss)).build();
//
//        return privateKey;
//    }

    /**
     * Generate a new XMSS private key / public key pair.
     */
    public void generateKeys()
    {
        final XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();

        kpGen.init(new XMSSKeyGenerationParameters(getParams(), this.prng));

        final AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        this.privateKey = (XMSSPrivateKeyParameters)kp.getPrivate();
        this.publicKey = (XMSSPublicKeyParameters)kp.getPublic();

        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    public void importState(final XMSSPrivateKeyParameters privateKey, final XMSSPublicKeyParameters publicKey)
    {
        if (!Arrays.areEqual(privateKey.getRoot(), publicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(privateKey.getPublicSeed(), publicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        /* import */
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    /**
     * Import XMSS private key / public key pair.
     *
     * @param privateKey XMSS private key.
     * @param publicKey  XMSS public key.
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
        /* import keys */
        final XMSSPrivateKeyParameters tmpPrivateKey = new XMSSPrivateKeyParameters.Builder(this.params)
            .withPrivateKey(privateKey).build();
        final XMSSPublicKeyParameters tmpPublicKey = new XMSSPublicKeyParameters.Builder(this.params).withPublicKey(publicKey)
            .build();
        if (!Arrays.areEqual(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot()))
        {
            throw new IllegalStateException("root of private key and public key do not match");
        }
        if (!Arrays.areEqual(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed()))
        {
            throw new IllegalStateException("public seed of private key and public key do not match");
        }
        /* import */
        this.privateKey = tmpPrivateKey;
        this.publicKey = tmpPublicKey;
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    /**
     * Sign message.
     *
     * @param message Message to sign.
     * @return XMSS signature on digest of message.
     */
    public byte[] sign(final byte[] message)
    {
        if (message == null)
        {
            throw new NullPointerException("message == null");
        }
        final XMSSSigner signer = new XMSSSigner();

        signer.init(true, this.privateKey);

        final byte[] signature = signer.generateSignature(message);

        this.privateKey = (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey();

        importState(this.privateKey, this.publicKey);

        return signature;
    }

    /**
     * Verify an XMSS signature.
     *
     * @param message   Message.
     * @param signature XMSS signature.
     * @param publicKey XMSS public key.
     * @return true if signature is valid false else.
     * @throws ParseException If error ocurrs while decoding signature.
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

        final XMSSSigner signer = new XMSSSigner();

        signer.init(false, new XMSSPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey).build());

        return signer.verifySignature(message, signature);
    }

    /**
     * Export XMSS private key.
     *
     * @return XMSS private key.
     */
    public XMSSPrivateKeyParameters exportPrivateKey()
    {
        return this.privateKey;
    }

    /**
     * Export XMSS public key.
     *
     * @return XMSS public key.
     */
    public XMSSPublicKeyParameters exportPublicKey()
    {
        return this.publicKey;
    }

    /**
     * Generate a WOTS+ signature on a message without the corresponding
     * authentication path
     *
     * @param messageDigest  Message digest of length n.
     * @param otsHashAddress OTS hash address.
     * @return XMSS signature.
     */
    protected WOTSPlusSignature wotsSign(final byte[] messageDigest, final OTSHashAddress otsHashAddress)
    {
        if (messageDigest.length != this.params.getTreeDigestSize())
        {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        }
        if (otsHashAddress == null)
        {
            throw new NullPointerException("otsHashAddress == null");
        }
        /* (re)initialize WOTS+ instance */
        this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(this.privateKey.getSecretKeySeed(), otsHashAddress), getPublicSeed());
        /* create WOTS+ signature */
        return this.wotsPlus.sign(messageDigest, otsHashAddress);
    }

    /**
     * Getter XMSS params.
     *
     * @return XMSS params.
     */
    public XMSSParameters getParams()
    {
        return this.params;
    }

    /**
     * Getter WOTS+.
     *
     * @return WOTS+ instance.
     */
    protected WOTSPlus getWOTSPlus()
    {
        return this.wotsPlus;
    }

    /**
     * Getter XMSS root.
     *
     * @return Root of binary tree.
     */
    public byte[] getRoot()
    {
        return this.privateKey.getRoot();
    }

    protected void setRoot(final byte[] root)
    {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params)
            .withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF())
            .withPublicSeed(getPublicSeed()).withRoot(root).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(root).withPublicSeed(getPublicSeed())
            .build();
    }

    /**
     * Getter XMSS index.
     *
     * @return Index.
     */
    public int getIndex()
    {
        return this.privateKey.getIndex();
    }

    protected void setIndex(final int index)
    {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params)
            .withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF())
            .withPublicSeed(this.privateKey.getPublicSeed()).withRoot(this.privateKey.getRoot())
            .withBDSState(this.privateKey.getBDSState()).build();
    }

    /**
     * Getter XMSS public seed.
     *
     * @return Public seed.
     */
    public byte[] getPublicSeed()
    {
        return this.privateKey.getPublicSeed();
    }

    protected void setPublicSeed(final byte[] publicSeed)
    {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params)
            .withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF())
            .withPublicSeed(publicSeed).withRoot(getRoot()).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(getRoot()).withPublicSeed(publicSeed)
            .build();

        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], publicSeed);
    }

    public XMSSPrivateKeyParameters getPrivateKey()
    {
        return this.privateKey;
    }
}
