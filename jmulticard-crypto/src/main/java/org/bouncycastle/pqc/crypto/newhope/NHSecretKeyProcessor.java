package org.bouncycastle.pqc.crypto.newhope;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.util.Arrays;

/**
 * A processor with associated builders for doing secret key transformation using
 * the New Hope algorithm.
 */
public class NHSecretKeyProcessor
{
    /**
     * Party U (initiator) processor builder.
     */
    public static class PartyUBuilder
    {
        private final AsymmetricCipherKeyPair aKp;
        private final NHAgreement agreement = new NHAgreement();

        private byte[] sharedInfo = null;
        private boolean used = false;

        public PartyUBuilder(final SecureRandom random)
        {
            final NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(new KeyGenerationParameters(random, 2048));

            aKp = kpGen.generateKeyPair();

            agreement.init(aKp.getPrivate());
        }

        public PartyUBuilder withSharedInfo(final byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartA()
        {
            return ((NHPublicKeyParameters)aKp.getPublic()).getPubData();
        }

        public NHSecretKeyProcessor build(final byte[] partB)
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return new NHSecretKeyProcessor(agreement.calculateAgreement(new NHPublicKeyParameters(partB)), sharedInfo);
        }
    }

    /**
     * Party V (responder) processor builder.
     */
    public static class PartyVBuilder
    {
        protected final SecureRandom random;

        private byte[] sharedInfo = null;
        private byte[] sharedSecret = null;
        private boolean used = false;

        public PartyVBuilder(final SecureRandom random)
        {
            this.random = random;
        }

        public PartyVBuilder withSharedInfo(final byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartB(final byte[] partUContribution)
        {
            final NHExchangePairGenerator exchGen = new NHExchangePairGenerator(random);

            final ExchangePair bEp = exchGen.generateExchange(new NHPublicKeyParameters(partUContribution));

            sharedSecret = bEp.getSharedValue();

            return ((NHPublicKeyParameters)bEp.getPublicKey()).getPubData();
        }

        public NHSecretKeyProcessor build()
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return new NHSecretKeyProcessor(sharedSecret, sharedInfo);
        }
    }

    private final Xof xof = new SHAKEDigest(256);

    NHSecretKeyProcessor(final byte[] secret, final byte[] shared) {
        xof.update(secret, 0, secret.length);

        if (shared != null) {
            xof.update(shared, 0, shared.length);
        }

        Arrays.fill(secret, (byte)0);
    }

    public byte[] processKey(final byte[] initialKey)
    {
        final byte[] xorBytes = new byte[initialKey.length];

        xof.doFinal(xorBytes, 0, xorBytes.length);

        xor(initialKey, xorBytes);

        Arrays.fill(xorBytes, (byte)0);

        return initialKey;
    }

    private static void xor(final byte[] a, final byte[] b)
    {
        for (int i = 0; i != a.length; i++)
        {
            a[i] ^= b[i];
        }
    }
}
