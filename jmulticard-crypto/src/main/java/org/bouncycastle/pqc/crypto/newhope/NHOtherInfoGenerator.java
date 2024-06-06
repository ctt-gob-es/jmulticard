package org.bouncycastle.pqc.crypto.newhope;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.ExchangePair;

/**
 * OtherInfo Generator for which can be used for populating the SuppPrivInfo field used to provide shared
 * secret data used with NIST SP 800-56A agreement algorithms.
 */
public class NHOtherInfoGenerator
{
    protected final DEROtherInfo.Builder otherInfoBuilder;
    protected final SecureRandom random;

    protected boolean used = false;

    /**
     * Create a basic builder with just the compulsory fields.
     *
     * @param algorithmID the algorithm associated with this invocation of the KDF.
     * @param partyUInfo  sender party info.
     * @param partyVInfo  receiver party info.
     * @param random a source of randomness.
     */
    public NHOtherInfoGenerator(final AlgorithmIdentifier algorithmID, final byte[] partyUInfo, final byte[] partyVInfo, final SecureRandom random)
    {
        this.otherInfoBuilder = new DEROtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
        this.random = random;
    }

    /**
     * Party U (initiator) generation.
     */
    public static class PartyU
        extends NHOtherInfoGenerator
    {
        private final AsymmetricCipherKeyPair aKp;
        private final NHAgreement agreement = new NHAgreement();

        public PartyU(final AlgorithmIdentifier algorithmID, final byte[] partyUInfo, final byte[] partyVInfo, final java.security.SecureRandom random)
        {
            super(algorithmID, partyUInfo, partyVInfo, random);

            final NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(new KeyGenerationParameters(random, 2048));

            aKp = kpGen.generateKeyPair();

            agreement.init(aKp.getPrivate());
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public NHOtherInfoGenerator withSuppPubInfo(final byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        public byte[] getSuppPrivInfoPartA()
        {
            return getEncoded((NHPublicKeyParameters)aKp.getPublic());
        }

        public DEROtherInfo generate(final byte[] suppPrivInfoPartB)
        {
            if (used)
            {
                throw new IllegalStateException("builder already used"); //$NON-NLS-1$
            }

            used = true;

            this.otherInfoBuilder.withSuppPrivInfo(agreement.calculateAgreement(NHOtherInfoGenerator.getPublicKey(suppPrivInfoPartB)));

            return otherInfoBuilder.build();
        }
    }

    /**
     * Party V (responder) generation.
     */
    public static class PartyV
        extends NHOtherInfoGenerator
    {
        public PartyV(final AlgorithmIdentifier algorithmID, final byte[] partyUInfo, final byte[] partyVInfo, final SecureRandom random)
        {
            super(algorithmID, partyUInfo, partyVInfo, random);
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return the current builder instance.
         */
        public NHOtherInfoGenerator withSuppPubInfo(final byte[] suppPubInfo)
        {
            this.otherInfoBuilder.withSuppPubInfo(suppPubInfo);

            return this;
        }

        public byte[] getSuppPrivInfoPartB(final byte[] suppPrivInfoPartA)
        {
            final NHExchangePairGenerator exchGen = new NHExchangePairGenerator(random);

            final ExchangePair bEp = exchGen.generateExchange(getPublicKey(suppPrivInfoPartA));

            this.otherInfoBuilder.withSuppPrivInfo(bEp.getSharedValue());

            return getEncoded((NHPublicKeyParameters)bEp.getPublicKey());
        }

        public DEROtherInfo generate()
        {
            if (used)
            {
                throw new IllegalStateException("builder already used"); //$NON-NLS-1$
            }

            used = true;

            return otherInfoBuilder.build();
        }
    }

    static byte[] getEncoded(final NHPublicKeyParameters pubKey)
    {
        SubjectPublicKeyInfo pki;
        try
        {
            final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            pki = new SubjectPublicKeyInfo(algorithmIdentifier, pubKey.getPubData());

            return pki.getEncoded();
        }
        catch (final IOException e)
        {
            return null;
        }
    }

    static NHPublicKeyParameters getPublicKey(final byte[] enc)
    {
        final SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(enc);

        return new NHPublicKeyParameters(pki.getPublicKeyData().getOctets());
    }
}
