package org.bouncycastle.operator.jcajce;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.io.TeeOutputStream;

public class JcaContentVerifierProviderBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcaContentVerifierProviderBuilder()
    {
    }

    public JcaContentVerifierProviderBuilder setProvider(final Provider provider)
    {
        helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaContentVerifierProviderBuilder setProvider(final String providerName)
    {
        helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public ContentVerifierProvider build(final X509CertificateHolder certHolder)
        throws OperatorCreationException, CertificateException
    {
        return build(helper.convertCertificate(certHolder));
    }

    public ContentVerifierProvider build(final X509Certificate certificate)
        throws OperatorCreationException
    {
        final X509CertificateHolder certHolder;

        try
        {
            certHolder = new JcaX509CertificateHolder(certificate);
        }
        catch (final CertificateEncodingException e)
        {
            throw new OperatorCreationException("cannot process certificate: " + e.getMessage(), e); //$NON-NLS-1$
        }

        return new ContentVerifierProvider()
        {
            @Override
			public boolean hasAssociatedCertificate()
            {
                return true;
            }

            @Override
			public X509CertificateHolder getAssociatedCertificate()
            {
                return certHolder;
            }

            @Override
			public ContentVerifier get(final AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                if (algorithm.getAlgorithm().equals(MiscObjectIdentifiers.id_alg_composite))
                {
                    return createCompositeVerifier(algorithm, certificate.getPublicKey());
                }
				Signature sig;
				try
				{
				    sig = helper.createSignature(algorithm);

				    sig.initVerify(certificate.getPublicKey());
				}
				catch (final GeneralSecurityException e)
				{
				    throw new OperatorCreationException("exception on setup: " + e, e); //$NON-NLS-1$
				}

				final Signature rawSig = createRawSig(algorithm, certificate.getPublicKey());

				if (rawSig != null)
				{
				    return new RawSigVerifier(algorithm, sig, rawSig);
				}
				return new SigVerifier(algorithm, sig);
            }
        };
    }

    public ContentVerifierProvider build(final PublicKey publicKey)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            @Override
			public boolean hasAssociatedCertificate()
            {
                return false;
            }

            @Override
			public X509CertificateHolder getAssociatedCertificate()
            {
                return null;
            }

            @Override
			public ContentVerifier get(final AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                if (algorithm.getAlgorithm().equals(MiscObjectIdentifiers.id_alg_composite))
                {
                    return createCompositeVerifier(algorithm, publicKey);
                }

                if (!(publicKey instanceof CompositePublicKey)) {
                    final Signature sig = createSignature(algorithm, publicKey);

                    final Signature rawSig = createRawSig(algorithm, publicKey);

                    if (rawSig != null)
                    {
                        return new RawSigVerifier(algorithm, sig, rawSig);
                    }
					return new SigVerifier(algorithm, sig);
                }
				final List<PublicKey> keys = ((CompositePublicKey)publicKey).getPublicKeys();

				for (final PublicKey key : keys) {
				    try
				    {
				        final Signature sig = createSignature(algorithm, key);

				        final Signature rawSig = createRawSig(algorithm, key);

				        if (rawSig != null)
				        {
				            return new RawSigVerifier(algorithm, sig, rawSig);
				        }
						return new SigVerifier(algorithm, sig);
				    }
				    catch (final OperatorCreationException e)
				    {
				        // skip incorrect keys
				    }
				}

				throw new OperatorCreationException("no matching algorithm found for key"); //$NON-NLS-1$
            }
        };
    }

    public ContentVerifierProvider build(final SubjectPublicKeyInfo publicKey)
        throws OperatorCreationException
    {
        return this.build(helper.convertPublicKey(publicKey));
    }

    ContentVerifier createCompositeVerifier(final AlgorithmIdentifier compAlgId, final PublicKey publicKey)
        throws OperatorCreationException
    {
        if (publicKey instanceof CompositePublicKey)
        {
            final List<PublicKey> pubKeys = ((CompositePublicKey)publicKey).getPublicKeys();
            final ASN1Sequence keySeq = ASN1Sequence.getInstance(compAlgId.getParameters());
            final Signature[] sigs = new Signature[keySeq.size()];
            for (int i = 0; i != keySeq.size(); i++)
            {
                final AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                if (pubKeys.get(i) != null)
                {
                    sigs[i] = createSignature(sigAlg, pubKeys.get(i));
                }
                else
                {
                    sigs[i] = null;
                }
            }

            return new CompositeVerifier(sigs);
        }
		final ASN1Sequence keySeq = ASN1Sequence.getInstance(compAlgId.getParameters());
		final Signature[] sigs = new Signature[keySeq.size()];
		for (int i = 0; i != keySeq.size(); i++)
		{
		    final AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
		    try
		    {
		        sigs[i] = createSignature(sigAlg, publicKey);
		    }
		    catch (final Exception e)
		    {
		        sigs[i] = null;
		        // continue
		    }
		}

		return new CompositeVerifier(sigs);
    }

    Signature createSignature(final AlgorithmIdentifier algorithm, final PublicKey publicKey)
        throws OperatorCreationException
    {
        try
        {
            final Signature sig = helper.createSignature(algorithm);

            sig.initVerify(publicKey);

            return sig;
        }
        catch (final GeneralSecurityException e)
        {
            throw new OperatorCreationException("exception on setup: " + e, e); //$NON-NLS-1$
        }
    }

    Signature createRawSig(final AlgorithmIdentifier algorithm, final PublicKey publicKey)
    {
        Signature rawSig;
        try
        {
            rawSig = helper.createRawSignature(algorithm);

            if (rawSig != null)
            {
                rawSig.initVerify(publicKey);
            }
        }
        catch (final Exception e)
        {
            rawSig = null;
        }
        return rawSig;
    }

    private static class SigVerifier
        implements ContentVerifier
    {
        private final AlgorithmIdentifier algorithm;
        private final Signature signature;

        protected final OutputStream stream;

        SigVerifier(final AlgorithmIdentifier algorithm, final Signature signature)
        {
            this.algorithm = algorithm;
            this.signature = signature;
            stream = OutputStreamFactory.createStream(signature);
        }

        @Override
		public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithm;
        }

        @Override
		public OutputStream getOutputStream()
        {
            if (stream == null)
            {
                throw new IllegalStateException("verifier not initialised"); //$NON-NLS-1$
            }

            return stream;
        }

        @Override
		public boolean verify(final byte[] expected)
        {
            try
            {
                return signature.verify(expected);
            }
            catch (final SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e); //$NON-NLS-1$
            }
        }
    }

    private class RawSigVerifier
        extends SigVerifier
        implements RawContentVerifier
    {
        private final Signature rawSignature;

        RawSigVerifier(final AlgorithmIdentifier algorithm, final Signature standardSig, final Signature rawSignature)
        {
            super(algorithm, standardSig);
            this.rawSignature = rawSignature;
        }

        @Override
		public boolean verify(final byte[] expected)
        {
            try
            {
                return super.verify(expected);
            }
            finally
            {
                // we need to do this as in some PKCS11 implementations the session associated with the init of the
                // raw signature will not be freed if verify is not called on it.
                try
                {
                    rawSignature.verify(expected);
                }
                catch (final Exception e)
                {
                    // ignore
                }
            }
        }

        @Override
		public boolean verify(final byte[] digest, final byte[] expected)
        {
            try
            {
                rawSignature.update(digest);

                return rawSignature.verify(expected);
            }
            catch (final SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining raw signature: " + e.getMessage(), e); //$NON-NLS-1$
            }
            finally
            {
                // we need to do this as in some PKCS11 implementations the session associated with the init of the
                // standard signature will not be freed if verify is not called on it.
                try
                {
                    rawSignature.verify(expected);
                }
                catch (final Exception e)
                {
                    // ignore
                }
            }
        }
    }

    private static class CompositeVerifier
        implements ContentVerifier
    {
        private final Signature[] sigs;
        private OutputStream stream;

        public CompositeVerifier(final Signature[] sigs)
            throws OperatorCreationException
        {
            this.sigs = sigs;

            int start = 0;
            while (start < sigs.length && sigs[start] == null)
            {
                start++;
            }

            if (start == sigs.length)
            {
                throw new OperatorCreationException("no matching signature found in composite"); //$NON-NLS-1$
            }
            stream = OutputStreamFactory.createStream(sigs[start]);
            for (int i = start + 1; i != sigs.length; i++)
            {
                if (sigs[i] != null)
                {
                    stream = new TeeOutputStream(stream, OutputStreamFactory.createStream(sigs[i]));
                }
            }
        }

        @Override
		public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite);
        }

        @Override
		public OutputStream getOutputStream()
        {
            return stream;
        }

        @Override
		public boolean verify(final byte[] expected)
        {
            try
            {
                final ASN1Sequence sigSeq = ASN1Sequence.getInstance(expected);
                boolean failed = false;
                for (int i = 0; i != sigSeq.size(); i++)
                {
                    if (sigs[i] != null && !sigs[i].verify(DERBitString.getInstance(sigSeq.getObjectAt(i)).getBytes()))
					{
					    failed = true;
					}
                }
                return !failed;
            }
            catch (final SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e); //$NON-NLS-1$
            }
        }
    }
}