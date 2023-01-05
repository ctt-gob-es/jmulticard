package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeInputStream;
import org.bouncycastle.util.io.TeeOutputStream;

class CMSUtils
{
    private static final Set<String> des = new HashSet<>();
    private static final Set mqvAlgs = new HashSet();
    private static final Set ecAlgs = new HashSet();
    private static final Set gostAlgs = new HashSet();

    static
    {
        des.add("DES");
        des.add("DESEDE");
        des.add(OIWObjectIdentifiers.desCBC.getId());
        des.add(PKCSObjectIdentifiers.des_EDE3_CBC.getId());
        des.add(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId());

        mqvAlgs.add(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme);

        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme);
        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme);

        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);
    }

    static boolean isMQV(final ASN1ObjectIdentifier algorithm)
    {
        return mqvAlgs.contains(algorithm);
    }

    static boolean isEC(final ASN1ObjectIdentifier algorithm)
    {
        return ecAlgs.contains(algorithm);
    }

    static boolean isGOST(final ASN1ObjectIdentifier algorithm)
    {
        return gostAlgs.contains(algorithm);
    }

    static boolean isRFC2631(final ASN1ObjectIdentifier algorithm)
    {
        return algorithm.equals(PKCSObjectIdentifiers.id_alg_ESDH) || algorithm.equals(PKCSObjectIdentifiers.id_alg_SSDH);
    }

    static boolean isDES(final String algorithmID)
    {
        final String name = Strings.toUpperCase(algorithmID);

        return des.contains(name);
    }

    static boolean isEquivalent(final AlgorithmIdentifier algId1, final AlgorithmIdentifier algId2)
    {
        if (algId1 == null || algId2 == null || !algId1.getAlgorithm().equals(algId2.getAlgorithm()))
        {
            return false;
        }

        final ASN1Encodable params1 = algId1.getParameters();
        final ASN1Encodable params2 = algId2.getParameters();
        if (params1 != null)
        {
            return params1.equals(params2) || params1.equals(DERNull.INSTANCE) && params2 == null;
        }

        return params2 == null || params2.equals(DERNull.INSTANCE);
    }

    static ContentInfo readContentInfo(
        final byte[] input)
        throws CMSException
    {
        // enforce limit checking as from a byte array
        return readContentInfo(new ASN1InputStream(input));
    }

    static ContentInfo readContentInfo(
        final InputStream input)
        throws CMSException
    {
        // enforce some limit checking
        return readContentInfo(new ASN1InputStream(input));
    }

    static ASN1Set convertToDlSet(final Set<AlgorithmIdentifier> digestAlgs)
    {
        return new DLSet(digestAlgs.toArray(new AlgorithmIdentifier[digestAlgs.size()]));
    }

    static void addDigestAlgs(final Set<AlgorithmIdentifier> digestAlgs, final SignerInformation signer, final DigestAlgorithmIdentifierFinder dgstAlgFinder)
    {
        digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(signer.getDigestAlgorithmID(), dgstAlgFinder));
        final SignerInformationStore counterSignaturesStore = signer.getCounterSignatures();
        final Iterator<SignerInformation> counterSignatureIt = counterSignaturesStore.iterator();
        while (counterSignatureIt.hasNext())
        {
            final SignerInformation counterSigner = counterSignatureIt.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixDigestAlgID(counterSigner.getDigestAlgorithmID(), dgstAlgFinder));
        }
    }

    static List getCertificatesFromStore(final Store certStore)
        throws CMSException
    {
        final List certs = new ArrayList();

        try
        {
            for (final Object element : certStore.getMatches(null)) {
                final X509CertificateHolder c = (X509CertificateHolder)element;

                certs.add(c.toASN1Structure());
            }

            return certs;
        }
        catch (final ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }

    static List getAttributeCertificatesFromStore(final Store attrStore)
        throws CMSException
    {
        final List certs = new ArrayList();

        try
        {
            for (final Object element : attrStore.getMatches(null)) {
                final X509AttributeCertificateHolder attrCert = (X509AttributeCertificateHolder)element;

                certs.add(new DERTaggedObject(false, 2, attrCert.toASN1Structure()));
            }

            return certs;
        }
        catch (final ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }


    static List getCRLsFromStore(final Store crlStore)
        throws CMSException
    {
        final List crls = new ArrayList();

        try
        {
            for (final Object rev : crlStore.getMatches(null)) {
                if (rev instanceof X509CRLHolder)
                {
                    final X509CRLHolder c = (X509CRLHolder)rev;

                    crls.add(c.toASN1Structure());
                }
                else if (rev instanceof OtherRevocationInfoFormat)
                {
                    final OtherRevocationInfoFormat infoFormat = OtherRevocationInfoFormat.getInstance(rev);

                    validateInfoFormat(infoFormat);

                    crls.add(new DERTaggedObject(false, 1, infoFormat));
                }
                else if (rev instanceof ASN1TaggedObject)
                {
                    crls.add(rev);
                }
            }

            return crls;
        }
        catch (final ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }

    private static void validateInfoFormat(final OtherRevocationInfoFormat infoFormat)
    {
        if (CMSObjectIdentifiers.id_ri_ocsp_response.equals(infoFormat.getInfoFormat()))
        {
            final OCSPResponse resp = OCSPResponse.getInstance(infoFormat.getInfo());

            if (OCSPResponseStatus.SUCCESSFUL != resp.getResponseStatus().getIntValue())
            {
                throw new IllegalArgumentException("cannot add unsuccessful OCSP response to CMS SignedData");
            }
        }
    }

    static Collection getOthersFromStore(final ASN1ObjectIdentifier otherRevocationInfoFormat, final Store otherRevocationInfos)
    {
        final List others = new ArrayList();

        for (final Object element : otherRevocationInfos.getMatches(null)) {
            final ASN1Encodable info = (ASN1Encodable)element;
            final OtherRevocationInfoFormat infoFormat = new OtherRevocationInfoFormat(otherRevocationInfoFormat, info);

            validateInfoFormat(infoFormat);

            others.add(new DERTaggedObject(false, 1, infoFormat));
        }

        return others;
    }

    static ASN1Set createBerSetFromList(final List derObjects)
    {
        final ASN1EncodableVector v = new ASN1EncodableVector();

        for (final Object derObject : derObjects) {
            v.add((ASN1Encodable)derObject);
        }

        return new BERSet(v);
    }

    static ASN1Set createDlSetFromList(final List derObjects)
    {
        final ASN1EncodableVector v = new ASN1EncodableVector();

        for (final Object derObject : derObjects) {
            v.add((ASN1Encodable)derObject);
        }

        return new DLSet(v);
    }

    static ASN1Set createDerSetFromList(final List derObjects)
    {
        final ASN1EncodableVector v = new ASN1EncodableVector();

        for (final Object derObject : derObjects) {
            v.add((ASN1Encodable)derObject);
        }

        return new DERSet(v);
    }

    static OutputStream createBEROctetOutputStream(final OutputStream s,
                                                   final int tagNo, final boolean isExplicit, final int bufferSize)
        throws IOException
    {
        final BEROctetStringGenerator octGen = new BEROctetStringGenerator(s, tagNo, isExplicit);

        if (bufferSize != 0)
        {
            return octGen.getOctetOutputStream(new byte[bufferSize]);
        }

        return octGen.getOctetOutputStream();
    }

    private static ContentInfo readContentInfo(
        final ASN1InputStream in)
        throws CMSException
    {
        try
        {
            final ContentInfo info = ContentInfo.getInstance(in.readObject());
            if (info == null)
            {
                throw new CMSException("No content found.");
            }

            return info;
        }
        catch (final IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
        catch (final ClassCastException | IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    public static byte[] streamToByteArray(
        final InputStream in)
        throws IOException
    {
        return Streams.readAll(in);
    }

    public static byte[] streamToByteArray(
        final InputStream in,
        final int limit)
        throws IOException
    {
        return Streams.readAllLimited(in, limit);
    }

    static InputStream attachDigestsToInputStream(final Collection digests, final InputStream s)
    {
        InputStream result = s;
        final Iterator it = digests.iterator();
        while (it.hasNext())
        {
            final DigestCalculator digest = (DigestCalculator)it.next();
            result = new TeeInputStream(result, digest.getOutputStream());
        }
        return result;
    }

    static OutputStream attachSignersToOutputStream(final Collection signers, final OutputStream s)
    {
        OutputStream result = s;
        final Iterator it = signers.iterator();
        while (it.hasNext())
        {
            final SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            result = getSafeTeeOutputStream(result, signerGen.getCalculatingOutputStream());
        }
        return result;
    }

    static OutputStream getSafeOutputStream(final OutputStream s)
    {
        return s == null ? new NullOutputStream() : s;
    }

    static OutputStream getSafeTeeOutputStream(final OutputStream s1,
                                               final OutputStream s2)
    {
        return s1 == null ? getSafeOutputStream(s2)
            : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
            s1, s2);
    }
}
