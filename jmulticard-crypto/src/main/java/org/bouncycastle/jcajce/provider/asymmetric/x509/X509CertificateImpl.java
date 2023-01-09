package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

abstract class X509CertificateImpl
    extends X509Certificate
    implements BCX509Certificate
{
    protected JcaJceHelper bcHelper;
    protected org.bouncycastle.asn1.x509.Certificate c;
    protected BasicConstraints basicConstraints;
    protected boolean[] keyUsage;
    protected String sigAlgName;
    protected byte[] sigAlgParams;

    X509CertificateImpl(final JcaJceHelper bcHelper, final org.bouncycastle.asn1.x509.Certificate c,
        final BasicConstraints basicConstraints, final boolean[] keyUsage, final String sigAlgName, final byte[] sigAlgParams)
    {
        this.bcHelper = bcHelper;
        this.c = c;
        this.basicConstraints = basicConstraints;
        this.keyUsage = keyUsage;
        this.sigAlgName = sigAlgName;
        this.sigAlgParams = sigAlgParams;
    }

    @Override
	public X500Name getIssuerX500Name()
    {
        return c.getIssuer();
    }

    @Override
	public TBSCertificate getTBSCertificateNative()
    {
        return c.getTBSCertificate();
    }

    @Override
	public X500Name getSubjectX500Name()
    {
        return c.getSubject();
    }

    @Override
	public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        this.checkValidity(new Date());
    }

    @Override
	public void checkValidity(
        final Date    date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        if (date.getTime() > this.getNotAfter().getTime())  // for other VM compatibility
        {
            throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
        }

        if (date.getTime() < this.getNotBefore().getTime())
        {
            throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
        }
    }

    @Override
	public int getVersion()
    {
        return c.getVersionNumber();
    }

    @Override
	public BigInteger getSerialNumber()
    {
        return c.getSerialNumber().getValue();
    }

    @Override
	public Principal getIssuerDN()
    {
        return new X509Principal(c.getIssuer());
    }

    @Override
	public X500Principal getIssuerX500Principal()
    {
        try
        {
            final byte[] encoding = c.getIssuer().getEncoded(ASN1Encoding.DER);

            return new X500Principal(encoding);
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    @Override
	public Principal getSubjectDN()
    {
        return new X509Principal(c.getSubject());
    }

    @Override
	public X500Principal getSubjectX500Principal()
    {
        try
        {
            final byte[] encoding = c.getSubject().getEncoded(ASN1Encoding.DER);

            return new X500Principal(encoding);
        }
        catch (final IOException e)
        {
            throw new IllegalStateException("can't encode subject DN");
        }
    }

    @Override
	public Date getNotBefore()
    {
        return c.getStartDate().getDate();
    }

    @Override
	public Date getNotAfter()
    {
        return c.getEndDate().getDate();
    }

    @Override
	public byte[] getTBSCertificate()
        throws CertificateEncodingException
    {
        try
        {
            return c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
        }
        catch (final IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    @Override
	public byte[] getSignature()
    {
        return c.getSignature().getOctets();
    }

    /**
     * return a more "meaningful" representation for the signature algorithm used in
     * the certificate.
     */
    @Override
	public String getSigAlgName()
    {
        return sigAlgName;
    }

    /**
     * return the object identifier for the signature.
     */
    @Override
	public String getSigAlgOID()
    {
        return c.getSignatureAlgorithm().getAlgorithm().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    @Override
	public byte[] getSigAlgParams()
    {
        return Arrays.clone(sigAlgParams);
    }

    @Override
	public boolean[] getIssuerUniqueID()
    {
        final ASN1BitString    id = c.getTBSCertificate().getIssuerUniqueId();

        if (id != null)
        {
            final byte[]          bytes = id.getBytes();
            final boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & 0x80 >>> i % 8) != 0;
            }

            return boolId;
        }

        return null;
    }

    @Override
	public boolean[] getSubjectUniqueID()
    {
        final ASN1BitString id = c.getTBSCertificate().getSubjectUniqueId();

        if (id != null)
        {
            final byte[]          bytes = id.getBytes();
            final boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & 0x80 >>> i % 8) != 0;
            }

            return boolId;
        }

        return null;
    }

    @Override
	public boolean[] getKeyUsage()
    {
        return Arrays.clone(keyUsage);
    }

    @Override
	public List getExtendedKeyUsage()
        throws CertificateParsingException
    {
        final byte[] extOctets = getExtensionOctets(c, "2.5.29.37");
        if (null == extOctets)
        {
            return null;
        }

        try
        {
            final ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extOctets));

            final List list = new ArrayList();
            for (int i = 0; i != seq.size(); i++)
            {
                list.add(((ASN1ObjectIdentifier)seq.getObjectAt(i)).getId());
            }
            return Collections.unmodifiableList(list);
        }
        catch (final Exception e)
        {
            throw new CertificateParsingException("error processing extended key usage extension");
        }
    }

    @Override
	public int getBasicConstraints()
    {
        if (basicConstraints != null)
        {
            if (basicConstraints.isCA())
            {
                if (basicConstraints.getPathLenConstraint() == null)
                {
                    return Integer.MAX_VALUE;
                }
                else
                {
                    return basicConstraints.getPathLenConstraint().intValue();
                }
            }
            else
            {
            }
        }

        return -1;
    }

    @Override
	public Collection getSubjectAlternativeNames()
        throws CertificateParsingException
    {
        return getAlternativeNames(c, Extension.subjectAlternativeName.getId());
    }

    @Override
	public Collection getIssuerAlternativeNames()
        throws CertificateParsingException
    {
        return getAlternativeNames(c, Extension.issuerAlternativeName.getId());
    }

    @Override
	public Set getCriticalExtensionOIDs()
    {
        if (this.getVersion() == 3)
        {
            final Set             set = new HashSet();
            final Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                final Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    final Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    @Override
	public byte[] getExtensionValue(final String oid)
    {
        final ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue)
        {
            try
            {
                return extValue.getEncoded();
            }
            catch (final Exception e)
            {
                throw new IllegalStateException("error parsing " + e.toString());
            }
        }

        return null;
    }

    @Override
	public Set getNonCriticalExtensionOIDs()
    {
        if (this.getVersion() == 3)
        {
            final Set             set = new HashSet();
            final Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                final Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    final Extension       ext = extensions.getExtension(oid);

                    if (!ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    @Override
	public boolean hasUnsupportedCriticalExtension()
    {
        if (this.getVersion() == 3)
        {
            final Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                final Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

                    if (oid.equals(Extension.keyUsage)
                     || oid.equals(Extension.certificatePolicies)
                     || oid.equals(Extension.policyMappings)
                     || oid.equals(Extension.inhibitAnyPolicy)
                     || oid.equals(Extension.cRLDistributionPoints)
                     || oid.equals(Extension.issuingDistributionPoint)
                     || oid.equals(Extension.deltaCRLIndicator)
                     || oid.equals(Extension.policyConstraints)
                     || oid.equals(Extension.basicConstraints)
                     || oid.equals(Extension.subjectAlternativeName)
                     || oid.equals(Extension.nameConstraints))
                    {
                        continue;
                    }

                    final Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    @Override
	public PublicKey getPublicKey()
    {
        try
        {
            return BouncyCastleProvider.getPublicKey(c.getSubjectPublicKeyInfo());
        }
        catch (final IOException e)
        {
            return null;   // should never happen...
        }
    }

    @Override
	public String toString()
    {
        final StringBuffer    buf = new StringBuffer();
        final String          nl = Strings.lineSeparator();

        buf.append("  [0]         Version: ").append(this.getVersion()).append(nl);
        buf.append("         SerialNumber: ").append(this.getSerialNumber()).append(nl);
        buf.append("             IssuerDN: ").append(this.getIssuerDN()).append(nl);
        buf.append("           Start Date: ").append(this.getNotBefore()).append(nl);
        buf.append("           Final Date: ").append(this.getNotAfter()).append(nl);
        buf.append("            SubjectDN: ").append(this.getSubjectDN()).append(nl);
        buf.append("           Public Key: ").append(this.getPublicKey()).append(nl);
        buf.append("  Signature Algorithm: ").append(this.getSigAlgName()).append(nl);

        X509SignatureUtil.prettyPrintSignature(this.getSignature(), buf, nl);

        final Extensions extensions = c.getTBSCertificate().getExtensions();

        if (extensions != null)
        {
            final Enumeration     e = extensions.oids();

            if (e.hasMoreElements())
            {
                buf.append("       Extensions: \n");
            }

            while (e.hasMoreElements())
            {
                final ASN1ObjectIdentifier     oid = (ASN1ObjectIdentifier)e.nextElement();
                final Extension ext = extensions.getExtension(oid);

                if (ext.getExtnValue() != null)
                {
                    final byte[]                  octs = ext.getExtnValue().getOctets();
                    final ASN1InputStream         dIn = new ASN1InputStream(octs);
                    buf.append("                       critical(").append(ext.isCritical()).append(") ");
                    try
                    {
                        if (oid.equals(Extension.basicConstraints))
                        {
                            buf.append(BasicConstraints.getInstance(dIn.readObject())).append(nl);
                        }
                        else if (oid.equals(Extension.keyUsage))
                        {
                            buf.append(KeyUsage.getInstance(dIn.readObject())).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeCertType))
                        {
                            buf.append(new NetscapeCertType(DERBitString.getInstance(dIn.readObject()))).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeRevocationURL))
                        {
                            buf.append(new NetscapeRevocationURL(ASN1IA5String.getInstance(dIn.readObject()))).append(nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.verisignCzagExtension))
                        {
                            buf.append(new VerisignCzagExtension(ASN1IA5String.getInstance(dIn.readObject()))).append(nl);
                        }
                        else
                        {
                            buf.append(oid.getId());
                            buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
                            //buf.append(" value = ").append("*****").append(nl);
                        }
                    }
                    catch (final Exception ex)
                    {
                        buf.append(oid.getId());
                   //     buf.append(" value = ").append(new String(Hex.encode(ext.getExtnValue().getOctets()))).append(nl);
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }

        return buf.toString();
    }

    @Override
	public final void verify(
        final PublicKey   key)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        doVerify(key, new SignatureCreator()
        {
            @Override
			public Signature createSignature(final String sigName)
                throws NoSuchAlgorithmException
            {
                try
                {
                    return bcHelper.createSignature(sigName);
                }
                catch (final Exception e)
                {
                    return Signature.getInstance(sigName);
                }
            }
        });
    }

    @Override
	public final void verify(
        final PublicKey   key,
        final String      sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        doVerify(key, new SignatureCreator()
        {
            @Override
			public Signature createSignature(final String sigName)
                throws NoSuchAlgorithmException, NoSuchProviderException
            {
                if (sigProvider != null)
                {
                    return Signature.getInstance(sigName, sigProvider);
                }
                else
                {
                    return Signature.getInstance(sigName);
                }
            }
        });
    }

    @Override
	public final void verify(
        final PublicKey   key,
        final Provider sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException
    {
        try
        {
            doVerify(key, new SignatureCreator()
            {
                @Override
				public Signature createSignature(final String sigName)
                    throws NoSuchAlgorithmException
                {
                    if (sigProvider != null)
                    {
                        return Signature.getInstance(sigName, sigProvider);
                    }
                    else
                    {
                        return Signature.getInstance(sigName);
                    }
                }
            });
        }
        catch (final NoSuchProviderException e)
        {
            // can't happen, but just in case
            throw new NoSuchAlgorithmException("provider issue: " + e.getMessage());
        }
    }

    private void doVerify(
        final PublicKey key,
        final SignatureCreator signatureCreator)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, SignatureException, NoSuchProviderException
    {
        if (key instanceof CompositePublicKey && X509SignatureUtil.isCompositeAlgorithm(c.getSignatureAlgorithm()))
        {
            final List<PublicKey> pubKeys = ((CompositePublicKey)key).getPublicKeys();
            final ASN1Sequence keySeq = ASN1Sequence.getInstance(c.getSignatureAlgorithm().getParameters());
            final ASN1Sequence sigSeq = ASN1Sequence.getInstance(DERBitString.getInstance(c.getSignature()).getBytes());

            boolean success = false;
            for (int i = 0; i != pubKeys.size(); i++)
            {
                if (pubKeys.get(i) == null)
                {
                    continue;
                }
                final AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                final String sigName = X509SignatureUtil.getSignatureName(sigAlg);

                final Signature signature = signatureCreator.createSignature(sigName);

                SignatureException sigExc = null;

                try
                {
                    checkSignature(
                        pubKeys.get(i), signature,
                        sigAlg.getParameters(),
                        DERBitString.getInstance(sigSeq.getObjectAt(i)).getBytes());
                    success = true;
                }
                catch (final SignatureException e)
                {
                    sigExc = e;
                }

                if (sigExc != null)
                {
                    throw sigExc;
                }
            }

            if (!success)
            {
                throw new InvalidKeyException("no matching key found");
            }
        }
        else if (X509SignatureUtil.isCompositeAlgorithm(c.getSignatureAlgorithm()))
        {
            final ASN1Sequence keySeq = ASN1Sequence.getInstance(c.getSignatureAlgorithm().getParameters());
            final ASN1Sequence sigSeq = ASN1Sequence.getInstance(DERBitString.getInstance(c.getSignature()).getBytes());

            boolean success = false;
            for (int i = 0; i != sigSeq.size(); i++)
            {
                final AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                final String sigName = X509SignatureUtil.getSignatureName(sigAlg);

                SignatureException sigExc = null;

                try
                {
                    final Signature signature = signatureCreator.createSignature(sigName);

                    checkSignature(
                        key, signature,
                        sigAlg.getParameters(),
                        DERBitString.getInstance(sigSeq.getObjectAt(i)).getBytes());

                    success = true;
                }
                catch (final InvalidKeyException | NoSuchAlgorithmException e)
                {
                    // ignore
                }
                catch (final SignatureException e)
                {
                    sigExc = e;
                }

                if (sigExc != null)
                {
                    throw sigExc;
                }
            }

            if (!success)
            {
                throw new InvalidKeyException("no matching key found");
            }
        }
        else
        {
            final String sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());

            final Signature signature = signatureCreator.createSignature(sigName);

            if (key instanceof CompositePublicKey)
            {
                final List<PublicKey> keys = ((CompositePublicKey)key).getPublicKeys();

                for (final PublicKey key2 : keys) {
                    try
                    {
                        checkSignature(key2, signature,
                            c.getSignatureAlgorithm().getParameters(), this.getSignature());
                        return;     // found the match!
                    }
                    catch (final InvalidKeyException e)
                    {
                        // continue;
                    }
                }

                throw new InvalidKeyException("no matching signature found");
            }
            else
            {
                checkSignature(key, signature,
                    c.getSignatureAlgorithm().getParameters(), this.getSignature());
            }
        }
    }

    private void checkSignature(
        final PublicKey key,
        final Signature signature,
        final ASN1Encodable params,
        final byte[] sigBytes)
        throws CertificateException, NoSuchAlgorithmException,
            SignatureException, InvalidKeyException
    {
        if (!isAlgIdEqual(c.getSignatureAlgorithm(), c.getTBSCertificate().getSignature()))
        {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }

        // TODO This should go after the initVerify?
        X509SignatureUtil.setSignatureParameters(signature, params);

        signature.initVerify(key);

        try
        {
            final OutputStream sigOut = new BufferedOutputStream(OutputStreamFactory.createStream(signature), 512);

            c.getTBSCertificate().encodeTo(sigOut, ASN1Encoding.DER);

            sigOut.close();
        }
        catch (final IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }

        if (!signature.verify(sigBytes))
        {
            throw new SignatureException("certificate does not verify with supplied key");
        }
    }

    private boolean isAlgIdEqual(final AlgorithmIdentifier id1, final AlgorithmIdentifier id2)
    {
        if (!id1.getAlgorithm().equals(id2.getAlgorithm()))
        {
            return false;
        }

        if (Properties.isOverrideSet("org.bouncycastle.x509.allow_absent_equiv_NULL"))
        {
            if (id1.getParameters() == null)
            {
                if (id2.getParameters() != null && !id2.getParameters().equals(DERNull.INSTANCE))
                {
                    return false;
                }

                return true;
            }

            if (id2.getParameters() == null)
            {
                if (id1.getParameters() != null && !id1.getParameters().equals(DERNull.INSTANCE))
                {
                    return false;
                }

                return true;
            }
        }

        if (id1.getParameters() != null)
        {
            return id1.getParameters().equals(id2.getParameters());
        }

        if (id2.getParameters() != null)
        {
            return id2.getParameters().equals(id1.getParameters());
        }

        return true;
    }

    private static Collection getAlternativeNames(final org.bouncycastle.asn1.x509.Certificate c, final String oid)
        throws CertificateParsingException
    {
        final byte[] extOctets = getExtensionOctets(c, oid);
        if (extOctets == null)
        {
            return null;
        }
        try
        {
            final Collection temp = new ArrayList();
            final Enumeration it = ASN1Sequence.getInstance(extOctets).getObjects();
            while (it.hasMoreElements())
            {
                final GeneralName genName = GeneralName.getInstance(it.nextElement());
                final List list = new ArrayList();
                list.add(Integers.valueOf(genName.getTagNo()));
                switch (genName.getTagNo())
                {
                case GeneralName.ediPartyName:
                case GeneralName.x400Address:
                case GeneralName.otherName:
                    list.add(genName.getEncoded());
                    break;
                case GeneralName.directoryName:
                    list.add(X500Name.getInstance(RFC4519Style.INSTANCE, genName.getName()).toString());
                    break;
                case GeneralName.dNSName:
                case GeneralName.rfc822Name:
                case GeneralName.uniformResourceIdentifier:
                    list.add(((ASN1String)genName.getName()).getString());
                    break;
                case GeneralName.registeredID:
                    list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
                    break;
                case GeneralName.iPAddress:
                    final byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
                    final String addr;
                    try
                    {
                        addr = InetAddress.getByAddress(addrBytes).getHostAddress();
                    }
                    catch (final UnknownHostException e)
                    {
                        continue;
                    }
                    list.add(addr);
                    break;
                default:
                    throw new IOException("Bad tag number: " + genName.getTagNo());
                }

                temp.add(Collections.unmodifiableList(list));
            }
            if (temp.size() == 0)
            {
                return null;
            }
            return Collections.unmodifiableCollection(temp);
        }
        catch (final Exception e)
        {
            throw new CertificateParsingException(e.getMessage());
        }
    }

    protected static byte[] getExtensionOctets(final org.bouncycastle.asn1.x509.Certificate c, final String oid)
    {
        final ASN1OctetString extValue = getExtensionValue(c, oid);
        if (null != extValue)
        {
            return extValue.getOctets();
        }
        return null;
    }

    protected static ASN1OctetString getExtensionValue(final org.bouncycastle.asn1.x509.Certificate c, final String oid)
    {
        final Extensions exts = c.getTBSCertificate().getExtensions();
        if (null != exts)
        {
            final Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
            if (null != ext)
            {
                return ext.getExtnValue();
            }
        }
        return null;
    }
}
