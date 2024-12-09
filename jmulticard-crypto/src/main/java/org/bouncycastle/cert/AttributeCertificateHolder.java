package org.bouncycastle.cert;

import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.ObjectDigestInfo;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;

/**
 * The Holder object.
 *
 * <pre>
 *          Holder ::= SEQUENCE {
 *                baseCertificateID   [0] IssuerSerial OPTIONAL,
 *                         -- the issuer and serial number of
 *                         -- the holder's Public Key Certificate
 *                entityName          [1] GeneralNames OPTIONAL,
 *                         -- the name of the claimant or role
 *                objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
 *                         -- used to directly authenticate the holder,
 *                         -- for example, an executable
 *          }
 * </pre>
 * <p>
 * <b>Note:</b> If objectDigestInfo comparisons are to be carried out the static
 * method setDigestCalculatorProvider <b>must</b> be called once to configure the class
 * to do the necessary calculations.
 * </p>
 */
public class AttributeCertificateHolder
    implements Selector
{
    private static DigestCalculatorProvider digestCalculatorProvider;

    final Holder holder;

    AttributeCertificateHolder(final ASN1Sequence seq)
    {
        this.holder = Holder.getInstance(seq);
    }

    /**
     * Create a holder using the baseCertificateID element.
     *
     * @param issuerName name of associated certificate's issuer.
     * @param serialNumber serial number of associated certificate.
     */
    public AttributeCertificateHolder(final X500Name issuerName,
        final BigInteger serialNumber)
    {
        this.holder = new Holder(new IssuerSerial(
            generateGeneralNames(issuerName),
            new ASN1Integer(serialNumber)));
    }

    /**
     * Create a holder using the baseCertificateID option based on the passed in associated certificate,
     *
     * @param cert the certificate to be associated with this holder.
     */
    public AttributeCertificateHolder(final X509CertificateHolder cert)
    {
        this.holder = new Holder(new IssuerSerial(generateGeneralNames(cert.getIssuer()),
            new ASN1Integer(cert.getSerialNumber())));
    }

    /**
     * Create a holder using the entityName option based on the passed in principal.
     *
     * @param principal the entityName to be associated with the attribute certificate.
     */
    public AttributeCertificateHolder(final X500Name principal)
    {
        this.holder = new Holder(generateGeneralNames(principal));
    }

    /**
     * Constructs a holder for v2 attribute certificates with a hash value for
     * some type of object.
     * <p>
     * <code>digestedObjectType</code> can be one of the following:
     * <ul>
     * <li>0 - publicKey - A hash of the public key of the holder must be
     * passed.
     * <li>1 - publicKeyCert - A hash of the public key certificate of the
     * holder must be passed.
     * <li>2 - otherObjectDigest - A hash of some other object type must be
     * passed. <code>otherObjectTypeID</code> must not be empty.
     * </ul>
     * <p>
     * This cannot be used if a v1 attribute certificate is used.
     *
     * @param digestedObjectType The digest object type.
     * @param digestAlgorithm The algorithm identifier for the hash.
     * @param otherObjectTypeID The object type ID if
     *            <code>digestedObjectType</code> is
     *            <code>otherObjectDigest</code>.
     * @param objectDigest The hash value.
     */
    public AttributeCertificateHolder(final int digestedObjectType,
        final ASN1ObjectIdentifier digestAlgorithm, final ASN1ObjectIdentifier otherObjectTypeID, final byte[] objectDigest)
    {
        this.holder = new Holder(new ObjectDigestInfo(digestedObjectType,
            otherObjectTypeID, new AlgorithmIdentifier(digestAlgorithm), Arrays
                .clone(objectDigest)));
    }

    /**
     * Returns the digest object type if an object digest info is used.
     * <ul>
     * <li>0 - publicKey - A hash of the public key of the holder must be
     * passed.
     * <li>1 - publicKeyCert - A hash of the public key certificate of the
     * holder must be passed.
     * <li>2 - otherObjectDigest - A hash of some other object type must be
     * passed. <code>otherObjectTypeID</code> must not be empty.
     * </ul>
     *
     * @return The digest object type or -1 if no object digest info is set.
     */
    public int getDigestedObjectType()
    {
        if (this.holder.getObjectDigestInfo() != null)
        {
            return this.holder.getObjectDigestInfo().getDigestedObjectType().intValueExact();
        }
        return -1;
    }

    /**
     * Returns algorithm identifier for the digest used if ObjectDigestInfo is present.
     *
     * @return digest AlgorithmIdentifier or <code>null</code> if ObjectDigestInfo is absent.
     */
    public AlgorithmIdentifier getDigestAlgorithm()
    {
        if (this.holder.getObjectDigestInfo() != null)
        {
            return this.holder.getObjectDigestInfo().getDigestAlgorithm();
        }
        return null;
    }

    /**
     * Returns the hash if an object digest info is used.
     *
     * @return The hash or <code>null</code> if ObjectDigestInfo is absent.
     */
    public byte[] getObjectDigest()
    {
        if (this.holder.getObjectDigestInfo() != null)
        {
            return this.holder.getObjectDigestInfo().getObjectDigest().getBytes();
        }
        return null;
    }

    /**
     * Returns the digest algorithm ID if an object digest info is used.
     *
     * @return The digest algorithm ID or <code>null</code> if no object
     *         digest info is set.
     */
    public ASN1ObjectIdentifier getOtherObjectTypeID()
    {
        if (this.holder.getObjectDigestInfo() != null)
        {
            new ASN1ObjectIdentifier(this.holder.getObjectDigestInfo().getOtherObjectTypeID().getId());
        }
        return null;
    }

    private GeneralNames generateGeneralNames(final X500Name principal)
    {
        return new GeneralNames(new GeneralName(principal));
    }

    private boolean matchesDN(final X500Name subject, final GeneralNames targets)
    {
        final GeneralName[] names = targets.getNames();

        for (int i = 0; i != names.length; i++)
        {
            final GeneralName gn = names[i];

            if (gn.getTagNo() == GeneralName.directoryName)
            {
                if (X500Name.getInstance(gn.getName()).equals(subject))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private X500Name[] getPrincipals(final GeneralName[] names)
    {
        final List l = new ArrayList(names.length);

        for (int i = 0; i != names.length; i++)
        {
            if (names[i].getTagNo() == GeneralName.directoryName)
            {
                l.add(X500Name.getInstance(names[i].getName()));
            }
        }

        return (X500Name[])l.toArray(new X500Name[l.size()]);
    }

    /**
     * Return any principal objects inside the attribute certificate holder
     * entity names field.
     *
     * @return an array of Principal objects (usually X500Principal), null if no
     *         entity names field is set.
     */
    public X500Name[] getEntityNames()
    {
        if (this.holder.getEntityName() != null)
        {
            return getPrincipals(this.holder.getEntityName().getNames());
        }

        return null;
    }

    /**
     * Return the principals associated with the issuer attached to this holder
     *
     * @return an array of principals, null if no BaseCertificateID is set.
     */
    public X500Name[] getIssuer()
    {
        if (this.holder.getBaseCertificateID() != null)
        {
            return getPrincipals(this.holder.getBaseCertificateID().getIssuer().getNames());
        }

        return null;
    }

    /**
     * Return the serial number associated with the issuer attached to this
     * holder.
     *
     * @return the certificate serial number, null if no BaseCertificateID is
     *         set.
     */
    public BigInteger getSerialNumber()
    {
        if (this.holder.getBaseCertificateID() != null)
        {
            return this.holder.getBaseCertificateID().getSerial().getValue();
        }

        return null;
    }

    @Override
	public Object clone()
    {
        return new AttributeCertificateHolder((ASN1Sequence)this.holder.toASN1Primitive());
    }

    @Override
	public boolean match(final Object obj)
    {
        if (!(obj instanceof X509CertificateHolder))
        {
            return false;
        }

        final X509CertificateHolder x509Cert = (X509CertificateHolder)obj;

        if (this.holder.getBaseCertificateID() != null)
        {
            return this.holder.getBaseCertificateID().getSerial().hasValue(x509Cert.getSerialNumber())
                && matchesDN(x509Cert.getIssuer(), this.holder.getBaseCertificateID().getIssuer());
        }

        if (this.holder.getEntityName() != null)
        {
            if (matchesDN(x509Cert.getSubject(),
                this.holder.getEntityName()))
            {
                return true;
            }
        }

        if (this.holder.getObjectDigestInfo() != null)
        {
            try
            {
                final DigestCalculator digCalc = digestCalculatorProvider.get(this.holder.getObjectDigestInfo().getDigestAlgorithm());
                final OutputStream     digOut = digCalc.getOutputStream();

                switch (getDigestedObjectType())
                {
                case ObjectDigestInfo.publicKey:
                    // TODO: DSA Dss-parms
                    digOut.write(x509Cert.getSubjectPublicKeyInfo().getEncoded());
                    break;
                case ObjectDigestInfo.publicKeyCert:
                    digOut.write(x509Cert.getEncoded());
                    break;
                }

                digOut.close();

                if (!Arrays.areEqual(digCalc.getDigest(), getObjectDigest()))
                {
                    return false;
                }
            }
            catch (final Exception e)
            {
                return false;
            }
        }

        return false;
    }

    @Override
	public boolean equals(final Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof AttributeCertificateHolder))
        {
            return false;
        }

        final AttributeCertificateHolder other = (AttributeCertificateHolder)obj;

        return this.holder.equals(other.holder);
    }

    @Override
	public int hashCode()
    {
        return this.holder.hashCode();
    }

    /**
     * Set a digest calculator provider to be used if matches are attempted using
     * ObjectDigestInfo,
     *
     * @param digCalcProvider a provider of digest calculators.
     */
    public static void setDigestCalculatorProvider(final DigestCalculatorProvider digCalcProvider)
    {
        digestCalculatorProvider = digCalcProvider;
    }
}
