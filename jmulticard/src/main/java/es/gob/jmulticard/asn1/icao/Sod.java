package es.gob.jmulticard.asn1.icao;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.icao.DataGroupHash;
import org.spongycastle.asn1.icao.LDSSecurityObject;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.spongycastle.cms.SignerId;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationVerifier;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.bc.BcDigestCalculatorProvider;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.util.Selector;
import org.spongycastle.util.Store;

import es.gob.jmulticard.CertificateUtils;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;

/** SOD de ICAO 9303.
 * La implementaci&oacute;n interna se apoya en BouncyCastle.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Sod extends DecoderObject {

	private static final byte TAG = 0x77;

	private byte[] ldsSecurityObjectBytes = null;
	private LDSSecurityObject ldsSecurityObject = null;
	private X509Certificate[] certificateChain = null;

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		final Tlv tlv = new Tlv(getRawDerValue());
		checkTag(tlv.getTag());
	}

	/** Valida la firma electr&oacute;nica del SOD.
	 * @throws SodException Si el SOD es estructuralmente incorrecto o su firma
	 *                      electr&oacute;nica es inv&aacute;lida.
	 * @throws TlvException Si el SOD no es un TLV correctamente formado. */
	public void validateSignature() throws SodException, TlvException {
		final Tlv tlv = new Tlv(getRawDerValue());

		final CMSSignedData cmsSignedData;
		try {
			cmsSignedData = new CMSSignedData(tlv.getValue());
		}
		catch (final CMSException e2) {
			throw new SodException("El SOD no estaba firmado: " + e2, e2); //$NON-NLS-1$
		}
		final Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
		final List<X509Certificate> certChain = new ArrayList<>();
		for (final SignerInformation si : cmsSignedData.getSignerInfos().getSigners()) {
			final Iterator<X509CertificateHolder> certIt = store.getMatches(
				new CertHolderBySignerIdSelector(si.getSID())
			).iterator();
			final X509Certificate cert;
            try {
				cert = CertificateUtils.generateCertificate(certIt.next().getEncoded());
			}
            catch (final CertificateException | IOException e1) {
            	throw new SodIncorrectCertificateException(
					"El SignedData contiene un certificado en formato incorrecto: " + e1, e1//$NON-NLS-1$
				);
			}
            try {
				cert.checkValidity();
			}
            catch (final CertificateExpiredException | CertificateNotYetValidException e1) {
            	throw new SodInvalidCertificateException(
					"El SignedData contiene un certificado fuera de su periodo temporal de validez: " + e1, e1 //$NON-NLS-1$
				);
			}
			try {
				if (
					!si.verify(
						new SignerInformationVerifier(
							new	DefaultCMSSignatureAlgorithmNameGenerator(),
							new DefaultSignatureAlgorithmIdentifierFinder(),
							new JcaContentVerifierProviderBuilder().setProvider(
								new BouncyCastleProvider()
							).build(cert),
							new BcDigestCalculatorProvider()
						)
					)
				) {
					throw new SodInvalidSignatureException("Firma del SOD no valida"); //$NON-NLS-1$
				}
			}
			catch (final Exception e) {
				throw new SodInvalidSignatureException(
					"No se ha podido comprobar la firma del SOD: " + e, e //$NON-NLS-1$
				);
			}
            certChain.add(cert);
		}
		this.certificateChain = certChain.toArray(new X509Certificate[certChain.size()]);

		this.ldsSecurityObjectBytes = (byte[]) cmsSignedData.getSignedContent().getContent();
		try (
			final ASN1InputStream is = new ASN1InputStream(this.ldsSecurityObjectBytes)
		) {
			this.ldsSecurityObject = LDSSecurityObject.getInstance(is.readObject());
		}
		catch (final IOException e1) {
			throw new SodException(
				"El SignedData del SOD no contenia un LDSSecurityObject: " + e1 //$NON-NLS-1$
			);
		}
	}

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

	/** Obtiene la codificaci&oacute;n binaria del LDSSecurityObject.
	 * La obtenci&oacute;n desencadena una validaci&oacute;n de la firma
	 * electr&oacute;nica del SOD.
	 * @return Codificaci&oacute;n binaria del LDSSecurityObject.
	 * @throws TlvException Si el SOD del documento no es un TLV v&aacute;lido.
     * @throws SodException Si el SOD es estructuralmente incorrecto. */
	public byte[] getLdsSecurityObjectBytes() throws SodException, TlvException {
		if (this.ldsSecurityObjectBytes == null) {
			validateSignature();
		}
		return this.ldsSecurityObjectBytes;
	}

	/** Obtiene el LDSSecurityObject.
	 * La obtenci&oacute;n desencadena una validaci&oacute;n de la firma
	 * electr&oacute;nica del SOD.
	 * @return LDSSecurityObject.
	 * @throws TlvException Si el SOD del documento no es un TLV v&aacute;lido.
     * @throws SodException Si el SOD es estructuralmente incorrecto. */
	public LDSSecurityObject getLdsSecurityObject() throws SodException, TlvException {
		if (this.ldsSecurityObject == null) {
			validateSignature();
		}
		return this.ldsSecurityObject;
	}

	/** Obtiene la cadena de certificados del firmante del LDSSecurityObject.
	 * La obtenci&oacute;n desencadena una validaci&oacute;n de la firma
	 * electr&oacute;nica del SOD.
	 * @return Cadena de certificados del firmante del LDSSecurityObject.
	 * @throws TlvException Si el SOD del documento no es un TLV v&aacute;lido.
     * @throws SodException Si el SOD es estructuralmente incorrecto. */
	public X509Certificate[] getCertificateChain() throws SodException, TlvException {
		if (this.certificateChain == null) {
			validateSignature();
		}
		return this.certificateChain.clone();
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("SOD ICAO\n"); //$NON-NLS-1$
		try {
			sb.append(
				"Firmado por: " + getCertificateChain()[0].getSubjectX500Principal() //$NON-NLS-1$
			);
		}
		catch (final Exception e) {
			return sb.toString();
		}
		sb.append("\n  Con huellas para los siguientes grupos de datos\n"); //$NON-NLS-1$

		for (final DataGroupHash dgh : this.ldsSecurityObject.getDatagroupHash()) {
			sb.append("    DG"); //$NON-NLS-1$
			sb.append(dgh.getDataGroupNumber());
			sb.append(" = "); //$NON-NLS-1$
			sb.append(HexUtils.hexify(dgh.getDataGroupHashValue().getOctets(), false));
			sb.append('\n');
		}

		return sb.toString();
	}

	/** Selector interno para la lectura de los certificados del firmante del SOD. */
	private static final class CertHolderBySignerIdSelector implements Selector<X509CertificateHolder> {

		private final SignerId signerId;

		CertHolderBySignerIdSelector(final SignerId sid) {
			if (sid == null) {
				throw new IllegalArgumentException("El ID del firmante no puede ser nulo"); //$NON-NLS-1$
			}
			this.signerId = sid;
		}

		@Override
		public boolean match(final X509CertificateHolder o) {
			return CertHolderBySignerIdSelector.this.signerId.getSerialNumber().equals(
				o.getSerialNumber()
			);
		}

		@Override
		public Object clone() {
			throw new UnsupportedOperationException();
		}

	}

}
