package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.Record;

/** Objeto PKCS#15 ODF (<i>Object Description File</i>) ASN&#46;1.
 * Su estructura general es una repetici&oacute;n de registros de tipo <code>PKCS15Objects</code>:
 * <pre>
 * PKCS15Objects ::= CHOICE {
 *   privateKeys         [0] PrivateKeys,
 *   publicKeys          [1] PublicKeys,
 *   trustedPublicKeys   [2] PublicKeys,
 *   secretKeys          [3] SecretKeys,
 *   certificates        [4] Certificates,
 *   trustedCertificates [5] Certificates,
 *   usefulCertificates  [6] Certificates,
 *   dataObjects         [7] DataObjects,
 *   authObjects         [8] AuthObjects,
 *   ... -- For future extensions
 * }
 *
 * PrivateKeys  ::= PathOrObjects {PrivateKeyType}
 * SecretKeys   ::= PathOrObjects {SecretKeyType}
 * PublicKeys   ::= PathOrObjects {PublicKeyType}
 * Certificates ::= PathOrObjects {CertificateType}
 * DataObjects  ::= PathOrObjects {DataType}
 * AuthObjects  ::= PathOrObjects {AuthenticationType}
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Odf extends Record {

	/** Construye un objeto PKCS#15 ODF (<i>Object Description File</i>) ASN&#46;1. */
	public Odf() {
		super(
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(PrivateKeysContextSpecific.class, true),
				new OptionalDecoderObjectElement(PublicKeysContextSpecific.class, true),
				//new OptionalDecoderObjectElement(TrustedPublicKeysContextSpecific.class, true),
				new OptionalDecoderObjectElement(SecretKeysContextSpecific.class, true),
				new OptionalDecoderObjectElement(CertificatesContextSpecific.class, true)
			}
		);
	}

	/** Obtiene la ruta (Path ASN&#46;1 PKCS#15) hacia los certificados.
	 * @return Ruta (Path ASN&#46;1 PKCS#15) hacia los certificados, o <code>null</code>
	 *         si este ODF no contiene esta ruta. */
	public Path getCertificatesPath() {
		for (int i=0;i<getElementCount();i++) {
			final DecoderObject dobj = getElementAt(i);
			if (dobj instanceof CertificatesContextSpecific) {
				return ((CertificatesContextSpecific)dobj).getCertificatesPath();
			}
		}
		return null;
	}

}
