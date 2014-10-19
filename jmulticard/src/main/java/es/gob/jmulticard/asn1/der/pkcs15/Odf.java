package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.Record;

/** Objeto PKCS#15 ODF (<i>Object Description File</i>) ASN.1.
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

	/** Construye un objeto PKCS#15 ODF (<i>Object Description File</i>) ASN.1. */
	public Odf() {
		super(
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(PrivateKeysContextSpecific.class, true),
			}
		);
	}

}
