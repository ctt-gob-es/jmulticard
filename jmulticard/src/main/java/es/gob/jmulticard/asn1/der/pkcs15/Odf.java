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
 *
 * PathOrObjects {ObjectType} ::= CHOICE {
 *   path    Path,
 *   objects [0] SEQUENCE OF ObjectType,
 *   ...,
 *   indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}},
 *   direct-protected   [2] EnvelopedData   {SEQUENCE OF ObjectType},
 * }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class Odf extends Record {

	/** Construye un objeto PKCS#15 ODF (<i>Object Description File</i>) ASN&#46;1. */
	public Odf() {
		super(
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(PrivateKeysContextSpecific.class, true),       // PrKDF
				new OptionalDecoderObjectElement(PublicKeysContextSpecific.class, true),
				new OptionalDecoderObjectElement(TrustedPublicKeysContextSpecific.class, true),
				new OptionalDecoderObjectElement(SecretKeysContextSpecific.class, true),
				new OptionalDecoderObjectElement(CertificatesContextSpecific.class, true)       // CDF
			}
		);
	}

	/** Obtiene la ruta (Path ASN&#46;1 PKCS#15) hacia el CDF.
	 * @return Ruta (Path ASN&#46;1 PKCS#15) hacia el CDF, o <code>null</code>
	 *         si este ODF no contiene esta ruta. */
	public Path getCdfPath() {
		for (int i=0;i<getElementCount();i++) {
			final DecoderObject dobj = getElementAt(i);
			if (dobj instanceof CertificatesContextSpecific) {
				return ((CertificatesContextSpecific)dobj).getCertificatesPath();
			}
		}
		return null;
	}

	/** Obtiene la ruta (Path ASN&#46;1 PKCS#15) hacia el PrKDF.
	 * @return Ruta (Path ASN&#46;1 PKCS#15) hacia el PrKDF, o <code>null</code>
	 *         si este ODF no contiene esta ruta. */
	public Path getPrKdfPath() {
		for (int i=0;i<getElementCount();i++) {
			final DecoderObject dobj = getElementAt(i);
			if (dobj instanceof PrivateKeysContextSpecific) {
				return ((PrivateKeysContextSpecific)dobj).getPrivateKeysPath();
			}
		}
		return null;
	}

	/** Obtiene la ruta (Path ASN&#46;1 PKCS#15) hacia el PuKDF.
	 * @return Ruta (Path ASN&#46;1 PKCS#15) hacia el PuKDF, o <code>null</code>
	 *         si este ODF no contiene esta ruta. */
	public Path getPuKdfPath() {
		for (int i=0;i<getElementCount();i++) {
			final DecoderObject dobj = getElementAt(i);
			if (dobj instanceof PublicKeysContextSpecific) {
				return ((PublicKeysContextSpecific)dobj).getPublicKeysPath();
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return
			"ODF: \n" + //$NON-NLS-1$
				" Ruta hacia el CDF: " + getCdfPath() + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
				" Ruta hacia el PrKDF: " + getPrKdfPath() + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
				" Ruta hacia el PuKDF: " + getPuKdfPath() //$NON-NLS-1$
		;
	}

}
