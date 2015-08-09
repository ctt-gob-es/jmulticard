package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.der.ContextSpecific;

/** Enumeraci&oacute;n de certificados espec&iacute;fica de contexto.
 * Sigue la estructura ASN&#46;1 (es de tipo <i>PublicKeys</i>):
 * <pre>
 *  Certificates ::= PathOrObjects {PrivateKeyType}
 * </pre>
 * Esta implememtaci&oacute;n solo soporta <code>Path</code> como tipo de los registros.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class CertificatesContextSpecific extends ContextSpecific {

	private static final byte TAG = (byte) 0xA4;

	/** Construye una numeraci&oacute;n de certificados espec&iacute;fica de contexto.
	 * Esta implememtaci&oacute;n solo soporta <code>Path</code> como tipo de los registros. */
	public CertificatesContextSpecific() {
		super(Path.class);
	}

	/** Obtiene la ruta (Path ASN&#46;1 PKCS#15) hacia los certificados.
	 * @return Ruta (Path ASN&#46;1 PKCS#15) hacia los certificados. */
	public Path getCertificatesPath() {
		if (getObject() instanceof Path) {
			return (Path) getObject();
		}
		throw new IllegalStateException(
			"El objeto interno no es de tipo Path PKCS#15" //$NON-NLS-1$
		);
	}

	/** {@inheritDoc} */
	@Override
    public void checkTag(final byte tag) throws Asn1Exception {
		if (TAG != tag) {
			throw new Asn1Exception(
				"CertificatesContextSpecific esperaba una etiqueta especifica de contexto " + HexUtils.hexify(new byte[] { TAG }, false) + //$NON-NLS-1$
				" pero ha encontrado " + HexUtils.hexify(new byte[] { tag }, false) //$NON-NLS-1$
			);
		}
	}

}
