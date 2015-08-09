package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.der.ContextSpecific;

/** Enumeraci&oacute;n de claves p&uacute;blicas de confianza (ra&iacute;z) espec&iacute;fica de contexto.
 * Sigue la estructura ASN&#46;1 (es de tipo <i>PublicKeys</i>):
 * <pre>
 *  PublicKeys ::= PathOrObjects {PrivateKeyType}
 * </pre>
 * Esta implememtaci&oacute;n solo soporta <code>Path</code> como tipo de los registros.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TrustedPublicKeysContextSpecific extends ContextSpecific {

	private static final byte TAG = (byte) 0xA2;

	/** Construye una numeraci&oacute;n de claves p&uacute;blicas de confianza espec&iacute;fica de contexto.
	 * Esta implememtaci&oacute;n solo soporta <code>Path</code> como tipo de los registros. */
	public TrustedPublicKeysContextSpecific() {
		super(Path.class);
	}

	/** {@inheritDoc} */
	@Override
    public void checkTag(final byte tag) throws Asn1Exception {
		if (TAG != tag) {
			throw new Asn1Exception(
				"TrustedPublicKeysContextSpecific esperaba una etiqueta especifica de contexto " + HexUtils.hexify(new byte[] { TAG }, false) + //$NON-NLS-1$
				" pero ha encontrado " + HexUtils.hexify(new byte[] { tag }, false) //$NON-NLS-1$
			);
		}
	}

}
