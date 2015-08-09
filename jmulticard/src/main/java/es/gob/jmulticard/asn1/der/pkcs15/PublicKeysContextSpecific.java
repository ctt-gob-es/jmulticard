package es.gob.jmulticard.asn1.der.pkcs15;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.der.ContextSpecific;

/** Enumeraci&oacute;n de claves p&uacute;blicas espec&iacute;fica de contexto.
 * Sigue la estructura ASN&#46;1:
 * <pre>
 *  PublicKeys ::= PathOrObjects {PrivateKeyType}
 * </pre>
 * Esta implememtaci&oacute;n solo soporta <code>Path</code> como tipo de los registros.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class PublicKeysContextSpecific extends ContextSpecific {

	private static final byte TAG = (byte) 0xA1;

	/** Construye una numeraci&oacute;n de claves p&uacute;blicas espec&iacute;fica de contexto.
	 * Esta implememtaci&oacute;n solo soporta <code>Path</code> como tipo de los registros. */
	public PublicKeysContextSpecific() {
		super(Path.class);
	}

	/** {@inheritDoc} */
	@Override
    public void checkTag(final byte tag) throws Asn1Exception {
		if (TAG != tag) {
			throw new Asn1Exception(
				"PublicKeysContextSpecific esperaba una etiqueta especifica de contexto " + HexUtils.hexify(new byte[] { TAG }, false) + //$NON-NLS-1$
				" pero ha encontrado " + HexUtils.hexify(new byte[] { tag }, false) //$NON-NLS-1$
			);
		}
	}

}
