package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;

/** CAN o MRZ err&oacute;neo introducido.
 * @author Sergio Mart&iacute;nez Rico
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class InvalidCanOrMrzException extends IcaoException {

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = 8254462304692038281L;

	/** Crea la excepci&oacute;n de MRZ o CAN err&oacute;neo.
	 * @param description Descripci&oacute;n del error. */
	public InvalidCanOrMrzException(final String description) {
		super(description);
	}

	/** Crea una excepci&oacute;n de MRZ o CAN err&oacute;neo.
	 * @param retCode Palabra de estado.
     * @param origin APDU que gener&oacute; la palabra de estado.
     * @param description Descripci&oacute;n de la excepci&oacute;n. */
	public InvalidCanOrMrzException(final StatusWord retCode,
			                        final Apdu origin,
			                        final String description) {
        super(retCode, origin, description);
	}
}
