package es.gob.jmulticard.card.pace;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;

/** CAN o MRZ err&oacute;neo introducido.
 * @author Sergio Mart&iacute;nez Rico. */
public final class InvalidCanOrMrzException extends PaceException {

	private static final long serialVersionUID = 8254462304692038281L;

	/** Crea la excepci&oacute;n de MRZ o CAN err&oacute;neo introducido.
	 * @param description Descripci&oacute;n del error. */
	public InvalidCanOrMrzException(final String description) {
		super(description);
	}

	InvalidCanOrMrzException(final StatusWord retCode, final Apdu origin, final String description) {
        super(retCode, origin, description);
	}

}
