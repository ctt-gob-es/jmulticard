package es.gob.jmulticard.card.pace;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Excepci&oacute;n de error relacionado con el protocolo PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceException extends Iso7816FourCardException {

	private static final long serialVersionUID = 6633945897491338530L;

	PaceException(final StatusWord retCode, final Apdu origin, final String description) {
        super(retCode, origin, description);
	}

	PaceException(final String description, final Throwable e) {
		super(description, e);
	}

}
