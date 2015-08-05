package es.gob.jmulticard.card.pace;

import es.gob.jmulticard.card.CardException;

/** Excepci&oacute;n de error relacionado con el protocolo PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceException extends CardException {

	private static final long serialVersionUID = 6633945897491338530L;

	PaceException(final String description) {
        super(description);
    }

}
