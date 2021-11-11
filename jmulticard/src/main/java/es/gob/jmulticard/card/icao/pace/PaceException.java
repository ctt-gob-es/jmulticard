package es.gob.jmulticard.card.icao.pace;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.card.icao.IcaoException;

/** Error relacionado con el protocolo PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class PaceException extends IcaoException {

	private static final long serialVersionUID = 6633945897491338530L;

	PaceException(final StatusWord retCode, final Apdu origin, final String description) {
        super(retCode, origin, description);
	}

	/** Crea la excepci&oacute;n de error relacionado con el protocolo PACE.
	 * @param description Detalle de la excepci&oacute;n.
	 * @param e Excepci&oacute;n de origen. */
	public PaceException(final String description, final Throwable e) {
		super(description, e);
	}

	/** Crea la excepci&oacute;n de error relacionado con el protocolo PACE.
	 * @param description Detalle de la excepci&oacute;n. */
	public PaceException(final String description) {
		super(description);
	}

}
