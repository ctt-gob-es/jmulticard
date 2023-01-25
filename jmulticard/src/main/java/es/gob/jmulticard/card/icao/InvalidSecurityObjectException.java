package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.card.CardException;

/** Si un objeto de seguridad ICAO no supera las comprobaciones de seguridad.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class InvalidSecurityObjectException extends CardException {

	/** Crea una excepci&oacute;n que indica que un objeto de seguridad ICAO no
	 * supera las comprobaciones de seguridad.
	 * @param desc Descripci&oacute;n. */
	public InvalidSecurityObjectException(final String desc) {
		super(desc);
	}

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = 6199689552084252644L;
}
