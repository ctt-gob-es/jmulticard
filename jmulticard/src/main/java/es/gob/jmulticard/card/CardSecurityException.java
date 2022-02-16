package es.gob.jmulticard.card;

/** Excepci&oacute;n gen&eacute;rica de seguridad en tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CardSecurityException extends CardException {

	/** Construye una excepci&oacute;n gen&eacute;rica de seguridad en tarjeta.
	 * @param desc descripci&oacute;n de la excepci&oacute;n.
	 * @param cause Cause inicial de la excepci&oacute;n. */
	public CardSecurityException(final String desc, final Exception cause) {
		super(desc, cause);
	}

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = 4053991684840787547L;

}
