package es.gob.jmulticard.card;

/** Introducci&oacute;n incorrecta del PIN de la tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class PinException extends CardException {

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = 9827614003517666L;

	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta de la tarjeta. */
	public PinException() {
		// Vacio
	}

	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta de la tarjeta.
	 * @param msg Mensaje de la excepci&oacute;n. */
	public PinException(final String msg) {
		super(msg);
	}

	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta de la tarjeta.
	 * @param msg Mensaje de la excepci&oacute;n.
	 * @param cause Causa inicial. */
	public PinException(final String msg, final Throwable cause) {
		super(msg, cause);
	}
}
