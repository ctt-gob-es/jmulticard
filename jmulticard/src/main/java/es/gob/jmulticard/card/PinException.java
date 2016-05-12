package es.gob.jmulticard.card;

/** Introducci&oacute;n incorrecta del PIN del DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class PinException extends CardException {

	private static final long serialVersionUID = 9827614003517666L;

	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta del PIN del DNIe.
	 * @param msg Mensaje de la excepci&oacute;n. */
	public PinException() {
		super();
	}
	
	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta del PIN del DNIe.
	 * @param msg Mensaje de la excepci&oacute;n. */
	public PinException(final String msg) {
		super(msg);
	}
	
	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta del PIN del DNIe.
	 * @param msg Mensaje de la excepci&oacute;n.
	 * @param retriesLeft Intentos restantes.
	 * @param cause Causa inicial. */
	public PinException(final String msg, final Throwable cause) {
		super(msg, cause);
	}
}
