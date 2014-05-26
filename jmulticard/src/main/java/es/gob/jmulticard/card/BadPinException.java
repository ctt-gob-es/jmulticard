package es.gob.jmulticard.card;

/** Introducci&oacute;n incorrecta del PIN del DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class BadPinException extends CardException {

	private static final long serialVersionUID = 9827614003517666L;

	private final int retries;

	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta del PIN del DNIe.
	 * @param retriesLeft Intentos restantes */
	public BadPinException(final int retriesLeft) {
		super("PIN incorrecto, intentos restantes: " + Integer.toString(retriesLeft)); //$NON-NLS-1$
		this.retries = retriesLeft;
	}

	/** Construye una excepci&oacute;n de introducci&oacute;n incorrecta del PIN del DNIe.
	 * @param msg Mensaje de la excepci&oacute;n */
	public BadPinException(final String msg) {
		super(msg);
		this.retries = -1;
	}

	/** Obtiene los intentos restantes que quedan para introdicir correctamente el PIN antes de que
	 * se bloquee el DNIe, y -1 si se desconoce.
	 * @return Intentos restantes que quedan para introdicir correctamente el PIN */
	public int getRemainingRetries() {
		return this.retries;
	}

}
