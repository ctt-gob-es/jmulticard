package es.gob.jmulticard.card;

/** No se encuentra un mecanismo para la inserci&oacute;n de contrase&ntilde;a (ni
 * un {@code PasswordCallback} o un {@code CallbackHandler} capaz de manejarlo).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PasswordCallbackNotFoundException extends PinException {

	/** Serial Id. */
	private static final long serialVersionUID = 3347342217520582788L;

	/** Construye una excepci&oacute;n de mecanismo de inserci&oacute;n de PIN no encontrado.
	 * @param msg Mensaje de la excepci&oacute;n. */
	public PasswordCallbackNotFoundException(final String msg) {
		super(msg);
	}

	/** Construye una excepci&oacute;n de mecanismo de inserci&oacute;n de PIN no encontrado.
	 * @param msg Mensaje de la excepci&oacute;n.
	 * @param cause Causa inicial. */
	public PasswordCallbackNotFoundException(final String msg, final Throwable cause) {
		super(msg, cause);
	}
}
