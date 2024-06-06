package es.gob.jmulticard.card;

/** Excepci&oacute;n relativa a la seguridad de una operaci&oacute;n criptogr&aacute;fica de tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CryptoCardSecurityException extends CardException {

	/** Identificador de versi&oacute;n para la serializaci&oacute;n. */
	private static final long serialVersionUID = -3133117372570125570L;

	/** Construye la excepci&oacute;n.
	 * @param msg Mensaje de error. */
	public CryptoCardSecurityException(final String msg) {
		super(msg);
	}

	/** Construye la excepci&oacute;n.
	 * @param msg Mensaje de error.
	 * @param cause Excepci&oacute;n que origin&oacute; este error. */
	public CryptoCardSecurityException(final String msg, final Throwable cause) {
		super(msg, cause);
	}
}
