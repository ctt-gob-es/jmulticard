package es.gob.jmulticard.jse.provider;

import java.security.SignatureException;

/**
 * Excepci&oacute;n para la notificaci&oacute;n de un error al autenticar al usuario durante la
 * operaci&oacute;n de firma.
 */
public class SignatureAuthException extends SignatureException {

	/** Serial ID. */
	private static final long serialVersionUID = 6467790733377018931L;

	/**
	 * Crea una excepci&oacute;n de autenticaci&oacute;n durante el proceso de firma.
	 * @param cause Causa de la excepci&oacute;n.
	 */
	public SignatureAuthException(final Throwable cause) {
		super(cause);
	}
}
