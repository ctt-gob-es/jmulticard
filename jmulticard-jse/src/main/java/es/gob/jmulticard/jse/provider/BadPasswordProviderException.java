package es.gob.jmulticard.jse.provider;

import java.security.ProviderException;

/** Excepci&oacute;n para la notificaci&oacute;n de un error de contrase&ntilde;a
 * durante el uso de un proveedor para el acceso a un <code>KeyStore</code>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class BadPasswordProviderException extends ProviderException {

	/** Serial ID. */
	private static final long serialVersionUID = 607788482342310411L;

	/** Crea una excepci&oacute;n de contrase&ntilde;a inv&aacute;lida para el
	 * proveedor para el uso de un <code>KeyStore</code>.
	 * @param cause Causa de la excepci&oacute;n. */
	public BadPasswordProviderException(final Throwable cause) {
		super(cause);
	}
}
