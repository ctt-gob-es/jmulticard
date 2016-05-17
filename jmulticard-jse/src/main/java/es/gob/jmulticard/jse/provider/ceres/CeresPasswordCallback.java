package es.gob.jmulticard.jse.provider.ceres;

import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.PasswordCallback;

/** Password Callback para CERES.
 * @author Sergio Mart&iacute;nez Rico */
final class CeresPasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = -2511696590746468782L;

	private final PasswordProtection passp;

	/** Callback para solicitar la constrasena.
	 * @param pp PasswordProtection para solicitar la constrasena.
	 */
	CeresPasswordCallback(final PasswordProtection pp) {
		super("Por favor, introduzca el PIN de la tarjeta CERES", false); //$NON-NLS-1$
		if (pp == null) {
			throw new IllegalArgumentException(
				"El PasswordProtection no puede ser nulo" //$NON-NLS-1$
			);
		}
		this.passp = pp;
	}

	@Override
	public char[] getPassword() {
		return this.passp.getPassword();
	}

}
