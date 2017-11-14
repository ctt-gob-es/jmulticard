package es.gob.jmulticard.jse.provider.ceres;

import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.PasswordCallback;

/** <code>PasswordCallback</code> para tarjetas FNMT-CERES.
 * @author Sergio Mart&iacute;nez Rico. */
final class CeresPasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = -2511696590746468782L;

	private final PasswordProtection passp;

	/** <code>Callback</code> para solicitar la constrase&ntilde;a.
	 * @param pp <code>PasswordProtection</code> para solicitar la constrase&ntilde;a. */
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
