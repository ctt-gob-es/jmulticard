package es.gob.jmulticard.jse.provider;

import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.PasswordCallback;

final class DniePasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = -2511696590746468782L;

	private final PasswordProtection passp;

	/**
	 * @param pp PasswordProtection para solicitar la contraseña
	 */
	DniePasswordCallback(final PasswordProtection pp) {
		super("Por favor, introduzca el PIN del DNIe", false); //$NON-NLS-1$
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
