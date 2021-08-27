package es.gob.jmulticard.jse.provider;

import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.PasswordCallback;

final class DniePasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = -2511696590746468782L;

	private final PasswordProtection passp;

	/** Constructor.
	 * @param pp PasswordProtection para solicitar la contrase&ntilde;a. */
	DniePasswordCallback(final PasswordProtection pp) {
		this(pp, "Por favor, introduzca el PIN del DNIe");
	}

	/** Constructor.
	 * @param pp PasswordProtection para solicitar la contrase&ntilde;a. */
	DniePasswordCallback(final PasswordProtection pp, final String prompt) {
		super(prompt, false);
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
