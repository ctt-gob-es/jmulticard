package es.gob.jmulticard.jse.provider;

import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.PasswordCallback;

final class PasswordProtectionPasswordCallback extends PasswordCallback {
	
	private static final long serialVersionUID = -2511696590746468782L;
	
	private final PasswordProtection passp;
	
	PasswordProtectionPasswordCallback(PasswordProtection pp) {
		super("Por favor, introduzca el PIN del DNIe", false);
		if (pp == null) {
			throw new IllegalArgumentException(
				"El PasswordProtection no puede ser nulo"
			);
		}
		passp = pp;
	}
	
	@Override
	public char[] getPassword() {
		return passp.getPassword();
	}

}
